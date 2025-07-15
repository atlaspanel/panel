#!/bin/bash

set -e

SKIP_OS_CHECK=false
SKIP_RESOURCE_CHECK=false
DEBUG=false
BRANCH="main"

for arg in "$@"; do
    case $arg in
        --skip-os)
            SKIP_OS_CHECK=true
            ;;
        --skip-resource)
            SKIP_RESOURCE_CHECK=true
            ;;
        --debug)
            DEBUG=true
            ;;
        --branch=*)
            BRANCH="${arg#*=}"
            ;;
    esac
done

error_exit() {
    echo "ERROR: $1"
    echo "Run with --debug for more information or report at https://github.com/atlaspanel/panel/issues"
    exit 1
}

debug_info() {
    echo "=== DEBUG INFORMATION ==="
    echo "OS Type: $OSTYPE"
    echo "Date: $(date)"
    echo "User: $(whoami)"
    echo "UID: $EUID"
    echo "Arguments: $@"
    echo
    
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macOS Version: $(sw_vers -productVersion)"
        echo "Hardware: $(uname -m)"
        echo "Total RAM: $(( $(sysctl -n hw.memsize) / 1024 / 1024 / 1024 ))GB"
        echo "CPU Cores: $(sysctl -n hw.ncpu)"
    else
        echo "Linux Distribution:"
        if [ -f /etc/os-release ]; then
            cat /etc/os-release
        fi
        echo
        echo "Kernel: $(uname -a)"
        echo "Hardware: $(uname -m)"
        if command -v free >/dev/null 2>&1; then
            echo "Memory Info:"
            free -h
        fi
        if command -v nproc >/dev/null 2>&1; then
            echo "CPU Cores: $(nproc)"
        fi
    fi
    
    echo "=========================="
    echo
}

if [ "$DEBUG" = true ]; then
    debug_info "$@"
fi

trap 'error_exit "Script failed at line $LINENO"' ERR

if [ "$EUID" -ne 0 ]; then
    error_exit "You need to be root to run this script"
fi

if [ "$SKIP_OS_CHECK" = false ]; then
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [ "$ID" != "ubuntu" ] && [ "$ID" != "debian" ]; then
            error_exit "This install script is only for Ubuntu & Debian"
        fi
    else
        error_exit "This install script is only for Ubuntu & Debian"
    fi
fi

REQUIRED_RAM_GB=4
REQUIRED_CPU_CORES=2

if [ "$SKIP_RESOURCE_CHECK" = false ]; then
    if [[ "$OSTYPE" == "darwin"* ]]; then
        TOTAL_RAM_GB=$(( $(sysctl -n hw.memsize) / 1024 / 1024 / 1024 ))
        CPU_CORES=$(sysctl -n hw.ncpu)
    else
        TOTAL_RAM_GB=$(free -g | awk '/^Mem:/{print $2}')
        CPU_CORES=$(nproc)
    fi

    if [ "$TOTAL_RAM_GB" -lt "$REQUIRED_RAM_GB" ]; then
        error_exit "This script requires at least ${REQUIRED_RAM_GB}GB of RAM. You have ${TOTAL_RAM_GB}GB"
    fi

    if [ "$CPU_CORES" -lt "$REQUIRED_CPU_CORES" ]; then
        error_exit "This script requires at least ${REQUIRED_CPU_CORES} CPU cores. You have ${CPU_CORES}"
    fi
fi

INSTALL_DIR="/opt/atlaspanel"
REPO_URL="https://github.com/atlaspanel/panel.git"

echo "Cloning repository..."
if [ -d "$INSTALL_DIR" ]; then
    echo "Directory $INSTALL_DIR already exists. Removing..."
    rm -rf "$INSTALL_DIR"
fi

git clone -b "$BRANCH" "$REPO_URL" "$INSTALL_DIR" || error_exit "Failed to clone repository"

echo "Moving to installation directory..."
cd "$INSTALL_DIR" || error_exit "Failed to change to installation directory"

echo "Updating package lists..."
apt update || error_exit "Failed to update package lists"

echo "Installing Go..."
apt install -y golang || error_exit "Failed to install Go"

echo "Installing Node.js and npm..."
apt install -y npm nodejs || error_exit "Failed to install Node.js and npm"

echo "Installing nginx..."
apt install -y nginx || error_exit "Failed to install nginx"

echo "Building Go applications..."
cd "$INSTALL_DIR/node" || error_exit "Failed to change to node directory"
go build . || error_exit "Failed to build node application"

cd "$INSTALL_DIR/api" || error_exit "Failed to change to api directory"
go build . || error_exit "Failed to build api application"

echo "Building panel frontend..."
cd "$INSTALL_DIR/panel" || error_exit "Failed to change to panel directory"
npm i || error_exit "Failed to install npm dependencies"
npm run build || error_exit "Failed to build panel frontend"

echo "Setting up nginx configuration..."
cat > /etc/nginx/sites-available/atlaspanel << 'EOF'
server {
    listen 80;
    server_name _;
    
    root /opt/atlaspanel/panel/dist;
    index index.html;
    
    location / {
        try_files $uri $uri/ /index.html;
    }
    
    location /api/ {
        proxy_pass http://127.0.0.1:8080/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF

ln -sf /etc/nginx/sites-available/atlaspanel /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t || error_exit "nginx configuration test failed"

echo "Setting up permissions..."
chown -R www-data:www-data /opt/atlaspanel/panel/dist
chmod -R 755 /opt/atlaspanel/panel/dist

echo "Creating configuration files..."

RANDOM_KEY=$(openssl rand -hex 32)
JWT_SECRET=$(openssl rand -hex 64)

cat > "$INSTALL_DIR/node/config.json" << EOF
{
  "api_endpoint": "http://0.0.0.0:8080",
  "key": "$RANDOM_KEY"
}
EOF

cat > "$INSTALL_DIR/api/config.json" << EOF
{
  "server": {
    "port": "8080",
    "host": "0.0.0.0"
  },
  "database": {
    "path": "/opt/atlaspanel/api/atlas.db"
  },
  "jwt": {
    "secret": "$JWT_SECRET",
    "expiration_hours": 24
  },
  "heartbeat": {
    "interval_seconds": 30,
    "timeout_seconds": 60
  },
  "cors": {
    "allow_origins": ["*"],
    "allow_methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    "allow_headers": ["Content-Type", "Authorization"]
  }
}
EOF

IP=$(hostname -I | awk '{print $1}')
cat > "$INSTALL_DIR/panel/dist/config.json" << EOF
{
  "apiUrl": "http://${IP}:8080"
}
EOF

echo "Creating systemd services..."

cat > /etc/systemd/system/atlaspanel-api.service << 'EOF'
[Unit]
Description=Atlas Panel API
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/atlaspanel/api
ExecStart=/opt/atlaspanel/api/atlas-panel-api
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/atlaspanel-node.service << 'EOF'
[Unit]
Description=Atlas Panel Node
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/atlaspanel/node
ExecStart=/opt/atlaspanel/node/atlas-panel-node
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable atlaspanel-api atlaspanel-node nginx
systemctl start atlaspanel-api atlaspanel-node nginx

echo "Installation completed successfully!"
echo "Atlas Panel is now accessible via http://your-server-ip/"
echo "API running on port 8080"
echo ""
echo "Service management commands:"
echo "  systemctl status atlaspanel-api"
echo "  systemctl status atlaspanel-node"
echo "  systemctl restart atlaspanel-api"
echo "  systemctl restart atlaspanel-node"