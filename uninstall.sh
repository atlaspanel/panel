#!/bin/bash

set -e

FORCE=false
KEEP_PACKAGES=true

for arg in "$@"; do
    case $arg in
        --force)
            FORCE=true
            ;;
        --remove-packages)
            KEEP_PACKAGES=false
            ;;
    esac
done

error_exit() {
    echo "ERROR: $1"
    exit 1
}

if [ "$EUID" -ne 0 ]; then
    error_exit "You need to be root to run this uninstall script"
fi

if [ "$FORCE" = false ]; then
    echo "WARNING: This will completely remove Atlas Panel and all its data."
    echo "This action cannot be undone!"
    echo ""
    echo "The following will be removed:"
    echo "  - Atlas Panel installation directory (/opt/atlaspanel)"
    echo "  - Systemd services (atlaspanel-api, atlaspanel-node)"
    echo "  - Nginx configuration"
    echo "  - All Atlas Panel data and databases"
    echo ""
    if [ "$KEEP_PACKAGES" = false ]; then
        echo "  - Go, Node.js, npm, and nginx packages"
    else
        echo "System packages (Go, Node.js, npm, nginx) will be kept"
    fi
    echo ""
    read -p "Are you sure you want to continue? (yes/no): " confirm
    if [ "$confirm" != "yes" ]; then
        echo "Uninstall cancelled."
        exit 0
    fi
fi

echo "Stopping Atlas Panel services..."
systemctl stop atlaspanel-api 2>/dev/null || true
systemctl stop atlaspanel-node 2>/dev/null || true
systemctl stop nginx 2>/dev/null || true

echo "Disabling Atlas Panel services..."
systemctl disable atlaspanel-api 2>/dev/null || true
systemctl disable atlaspanel-node 2>/dev/null || true

echo "Removing systemd service files..."
rm -f /etc/systemd/system/atlaspanel-api.service
rm -f /etc/systemd/system/atlaspanel-node.service
systemctl daemon-reload

echo "Removing nginx configuration..."
rm -f /etc/nginx/sites-available/atlaspanel
rm -f /etc/nginx/sites-enabled/atlaspanel

if [ -f /etc/nginx/sites-available/default ]; then
    echo "Restoring default nginx site..."
    ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default
fi

echo "Removing Atlas Panel installation directory..."
rm -rf /opt/atlaspanel

if [ "$KEEP_PACKAGES" = false ]; then
    echo "Removing installed packages..."
    apt remove --purge -y golang nodejs npm nginx 2>/dev/null || true
    apt autoremove -y 2>/dev/null || true
else
    echo "Keeping installed packages (golang, nodejs, npm, nginx)"
    echo "Starting nginx with default configuration..."
    systemctl start nginx 2>/dev/null || true
    systemctl enable nginx 2>/dev/null || true
fi

echo ""
echo "Atlas Panel has been completely uninstalled!"
echo ""
if [ "$KEEP_PACKAGES" = false ]; then
    echo "All related packages have been removed."
else
    echo "System packages were kept as requested."
fi
echo ""
echo "Remaining items (if any):"
echo "  - Package cache files in /var/cache/apt/"
echo "  - Log files in /var/log/"
echo "  - Any custom nginx configurations you may have added"