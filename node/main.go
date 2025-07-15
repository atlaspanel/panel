package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/spf13/cobra"
)

type Config struct {
	APIEndpoint string `json:"api_endpoint"`
	Key         string `json:"key"`
}

type Package struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
	Status      string `json:"status"`
	Size        int64  `json:"size"`
}

type SystemInfo struct {
	OS           string    `json:"os"`
	Arch         string    `json:"arch"`
	CPUUsage     float64   `json:"cpu_usage"`
	RAMUsage     float64   `json:"ram_usage"`
	RAMTotal     uint64    `json:"ram_total"`
	DiskUsage    float64   `json:"disk_usage"`
	DiskTotal    uint64    `json:"disk_total"`
	Uptime       uint64    `json:"uptime"`
	Packages     []Package `json:"packages,omitempty"`
	PackageCount int       `json:"package_count"`
}

type ShellSession struct {
	conn    *websocket.Conn
	cmd     *exec.Cmd
	ptmx    *os.File // PTY master for Unix
	stdin   io.WriteCloser // For Windows fallback
	stdout  io.ReadCloser // For Windows fallback
	stderr  io.ReadCloser // For Windows fallback
	cleanup chan bool
	mutex   sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
	isWindows bool
}

type Agent struct {
	config    Config
	client    *http.Client
	upgrader  websocket.Upgrader
	sessions  map[string]*ShellSession
	sessionMu sync.RWMutex
}

func main() {
	var configFile string

	rootCmd := &cobra.Command{
		Use:   "atlas-node",
		Short: "Atlas Panel Node Agent",
		Run: func(cmd *cobra.Command, args []string) {
			agent, err := NewAgent(configFile)
			if err != nil {
				log.Fatal("Failed to create agent:", err)
			}
			agent.Start()
		},
	}

	rootCmd.Flags().StringVarP(&configFile, "config", "c", "config.json", "Config file path")

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func NewAgent(configFile string) (*Agent, error) {
	config, err := loadConfig(configFile)
	if err != nil {
		return nil, err
	}

	return &Agent{
		config: config,
		client: &http.Client{Timeout: 10 * time.Second},
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				// Only allow connections from the configured API endpoint
				origin := r.Header.Get("Origin")
				if origin == "" {
					// Allow connections without origin header (direct tools)
					return true
				}
				
				// Parse the configured API endpoint to get allowed origin
				if apiURL, err := url.Parse(config.APIEndpoint); err == nil {
					allowedOrigin := fmt.Sprintf("%s://%s", apiURL.Scheme, apiURL.Host)
					return origin == allowedOrigin
				}
				
				return false
			},
		},
		sessions: make(map[string]*ShellSession),
	}, nil
}

func loadConfig(filename string) (Config, error) {
	var config Config
	
	file, err := os.ReadFile(filename)
	if err != nil {
		return config, fmt.Errorf("failed to read config file: %v", err)
	}

	err = json.Unmarshal(file, &config)
	if err != nil {
		return config, fmt.Errorf("failed to parse config: %v", err)
	}

	if config.APIEndpoint == "" || config.Key == "" {
		return config, fmt.Errorf("api_endpoint and key are required in config")
	}

	return config, nil
}

func (a *Agent) Start() {
	log.Printf("Starting Atlas Panel Node Agent")
	log.Printf("API Endpoint: %s", a.config.APIEndpoint)
	
	nodeURL := a.getNodeURL()
	log.Printf("Node URL: %s", nodeURL)
	log.Printf("Use this URL when adding the node in Atlas Panel")

	go a.startServer()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	a.sendHeartbeat()

	for range ticker.C {
		a.sendHeartbeat()
	}
}

func (a *Agent) startServer() {
	http.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "online", "agent": "atlas-panel-node"}`))
	})

	http.HandleFunc("/shell", a.handleShellConnection)

	log.Printf("Starting node server on :3040")
	if err := http.ListenAndServe(":3040", nil); err != nil {
		log.Printf("Failed to start server: %v", err)
	}
}

func (a *Agent) getNodeURL() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "unknown"
	}

	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				return fmt.Sprintf("http://%s:3040", ipNet.IP.String())
			}
		}
	}
	
	return "http://localhost:3040"
}

func (a *Agent) getPackageInfo() ([]Package, error) {
	if runtime.GOOS != "linux" {
		return nil, nil // Skip non-Linux systems
	}

	// Check if dpkg is available
	if _, err := exec.LookPath("dpkg-query"); err != nil {
		return nil, nil // dpkg not available, skip package info
	}

	cmd := exec.Command("dpkg-query", "-W", "-f=${Package}\t${Version}\t${installed-Size}\t${Status}\t${Description}\n")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var packages []Package
	lines := strings.Split(string(output), "\n")
	
	for _, line := range lines {
		if line == "" {
			continue
		}
		
		parts := strings.Split(line, "\t")
		if len(parts) < 5 {
			continue
		}
		
		// Only include installed packages
		if !strings.Contains(parts[3], "install ok installed") {
			continue
		}
		
		// Parse size (in KB)
		size, _ := strconv.ParseInt(parts[2], 10, 64)
		
		pkg := Package{
			Name:        parts[0],
			Version:     parts[1],
			Size:        size * 1024, // Convert KB to bytes
			Status:      parts[3],
			Description: parts[4],
		}
		
		packages = append(packages, pkg)
	}
	
	return packages, nil
}

func (a *Agent) getSystemInfo() (SystemInfo, error) {
	var sysInfo SystemInfo

	// Get OS info
	hostInfo, err := host.Info()
	if err != nil {
		return sysInfo, err
	}
	sysInfo.OS = hostInfo.OS
	sysInfo.Arch = runtime.GOARCH
	sysInfo.Uptime = hostInfo.Uptime

	// Get CPU usage
	cpuPercent, err := cpu.Percent(time.Second, false)
	if err != nil || len(cpuPercent) == 0 {
		sysInfo.CPUUsage = 0
	} else {
		sysInfo.CPUUsage = cpuPercent[0]
	}

	// Get memory info
	memInfo, err := mem.VirtualMemory()
	if err != nil {
		return sysInfo, err
	}
	sysInfo.RAMUsage = memInfo.UsedPercent
	sysInfo.RAMTotal = memInfo.Total

	// Get disk info (root partition)
	diskInfo, err := disk.Usage("/")
	if err != nil {
		// Try Windows C: drive if root fails
		diskInfo, err = disk.Usage("C:")
		if err != nil {
			return sysInfo, err
		}
	}
	sysInfo.DiskUsage = diskInfo.UsedPercent
	sysInfo.DiskTotal = diskInfo.Total

	// Get package info (Linux only)
	packages, err := a.getPackageInfo()
	if err != nil {
		log.Printf("Warning: Failed to get package info: %v", err)
		// Don't fail the entire system info collection if package info fails
	}
	sysInfo.Packages = packages
	sysInfo.PackageCount = len(packages)

	return sysInfo, nil
}

func (a *Agent) sendHeartbeat() {
	url := fmt.Sprintf("%s/heartbeat", a.config.APIEndpoint)
	
	sysInfo, err := a.getSystemInfo()
	if err != nil {
		log.Printf("Failed to get system info: %v", err)
		return
	}

	jsonData, err := json.Marshal(sysInfo)
	if err != nil {
		log.Printf("Failed to marshal system info: %v", err)
		return
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Failed to create heartbeat request: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", a.config.Key)

	resp, err := a.client.Do(req)
	if err != nil {
		log.Printf("Heartbeat failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		log.Printf("Heartbeat sent successfully - CPU: %.1f%%, RAM: %.1f%%, Disk: %.1f%%", 
			sysInfo.CPUUsage, sysInfo.RAMUsage, sysInfo.DiskUsage)
	} else {
		log.Printf("Heartbeat failed with status: %d", resp.StatusCode)
	}
}

func (a *Agent) handleShellConnection(w http.ResponseWriter, r *http.Request) {
	// Authenticate the request using the node key
	authKey := r.Header.Get("Authorization")
	if authKey != a.config.Key {
		log.Printf("Shell connection denied: invalid authentication key")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Upgrade to WebSocket
	conn, err := a.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade to websocket: %v", err)
		return
	}

	log.Printf("New shell connection established")
	session := a.createShellSession(conn)
	if session == nil {
		conn.Close()
		return
	}

	// Handle the session
	go a.handleShellSession(session)
}

func (a *Agent) createShellSession(conn *websocket.Conn) *ShellSession {
	// Determine shell command based on OS
	var shellCmd string
	
	switch runtime.GOOS {
	case "windows":
		// Windows doesn't support PTY, fall back to regular pipes
		return a.createWindowsShellSession(conn)
	default:
		// Use proper shell for Unix-like systems
		shellCmd = "/bin/bash"
		if _, err := exec.LookPath(shellCmd); err != nil {
			shellCmd = "/bin/sh"
		}
	}

	// Create command
	cmd := exec.Command(shellCmd)
	
	// Set up environment for proper terminal behavior
	cmd.Env = append(os.Environ(), 
		"TERM=xterm-256color",
		"LANG=en_US.UTF-8",
		"LC_ALL=en_US.UTF-8",
	)
	
	// Start the command with PTY
	ptmx, err := pty.Start(cmd)
	if err != nil {
		log.Printf("Failed to start shell with PTY: %v", err)
		return nil
	}

	// Set initial terminal size
	if err := pty.Setsize(ptmx, &pty.Winsize{
		Rows: 24,
		Cols: 80,
	}); err != nil {
		log.Printf("Failed to set PTY size: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	session := &ShellSession{
		conn:    conn,
		cmd:     cmd,
		ptmx:    ptmx,
		cleanup: make(chan bool, 1),
		ctx:     ctx,
		cancel:  cancel,
		isWindows: false,
	}

	// Store session for management
	sessionID := fmt.Sprintf("%p", session)
	a.sessionMu.Lock()
	a.sessions[sessionID] = session
	a.sessionMu.Unlock()

	// Set up cleanup when session ends
	go func() {
		<-session.cleanup
		a.sessionMu.Lock()
		delete(a.sessions, sessionID)
		a.sessionMu.Unlock()
	}()

	return session
}

// Windows-specific shell session without PTY
func (a *Agent) createWindowsShellSession(conn *websocket.Conn) *ShellSession {
	cmd := exec.Command("cmd")
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")
	
	// Create pipes for stdin, stdout, stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		log.Printf("Failed to create stdin pipe: %v", err)
		return nil
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Printf("Failed to create stdout pipe: %v", err)
		stdin.Close()
		return nil
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		log.Printf("Failed to create stderr pipe: %v", err)
		stdin.Close()
		stdout.Close()
		return nil
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		log.Printf("Failed to start shell: %v", err)
		stdin.Close()
		stdout.Close()
		stderr.Close()
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	session := &ShellSession{
		conn:      conn,
		cmd:       cmd,
		stdin:     stdin,
		stdout:    stdout,
		stderr:    stderr,
		cleanup:   make(chan bool, 1),
		ctx:       ctx,
		cancel:    cancel,
		isWindows: true,
	}

	// Store session for management
	sessionID := fmt.Sprintf("%p", session)
	a.sessionMu.Lock()
	a.sessions[sessionID] = session
	a.sessionMu.Unlock()

	// Set up cleanup when session ends
	go func() {
		<-session.cleanup
		a.sessionMu.Lock()
		delete(a.sessions, sessionID)
		a.sessionMu.Unlock()
	}()

	return session
}

func (a *Agent) handleShellSession(session *ShellSession) {
	defer func() {
		session.cancel()
		session.cleanup <- true
		session.conn.Close()
		if session.ptmx != nil {
			session.ptmx.Close()
		}
		if session.stdin != nil {
			session.stdin.Close()
		}
		if session.cmd.Process != nil {
			session.cmd.Process.Kill()
		}
		log.Printf("Shell session ended")
	}()

	// Goroutine to read from stdout/PTY and send to websocket
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("Output goroutine panic recovered: %v", r)
			}
		}()
		
		// Use raw byte reading instead of line scanning to preserve terminal control sequences
		buffer := make([]byte, 4096)
		var reader io.Reader
		if session.ptmx != nil {
			reader = session.ptmx
		} else {
			reader = session.stdout
		}
		
		for {
			select {
			case <-session.ctx.Done():
				log.Printf("Output goroutine cancelled")
				return
			default:
			}
			
			n, err := reader.Read(buffer)
			if err != nil {
				if err != io.EOF {
					log.Printf("Error reading output: %v", err)
				}
				return
			}
			
			if n > 0 {
				session.mutex.Lock()
				err := session.conn.WriteMessage(websocket.BinaryMessage, buffer[:n])
				session.mutex.Unlock()
				if err != nil {
					if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
						log.Printf("Output websocket connection closed: %v", err)
					}
					return
				}
			}
		}
	}()

	// Goroutine to read from stderr and send to websocket (only for non-PTY sessions)
	if session.stderr != nil {
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("Stderr goroutine panic recovered: %v", r)
				}
			}()
			
			// Use raw byte reading for stderr as well
			buffer := make([]byte, 4096)
			for {
				select {
				case <-session.ctx.Done():
					log.Printf("Stderr goroutine cancelled")
					return
				default:
				}
				
				n, err := session.stderr.Read(buffer)
				if err != nil {
					if err != io.EOF {
						log.Printf("Error reading from stderr: %v", err)
					}
					return
				}
				
				if n > 0 {
					session.mutex.Lock()
					err := session.conn.WriteMessage(websocket.BinaryMessage, buffer[:n])
					session.mutex.Unlock()
					if err != nil {
						if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
							log.Printf("Stderr websocket connection closed: %v", err)
						}
						return
					}
				}
			}
		}()
	}

	// Read from websocket and write to stdin
	for {
		select {
		case <-session.ctx.Done():
			log.Printf("Main websocket loop cancelled")
			return
		default:
		}
		
		_, message, err := session.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("Websocket read error: %v", err)
			} else {
				log.Printf("Websocket connection closed normally")
			}
			break
		}

		// Write input to PTY or stdin
		var writer io.Writer
		if session.ptmx != nil {
			writer = session.ptmx
		} else {
			writer = session.stdin
		}
		
		_, err = writer.Write(message)
		if err != nil {
			log.Printf("Failed to write to shell: %v", err)
			break
		}
	}

	// Wait for command to finish
	session.cmd.Wait()
}