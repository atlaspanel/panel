package main

import (
	"bufio"
	"bytes"
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
	"sync"
	"time"

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

type SystemInfo struct {
	OS          string  `json:"os"`
	Arch        string  `json:"arch"`
	CPUUsage    float64 `json:"cpu_usage"`
	RAMUsage    float64 `json:"ram_usage"`
	RAMTotal    uint64  `json:"ram_total"`
	DiskUsage   float64 `json:"disk_usage"`
	DiskTotal   uint64  `json:"disk_total"`
	Uptime      uint64  `json:"uptime"`
}

type ShellSession struct {
	conn    *websocket.Conn
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	stdout  io.ReadCloser
	stderr  io.ReadCloser
	cleanup chan bool
	mutex   sync.Mutex
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
	var shellArgs []string
	
	switch runtime.GOOS {
	case "windows":
		shellCmd = "cmd"
		shellArgs = []string{"/C", "cmd"}
	default:
		shellCmd = "/bin/bash"
		shellArgs = []string{"-i"}
	}

	cmd := exec.Command(shellCmd, shellArgs...)
	
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

	session := &ShellSession{
		conn:    conn,
		cmd:     cmd,
		stdin:   stdin,
		stdout:  stdout,
		stderr:  stderr,
		cleanup: make(chan bool, 1),
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
		session.cleanup <- true
		session.conn.Close()
		session.stdin.Close()
		if session.cmd.Process != nil {
			session.cmd.Process.Kill()
		}
		log.Printf("Shell session ended")
	}()

	// Goroutine to read from stdout and send to websocket
	go func() {
		scanner := bufio.NewScanner(session.stdout)
		for scanner.Scan() {
			output := scanner.Text() + "\n"
			session.mutex.Lock()
			err := session.conn.WriteMessage(websocket.TextMessage, []byte(output))
			session.mutex.Unlock()
			if err != nil {
				log.Printf("Failed to write stdout to websocket: %v", err)
				return
			}
		}
	}()

	// Goroutine to read from stderr and send to websocket
	go func() {
		scanner := bufio.NewScanner(session.stderr)
		for scanner.Scan() {
			output := scanner.Text() + "\n"
			session.mutex.Lock()
			err := session.conn.WriteMessage(websocket.TextMessage, []byte(output))
			session.mutex.Unlock()
			if err != nil {
				log.Printf("Failed to write stderr to websocket: %v", err)
				return
			}
		}
	}()

	// Read from websocket and write to stdin
	for {
		_, message, err := session.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("Websocket read error: %v", err)
			}
			break
		}

		// Write input to shell stdin
		_, err = session.stdin.Write(message)
		if err != nil {
			log.Printf("Failed to write to shell stdin: %v", err)
			break
		}
	}

	// Wait for command to finish
	session.cmd.Wait()
}