package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"time"

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

type Agent struct {
	config Config
	client *http.Client
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