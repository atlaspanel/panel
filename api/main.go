package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

type Node struct {
	ID          string    `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	URL         string    `json:"url" db:"url"`
	Key         string    `json:"key" db:"key"`
	Status      string    `json:"status" db:"status"`
	LastSeen    time.Time `json:"last_seen" db:"last_seen"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	SystemInfo  string    `json:"system_info" db:"system_info"`
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

type User struct {
	ID        string    `json:"id" db:"id"`
	Username  string    `json:"username" db:"username"`
	Password  string    `json:"-" db:"password"`
	Role      string    `json:"role" db:"role"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

type Webhook struct {
	ID           string    `json:"id" db:"id"`
	Name         string    `json:"name" db:"name"`
	Type         string    `json:"type" db:"type"` // "discord" or "custom"
	URL          string    `json:"url" db:"url"`
	Events       string    `json:"events" db:"events"` // JSON array of event types
	Headers      string    `json:"headers" db:"headers"` // JSON object for custom headers
	Secret       string    `json:"secret,omitempty" db:"secret"`
	Enabled      bool      `json:"enabled" db:"enabled"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	LastTriggered sql.NullTime `json:"last_triggered,omitempty" db:"last_triggered"`
	FailureCount int       `json:"failure_count" db:"failure_count"`
}

type WebhookEvent struct {
	Type      string                 `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
}

type Claims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

type Config struct {
	Server struct {
		Port string `json:"port"`
		Host string `json:"host"`
	} `json:"server"`
	Database struct {
		Path string `json:"path"`
	} `json:"database"`
	JWT struct {
		Secret          string `json:"secret"`
		ExpirationHours int    `json:"expiration_hours"`
	} `json:"jwt"`
	Heartbeat struct {
		IntervalSeconds int `json:"interval_seconds"`
		TimeoutSeconds  int `json:"timeout_seconds"`
	} `json:"heartbeat"`
	CORS struct {
		AllowOrigins []string `json:"allow_origins"`
		AllowMethods []string `json:"allow_methods"`
		AllowHeaders []string `json:"allow_headers"`
	} `json:"cors"`
}

type ShellProxy struct {
	clientConn *websocket.Conn
	nodeConn   *websocket.Conn
	nodeID     string
	userID     string
	username   string
	startTime  time.Time
	mutex      sync.Mutex
}

type RateLimiter struct {
	requests map[string][]time.Time
	mutex    sync.RWMutex
	limit    int
	window   time.Duration
}

type API struct {
	db          *sql.DB
	config      *Config
	upgrader    websocket.Upgrader
	shells      map[string]*ShellProxy
	shellMu     sync.RWMutex
	rateLimiter *RateLimiter
}

func main() {
	config, err := loadConfig()
	if err != nil {
		log.Fatal("Failed to load config:", err)
	}

	db, err := sql.Open("sqlite", config.Database.Path)
	if err != nil {
		log.Fatal("Failed to open database:", err)
	}
	defer db.Close()

	api := &API{
		db:     db,
		config: config,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				origin := r.Header.Get("Origin")
				if origin == "" {
					// Allow connections without origin header (direct tools)
					return true
				}
				
				// Check if origin is in the allowed CORS origins
				for _, allowedOrigin := range config.CORS.AllowOrigins {
					if allowedOrigin == "*" {
						// If wildcard is configured, allow all (should be avoided in production)
						return true
					}
					if origin == allowedOrigin {
						return true
					}
				}
				
				return false
			},
		},
		shells: make(map[string]*ShellProxy),
		rateLimiter: &RateLimiter{
			requests: make(map[string][]time.Time),
			limit:    30, // 30 requests per minute
			window:   time.Minute,
		},
	}
	api.initDB()

	r := gin.Default()
	r.Use(func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		
		// Set CORS headers based on origin validation
		if origin != "" {
			allowed := false
			for _, allowedOrigin := range config.CORS.AllowOrigins {
				if allowedOrigin == "*" {
					// If wildcard is configured, allow but be explicit about it
					c.Header("Access-Control-Allow-Origin", origin)
					allowed = true
					break
				} else if origin == allowedOrigin {
					c.Header("Access-Control-Allow-Origin", allowedOrigin)
					allowed = true
					break
				}
			}
			
			if !allowed {
				// Don't set CORS headers for unauthorized origins
				if c.Request.Method == "OPTIONS" {
					c.AbortWithStatus(403)
					return
				}
			} else {
				c.Header("Access-Control-Allow-Methods", strings.Join(config.CORS.AllowMethods, ", "))
				c.Header("Access-Control-Allow-Headers", strings.Join(config.CORS.AllowHeaders, ", "))
				c.Header("Access-Control-Allow-Credentials", "true")
			}
		}
		
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	// Auth routes with rate limiting
	r.POST("/auth/login", api.rateLimitMiddleware(), api.login)
	r.POST("/auth/logout", api.logout)
	
	// User management routes (admin only)
	authorized := r.Group("/")
	authorized.Use(api.authMiddleware())
	{
		authorized.GET("/me", api.getCurrentUser)
		authorized.GET("/users", api.requireAdmin(), api.getUsers)
		authorized.POST("/users", api.requireAdmin(), api.createUser)
		authorized.DELETE("/users/:id", api.requireAdmin(), api.deleteUser)
		authorized.PUT("/account/password", api.changePassword)
		
		// Node routes (read for all authenticated users, write for admin only)
		authorized.GET("/nodes", api.getNodes)
		authorized.POST("/nodes", api.requireAdmin(), api.createNode)
		authorized.DELETE("/nodes/:id", api.requireAdmin(), api.deleteNode)
		
		// Webhook routes (admin only)
		authorized.GET("/webhooks", api.requireAdmin(), api.getWebhooks)
		authorized.POST("/webhooks", api.requireAdmin(), api.createWebhook)
		authorized.GET("/webhooks/:id", api.requireAdmin(), api.getWebhook)
		authorized.PUT("/webhooks/:id", api.requireAdmin(), api.updateWebhook)
		authorized.DELETE("/webhooks/:id", api.requireAdmin(), api.deleteWebhook)
		authorized.POST("/webhooks/:id/test", api.requireAdmin(), api.testWebhook)
	}
	
	// Shell access (admin/sys only) - auth handled inside handler for WebSocket compatibility
	r.GET("/nodes/:id/shell", api.handleShellProxy)
	
	// Heartbeat doesn't need user auth, only node key
	r.POST("/heartbeat", api.heartbeat)

	go api.startHeartbeatChecker()

	address := config.Server.Host + ":" + config.Server.Port
	log.Printf("Atlas Panel API starting on %s", address)
	r.Run(address)
}

func (api *API) initDB() {
	// Create nodes table
	nodesQuery := `
	CREATE TABLE IF NOT EXISTS nodes (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		url TEXT NOT NULL,
		key TEXT UNIQUE NOT NULL,
		status TEXT DEFAULT 'offline',
		last_seen DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		system_info TEXT DEFAULT '{}'
	)`
	
	if _, err := api.db.Exec(nodesQuery); err != nil {
		log.Fatal("Failed to create nodes table:", err)
	}

	// Create users table
	usersQuery := `
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		role TEXT NOT NULL DEFAULT 'user',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`
	
	if _, err := api.db.Exec(usersQuery); err != nil {
		log.Fatal("Failed to create users table:", err)
	}

	// Create webhooks table
	webhooksQuery := `
	CREATE TABLE IF NOT EXISTS webhooks (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		type TEXT NOT NULL DEFAULT 'custom',
		url TEXT NOT NULL,
		events TEXT NOT NULL DEFAULT '[]',
		headers TEXT DEFAULT '{}',
		secret TEXT,
		enabled BOOLEAN DEFAULT true,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_triggered DATETIME,
		failure_count INTEGER DEFAULT 0
	)`
	
	if _, err := api.db.Exec(webhooksQuery); err != nil {
		log.Fatal("Failed to create webhooks table:", err)
	}

	// Create default admin user
	api.createDefaultAdmin()
}

func (api *API) createDefaultAdmin() {
	var count int
	err := api.db.QueryRow("SELECT COUNT(*) FROM users WHERE role = 'sys'").Scan(&count)
	if err != nil {
		log.Fatal("Failed to check for sys admin:", err)
	}

	if count == 0 {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
		if err != nil {
			log.Fatal("Failed to hash default admin password:", err)
		}

		_, err = api.db.Exec(
			"INSERT INTO users (id, username, password, role, created_at) VALUES (?, ?, ?, ?, ?)",
			uuid.New().String(), "admin", string(hashedPassword), "sys", time.Now(),
		)
		if err != nil {
			log.Fatal("Failed to create default admin user:", err)
		}

		log.Println("Created default admin user: admin/admin")
	}
}

func (api *API) createNode(c *gin.Context) {
	var req struct {
		Name string `json:"name" binding:"required"`
		URL  string `json:"url" binding:"required"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	node := Node{
		ID:        uuid.New().String(),
		Name:      req.Name,
		URL:       req.URL,
		Key:       uuid.New().String(),
		Status:    "offline",
		CreatedAt: time.Now(),
	}

	_, err := api.db.Exec(
		"INSERT INTO nodes (id, name, url, key, status, created_at, system_info) VALUES (?, ?, ?, ?, ?, ?, ?)",
		node.ID, node.Name, node.URL, node.Key, node.Status, node.CreatedAt, "{}",
	)
	
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to create node"})
		return
	}

	// Trigger webhook event
	go api.triggerWebhookEvent("node.created", map[string]interface{}{
		"node_id":   node.ID,
		"node_name": node.Name,
		"node_url":  node.URL,
		"message":   fmt.Sprintf("Node '%s' has been created", node.Name),
	})

	c.JSON(201, node)
}

func (api *API) getNodes(c *gin.Context) {
	rows, err := api.db.Query("SELECT id, name, url, key, status, last_seen, created_at, system_info FROM nodes")
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to fetch nodes"})
		return
	}
	defer rows.Close()

	var nodes []Node
	for rows.Next() {
		var node Node
		var lastSeen sql.NullTime
		
		err := rows.Scan(&node.ID, &node.Name, &node.URL, &node.Key, &node.Status, &lastSeen, &node.CreatedAt, &node.SystemInfo)
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to scan node"})
			return
		}
		
		if lastSeen.Valid {
			node.LastSeen = lastSeen.Time
		}
		
		nodes = append(nodes, node)
	}

	c.JSON(200, nodes)
}

func (api *API) deleteNode(c *gin.Context) {
	id := c.Param("id")
	
	// Get node info before deletion for webhook
	var nodeName string
	err := api.db.QueryRow("SELECT name FROM nodes WHERE id = ?", id).Scan(&nodeName)
	if err != nil {
		c.JSON(404, gin.H{"error": "Node not found"})
		return
	}
	
	result, err := api.db.Exec("DELETE FROM nodes WHERE id = ?", id)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to delete node"})
		return
	}
	
	affected, _ := result.RowsAffected()
	if affected == 0 {
		c.JSON(404, gin.H{"error": "Node not found"})
		return
	}

	// Trigger webhook event
	go api.triggerWebhookEvent("node.deleted", map[string]interface{}{
		"node_id":   id,
		"node_name": nodeName,
		"message":   fmt.Sprintf("Node '%s' has been deleted", nodeName),
	})

	c.JSON(200, gin.H{"message": "Node deleted"})
}

func (api *API) heartbeat(c *gin.Context) {
	key := c.GetHeader("Authorization")
	if key == "" {
		c.JSON(401, gin.H{"error": "Missing authorization key"})
		return
	}

	var systemInfo SystemInfo
	if err := c.ShouldBindJSON(&systemInfo); err != nil {
		c.JSON(400, gin.H{"error": "Invalid system info"})
		return
	}

	// Get current node status to check for status changes
	var nodeID, nodeName, currentStatus string
	err := api.db.QueryRow("SELECT id, name, status FROM nodes WHERE key = ?", key).Scan(&nodeID, &nodeName, &currentStatus)
	if err != nil {
		c.JSON(401, gin.H{"error": "Invalid node key"})
		return
	}

	systemInfoJSON, err := json.Marshal(systemInfo)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to marshal system info"})
		return
	}

	_, err = api.db.Exec(
		"UPDATE nodes SET status = 'online', last_seen = ?, system_info = ? WHERE key = ?",
		time.Now(), string(systemInfoJSON), key,
	)
	
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to update heartbeat"})
		return
	}

	// Check for status change (offline -> online)
	if currentStatus != "online" {
		go api.triggerWebhookEvent("node.status.changed", map[string]interface{}{
			"node_id":     nodeID,
			"node_name":   nodeName,
			"status":      "online",
			"old_status":  currentStatus,
			"message":     fmt.Sprintf("Node '%s' came online", nodeName),
		})
	}

	// Check for resource thresholds
	go api.checkResourceThresholds(nodeID, nodeName, &systemInfo)

	c.JSON(200, gin.H{"status": "ok"})
}

// Authentication middleware
func (api *API) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Bearer token required"})
			c.Abort()
			return
		}

		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(api.config.JWT.Secret), nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		claims, ok := token.Claims.(*Claims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			c.Abort()
			return
		}

		c.Set("user_id", claims.UserID)
		c.Set("username", claims.Username)
		c.Set("role", claims.Role)
		c.Next()
	}
}

// Admin only middleware
func (api *API) requireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		role, exists := c.Get("role")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "No role found"})
			c.Abort()
			return
		}

		if role != "admin" && role != "sys" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Admin privileges required"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// Login handler
func (api *API) login(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user User
	err := api.db.QueryRow(
		"SELECT id, username, password, role FROM users WHERE username = ?",
		req.Username,
	).Scan(&user.ID, &user.Username, &user.Password, &user.Role)

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &Claims{
		UserID:   user.ID,
		Username: user.Username,
		Role:     user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(api.config.JWT.ExpirationHours) * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	})

	tokenString, err := token.SignedString([]byte(api.config.JWT.Secret))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":    tokenString,
		"user":     gin.H{"id": user.ID, "username": user.Username, "role": user.Role},
		"expires":  time.Now().Add(time.Duration(api.config.JWT.ExpirationHours) * time.Hour).Unix(),
	})
}

// Logout handler
func (api *API) logout(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

// Get users (admin only)
func (api *API) getUsers(c *gin.Context) {
	rows, err := api.db.Query("SELECT id, username, role, created_at FROM users ORDER BY created_at DESC")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch users"})
		return
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		err := rows.Scan(&user.ID, &user.Username, &user.Role, &user.CreatedAt)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to scan user"})
			return
		}
		users = append(users, user)
	}

	c.JSON(http.StatusOK, users)
}

// Create user (admin only)
func (api *API) createUser(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
		Role     string `json:"role" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Role != "user" && req.Role != "admin" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Role must be 'user' or 'admin'"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	user := User{
		ID:        uuid.New().String(),
		Username:  req.Username,
		Role:      req.Role,
		CreatedAt: time.Now(),
	}

	_, err = api.db.Exec(
		"INSERT INTO users (id, username, password, role, created_at) VALUES (?, ?, ?, ?, ?)",
		user.ID, user.Username, string(hashedPassword), user.Role, user.CreatedAt,
	)

	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			c.JSON(http.StatusConflict, gin.H{"error": "Username already exists"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		}
		return
	}

	// Trigger webhook event for user creation
	go api.triggerWebhookEvent("user.created", map[string]interface{}{
		"user_id":   user.ID,
		"username":  user.Username,
		"role":      user.Role,
		"message":   fmt.Sprintf("User '%s' with role '%s' has been created", user.Username, user.Role),
	})

	c.JSON(http.StatusCreated, user)
}

// Delete user (admin only)
func (api *API) deleteUser(c *gin.Context) {
	userID := c.Param("id")

	// Check if user is sys role (cannot be deleted)
	var role string
	err := api.db.QueryRow("SELECT role FROM users WHERE id = ?", userID).Scan(&role)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	if role == "sys" {
		c.JSON(http.StatusForbidden, gin.H{"error": "System admin cannot be deleted"})
		return
	}

	result, err := api.db.Exec("DELETE FROM users WHERE id = ?", userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete user"})
		return
	}

	affected, _ := result.RowsAffected()
	if affected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
}

// Get current user info
func (api *API) getCurrentUser(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	var user User
	err := api.db.QueryRow(
		"SELECT id, username, role, created_at FROM users WHERE id = ?",
		userID,
	).Scan(&user.ID, &user.Username, &user.Role, &user.CreatedAt)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user": user,
	})
}

// Change password
func (api *API) changePassword(c *gin.Context) {
	var req struct {
		CurrentPassword string `json:"current_password" binding:"required"`
		NewPassword     string `json:"new_password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	var currentPassword string
	err := api.db.QueryRow("SELECT password FROM users WHERE id = ?", userID).Scan(&currentPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user"})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(currentPassword), []byte(req.CurrentPassword))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Current password is incorrect"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	_, err = api.db.Exec("UPDATE users SET password = ? WHERE id = ?", string(hashedPassword), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password updated successfully"})
}

func (api *API) startHeartbeatChecker() {
	ticker := time.NewTicker(time.Duration(api.config.Heartbeat.IntervalSeconds) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		threshold := time.Now().Add(-time.Duration(api.config.Heartbeat.TimeoutSeconds) * time.Second)
		
		// Get nodes that will be marked offline
		rows, err := api.db.Query("SELECT id, name, status FROM nodes WHERE (last_seen < ? OR last_seen IS NULL) AND status = 'online'", threshold)
		if err == nil {
			for rows.Next() {
				var nodeID, nodeName, status string
				if rows.Scan(&nodeID, &nodeName, &status) == nil {
					// Trigger webhook for status change
					go api.triggerWebhookEvent("node.status.changed", map[string]interface{}{
						"node_id":     nodeID,
						"node_name":   nodeName,
						"status":      "offline",
						"old_status":  status,
						"message":     fmt.Sprintf("Node '%s' went offline", nodeName),
					})
				}
			}
			rows.Close()
		}
		
		api.db.Exec("UPDATE nodes SET status = 'offline' WHERE last_seen < ? OR last_seen IS NULL", threshold)
	}
}

func loadConfig() (*Config, error) {
	configFile := "config.json"
	if envFile := os.Getenv("ATLAS_CONFIG_FILE"); envFile != "" {
		configFile = envFile
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, err
	}

	var config Config
	err = json.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	// Override with environment variables if set
	if port := os.Getenv("ATLAS_PORT"); port != "" {
		config.Server.Port = port
	}
	if host := os.Getenv("ATLAS_HOST"); host != "" {
		config.Server.Host = host
	}
	if dbPath := os.Getenv("ATLAS_DB_PATH"); dbPath != "" {
		config.Database.Path = dbPath
	}
	if jwtSecret := os.Getenv("ATLAS_JWT_SECRET"); jwtSecret != "" {
		config.JWT.Secret = jwtSecret
	}
	if expHours := os.Getenv("ATLAS_JWT_EXPIRATION_HOURS"); expHours != "" {
		if hours, err := strconv.Atoi(expHours); err == nil {
			config.JWT.ExpirationHours = hours
		}
	}

	return &config, nil
}

func (api *API) parseJWTToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(api.config.JWT.Secret), nil
	})

	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}

func (api *API) handleShellProxy(c *gin.Context) {
	nodeID := c.Param("id")
	
	// Handle WebSocket auth differently since browsers don't support custom headers on WebSocket
	// Check for token in query parameter first, then fall back to normal auth
	var userID, username, role interface{}
	var authOk bool
	
	if token := c.Query("token"); token != "" {
		// Parse JWT token from query parameter
		claims, err := api.parseJWTToken(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}
		userID = claims.UserID
		username = claims.Username
		role = claims.Role
		authOk = true
	} else {
		// Try normal middleware auth
		userID, authOk = c.Get("user_id")
		if authOk {
			username, _ = c.Get("username")
			role, _ = c.Get("role")
		}
	}
	
	if !authOk {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}
	
	// Additional role check (redundant but good practice)
	if role != "admin" && role != "sys" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Shell access requires admin privileges"})
		return
	}
	
	// Get node info from database
	var node Node
	err := api.db.QueryRow(
		"SELECT id, name, url, key, status FROM nodes WHERE id = ?",
		nodeID,
	).Scan(&node.ID, &node.Name, &node.URL, &node.Key, &node.Status)
	
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Node not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query node"})
		}
		return
	}
	
	// Check if node is online
	if node.Status != "online" {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Node is offline"})
		return
	}
	
	// Upgrade client connection to WebSocket
	clientConn, err := api.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("Failed to upgrade client connection: %v", err)
		return
	}
	
	log.Printf("Shell access requested by user %s (%s) for node %s (%s)", 
		username, userID, node.Name, node.ID)
	
	// Create proxy session
	proxy := &ShellProxy{
		clientConn: clientConn,
		nodeID:     node.ID,
		userID:     userID.(string),
		username:   username.(string),
		startTime:  time.Now(),
	}
	
	// Connect to node's shell endpoint
	if err := api.connectToNodeShell(proxy, &node); err != nil {
		log.Printf("Failed to connect to node shell: %v", err)
		clientConn.WriteMessage(websocket.TextMessage, []byte("Failed to connect to node shell: "+err.Error()))
		clientConn.Close()
		return
	}
	
	// Store proxy session
	sessionID := fmt.Sprintf("%s-%s-%d", userID, nodeID, time.Now().Unix())
	api.shellMu.Lock()
	api.shells[sessionID] = proxy
	api.shellMu.Unlock()
	
	// Clean up when session ends
	defer func() {
		api.shellMu.Lock()
		delete(api.shells, sessionID)
		api.shellMu.Unlock()
		
		log.Printf("Shell session ended: user %s, node %s, duration %v", 
			proxy.username, proxy.nodeID, time.Since(proxy.startTime))
	}()
	
	// Start proxying
	api.proxyShellSession(proxy)
}

func (api *API) connectToNodeShell(proxy *ShellProxy, node *Node) error {
	// Parse node URL to get WebSocket URL
	nodeURL, err := url.Parse(node.URL)
	if err != nil {
		return fmt.Errorf("invalid node URL: %v", err)
	}
	
	// Convert HTTP URL to WebSocket URL
	wsScheme := "ws"
	if nodeURL.Scheme == "https" {
		wsScheme = "wss"
	}
	
	shellURL := fmt.Sprintf("%s://%s/shell", wsScheme, nodeURL.Host)
	
	// Create headers with node authentication
	headers := http.Header{}
	headers.Set("Authorization", node.Key)
	
	// Connect to node's shell endpoint
	nodeConn, _, err := websocket.DefaultDialer.Dial(shellURL, headers)
	if err != nil {
		return fmt.Errorf("failed to dial node shell: %v", err)
	}
	
	proxy.nodeConn = nodeConn
	return nil
}

func (api *API) proxyShellSession(proxy *ShellProxy) {
	defer func() {
		if proxy.clientConn != nil {
			proxy.clientConn.Close()
		}
		if proxy.nodeConn != nil {
			proxy.nodeConn.Close()
		}
	}()
	
	// Channel to signal completion
	done := make(chan bool, 2)
	
	// Proxy messages from client to node
	go func() {
		defer func() { done <- true }()
		for {
			_, message, err := proxy.clientConn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					log.Printf("Client websocket read error: %v", err)
				}
				return
			}
			
			proxy.mutex.Lock()
			err = proxy.nodeConn.WriteMessage(websocket.TextMessage, message)
			proxy.mutex.Unlock()
			
			if err != nil {
				log.Printf("Failed to write to node: %v", err)
				return
			}
		}
	}()
	
	// Proxy messages from node to client
	go func() {
		defer func() { done <- true }()
		for {
			_, message, err := proxy.nodeConn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					log.Printf("Node websocket read error: %v", err)
				}
				return
			}
			
			proxy.mutex.Lock()
			err = proxy.clientConn.WriteMessage(websocket.TextMessage, message)
			proxy.mutex.Unlock()
			
			if err != nil {
				log.Printf("Failed to write to client: %v", err)
				return
			}
		}
	}()
	
	// Wait for either direction to close
	<-done
}

func (rl *RateLimiter) isAllowed(clientIP string) bool {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()
	
	now := time.Now()
	
	// Clean old requests outside the time window
	if requests, exists := rl.requests[clientIP]; exists {
		var validRequests []time.Time
		for _, requestTime := range requests {
			if now.Sub(requestTime) < rl.window {
				validRequests = append(validRequests, requestTime)
			}
		}
		rl.requests[clientIP] = validRequests
	}
	
	// Check if under limit
	if len(rl.requests[clientIP]) < rl.limit {
		rl.requests[clientIP] = append(rl.requests[clientIP], now)
		return true
	}
	
	return false
}

func (api *API) rateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		
		// Extract real IP if behind proxy
		if forwarded := c.GetHeader("X-Forwarded-For"); forwarded != "" {
			ips := strings.Split(forwarded, ",")
			if len(ips) > 0 {
				clientIP = strings.TrimSpace(ips[0])
			}
		} else if realIP := c.GetHeader("X-Real-IP"); realIP != "" {
			clientIP = realIP
		}
		
		// Validate IP format
		if net.ParseIP(clientIP) == nil {
			clientIP = c.ClientIP() // fallback to gin's method
		}
		
		if !api.rateLimiter.isAllowed(clientIP) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Rate limit exceeded. Please try again later.",
			})
			c.Abort()
			return
		}
		
		c.Next()
	}
}

// Webhook handlers
func (api *API) getWebhooks(c *gin.Context) {
	rows, err := api.db.Query("SELECT id, name, type, url, events, headers, secret, enabled, created_at, last_triggered, failure_count FROM webhooks ORDER BY created_at DESC")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch webhooks"})
		return
	}
	defer rows.Close()

	var webhooks []Webhook
	for rows.Next() {
		var webhook Webhook
		err := rows.Scan(&webhook.ID, &webhook.Name, &webhook.Type, &webhook.URL, &webhook.Events, &webhook.Headers, &webhook.Secret, &webhook.Enabled, &webhook.CreatedAt, &webhook.LastTriggered, &webhook.FailureCount)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to scan webhook"})
			return
		}
		webhooks = append(webhooks, webhook)
	}

	c.JSON(http.StatusOK, webhooks)
}

func (api *API) createWebhook(c *gin.Context) {
	var req struct {
		Name    string            `json:"name" binding:"required"`
		Type    string            `json:"type" binding:"required"`
		URL     string            `json:"url" binding:"required"`
		Events  []string          `json:"events" binding:"required"`
		Headers map[string]string `json:"headers"`
		Secret  string            `json:"secret"`
		Enabled bool              `json:"enabled"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate webhook type
	if req.Type != "discord" && req.Type != "custom" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Type must be 'discord' or 'custom'"})
		return
	}

	// Validate events
	validEvents := map[string]bool{
		"node.status.changed": true,
		"node.created":        true,
		"node.deleted":        true,
		"node.metric.cpu":     true,
		"node.metric.ram":     true,
		"node.metric.disk":    true,
		"user.created":        true,
		"auth.failed":         true,
	}
	
	for _, event := range req.Events {
		if !validEvents[event] {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid event type: %s", event)})
			return
		}
	}

	eventsJSON, _ := json.Marshal(req.Events)
	headersJSON, _ := json.Marshal(req.Headers)

	webhook := Webhook{
		ID:        uuid.New().String(),
		Name:      req.Name,
		Type:      req.Type,
		URL:       req.URL,
		Events:    string(eventsJSON),
		Headers:   string(headersJSON),
		Secret:    req.Secret,
		Enabled:   req.Enabled,
		CreatedAt: time.Now(),
	}

	_, err := api.db.Exec(
		"INSERT INTO webhooks (id, name, type, url, events, headers, secret, enabled, created_at, failure_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		webhook.ID, webhook.Name, webhook.Type, webhook.URL, webhook.Events, webhook.Headers, webhook.Secret, webhook.Enabled, webhook.CreatedAt, 0,
	)
	
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create webhook"})
		return
	}

	c.JSON(http.StatusCreated, webhook)
}

func (api *API) getWebhook(c *gin.Context) {
	id := c.Param("id")
	
	var webhook Webhook
	err := api.db.QueryRow(
		"SELECT id, name, type, url, events, headers, secret, enabled, created_at, last_triggered, failure_count FROM webhooks WHERE id = ?",
		id,
	).Scan(&webhook.ID, &webhook.Name, &webhook.Type, &webhook.URL, &webhook.Events, &webhook.Headers, &webhook.Secret, &webhook.Enabled, &webhook.CreatedAt, &webhook.LastTriggered, &webhook.FailureCount)

	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Webhook not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get webhook"})
		}
		return
	}

	c.JSON(http.StatusOK, webhook)
}

func (api *API) updateWebhook(c *gin.Context) {
	id := c.Param("id")
	
	var req struct {
		Name    string            `json:"name" binding:"required"`
		Type    string            `json:"type" binding:"required"`
		URL     string            `json:"url" binding:"required"`
		Events  []string          `json:"events" binding:"required"`
		Headers map[string]string `json:"headers"`
		Secret  string            `json:"secret"`
		Enabled bool              `json:"enabled"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate webhook type
	if req.Type != "discord" && req.Type != "custom" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Type must be 'discord' or 'custom'"})
		return
	}

	eventsJSON, _ := json.Marshal(req.Events)
	headersJSON, _ := json.Marshal(req.Headers)

	result, err := api.db.Exec(
		"UPDATE webhooks SET name = ?, type = ?, url = ?, events = ?, headers = ?, secret = ?, enabled = ? WHERE id = ?",
		req.Name, req.Type, req.URL, string(eventsJSON), string(headersJSON), req.Secret, req.Enabled, id,
	)
	
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update webhook"})
		return
	}
	
	affected, _ := result.RowsAffected()
	if affected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Webhook not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Webhook updated successfully"})
}

func (api *API) deleteWebhook(c *gin.Context) {
	id := c.Param("id")
	
	result, err := api.db.Exec("DELETE FROM webhooks WHERE id = ?", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete webhook"})
		return
	}
	
	affected, _ := result.RowsAffected()
	if affected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Webhook not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Webhook deleted successfully"})
}

func (api *API) testWebhook(c *gin.Context) {
	id := c.Param("id")
	
	var webhook Webhook
	err := api.db.QueryRow(
		"SELECT id, name, type, url, events, headers, secret, enabled FROM webhooks WHERE id = ?",
		id,
	).Scan(&webhook.ID, &webhook.Name, &webhook.Type, &webhook.URL, &webhook.Events, &webhook.Headers, &webhook.Secret, &webhook.Enabled)

	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Webhook not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get webhook"})
		}
		return
	}

	// Create test event
	testEvent := WebhookEvent{
		Type:      "webhook.test",
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"message": "This is a test webhook from Atlas Panel",
			"webhook_id": webhook.ID,
			"webhook_name": webhook.Name,
		},
	}

	// Send the webhook
	err = api.sendWebhook(&webhook, &testEvent)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to send test webhook: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Test webhook sent successfully"})
}

func (api *API) sendWebhook(webhook *Webhook, event *WebhookEvent) error {
	if !webhook.Enabled {
		return nil // Skip disabled webhooks
	}

	var payload interface{}
	
	if webhook.Type == "discord" {
		// Format for Discord webhook
		var color int
		switch event.Type {
		case "node.status.changed":
			if status, ok := event.Data["status"].(string); ok && status == "online" {
				color = 3066993 // Green
			} else {
				color = 15158332 // Red
			}
		case "node.created":
			color = 3447003 // Blue
		case "node.deleted":
			color = 15158332 // Red
		case "webhook.test":
			color = 16776960 // Yellow
		default:
			color = 8421504 // Gray
		}

		title := event.Type
		description := fmt.Sprintf("Event occurred at %s", event.Timestamp.Format("2006-01-02 15:04:05 UTC"))
		
		if message, ok := event.Data["message"].(string); ok {
			description = message
		}

		payload = map[string]interface{}{
			"embeds": []map[string]interface{}{
				{
					"title":       title,
					"description": description,
					"color":       color,
					"timestamp":   event.Timestamp.Format(time.RFC3339),
					"footer": map[string]interface{}{
						"text": "Atlas Panel",
					},
					"fields": []map[string]interface{}{},
				},
			},
		}

		// Add fields based on event data
		if embed, ok := payload.(map[string]interface{})["embeds"].([]map[string]interface{}); ok && len(embed) > 0 {
			fields := embed[0]["fields"].([]map[string]interface{})
			
			for key, value := range event.Data {
				if key != "message" {
					fields = append(fields, map[string]interface{}{
						"name":   strings.Title(strings.ReplaceAll(key, "_", " ")),
						"value":  fmt.Sprintf("%v", value),
						"inline": true,
					})
				}
			}
			embed[0]["fields"] = fields
		}
	} else {
		// Custom webhook format
		payload = event
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %v", err)
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", webhook.URL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Atlas-Panel-Webhook/1.0")

	// Add custom headers
	var headers map[string]string
	if err := json.Unmarshal([]byte(webhook.Headers), &headers); err == nil {
		for key, value := range headers {
			req.Header.Set(key, value)
		}
	}

	// Add signature if secret is provided
	if webhook.Secret != "" {
		mac := hmac.New(sha256.New, []byte(webhook.Secret))
		mac.Write(payloadBytes)
		signature := hex.EncodeToString(mac.Sum(nil))
		req.Header.Set("X-Atlas-Signature", "sha256="+signature)
	}

	// Send request with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	
	resp, err := client.Do(req)
	if err != nil {
		// Update failure count
		api.db.Exec("UPDATE webhooks SET failure_count = failure_count + 1 WHERE id = ?", webhook.ID)
		return fmt.Errorf("failed to send webhook: %v", err)
	}
	defer resp.Body.Close()

	// Update last triggered time
	api.db.Exec("UPDATE webhooks SET last_triggered = ?, failure_count = 0 WHERE id = ?", time.Now(), webhook.ID)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Update failure count for non-2xx responses
		api.db.Exec("UPDATE webhooks SET failure_count = failure_count + 1 WHERE id = ?", webhook.ID)
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}

func (api *API) triggerWebhookEvent(eventType string, data map[string]interface{}) {
	// Get all enabled webhooks that listen for this event type
	rows, err := api.db.Query("SELECT id, name, type, url, events, headers, secret, enabled FROM webhooks WHERE enabled = true")
	if err != nil {
		log.Printf("Failed to fetch webhooks for event %s: %v", eventType, err)
		return
	}
	defer rows.Close()

	event := &WebhookEvent{
		Type:      eventType,
		Timestamp: time.Now(),
		Data:      data,
	}

	for rows.Next() {
		var webhook Webhook
		err := rows.Scan(&webhook.ID, &webhook.Name, &webhook.Type, &webhook.URL, &webhook.Events, &webhook.Headers, &webhook.Secret, &webhook.Enabled)
		if err != nil {
			log.Printf("Failed to scan webhook: %v", err)
			continue
		}

		// Check if webhook listens for this event type
		var events []string
		if err := json.Unmarshal([]byte(webhook.Events), &events); err != nil {
			log.Printf("Failed to unmarshal webhook events: %v", err)
			continue
		}

		shouldTrigger := false
		for _, e := range events {
			if e == eventType {
				shouldTrigger = true
				break
			}
		}

		if shouldTrigger {
			go func(w Webhook) {
				if err := api.sendWebhook(&w, event); err != nil {
					log.Printf("Failed to send webhook %s (%s): %v", w.Name, w.ID, err)
				}
			}(webhook)
		}
	}
}

func (api *API) checkResourceThresholds(nodeID, nodeName string, systemInfo *SystemInfo) {
	// Define thresholds (can be made configurable later)
	const (
		cpuThreshold  = 90.0  // 90%
		ramThreshold  = 90.0  // 90%
		diskThreshold = 90.0  // 90%
	)

	if systemInfo.CPUUsage > cpuThreshold {
		api.triggerWebhookEvent("node.metric.cpu", map[string]interface{}{
			"node_id":      nodeID,
			"node_name":    nodeName,
			"metric_type":  "cpu",
			"current_value": systemInfo.CPUUsage,
			"threshold":    cpuThreshold,
			"message":      fmt.Sprintf("Node '%s' CPU usage is %.1f%% (threshold: %.1f%%)", nodeName, systemInfo.CPUUsage, cpuThreshold),
		})
	}

	if systemInfo.RAMUsage > ramThreshold {
		api.triggerWebhookEvent("node.metric.ram", map[string]interface{}{
			"node_id":       nodeID,
			"node_name":     nodeName,
			"metric_type":   "ram",
			"current_value": systemInfo.RAMUsage,
			"threshold":     ramThreshold,
			"ram_total":     systemInfo.RAMTotal,
			"message":       fmt.Sprintf("Node '%s' RAM usage is %.1f%% (threshold: %.1f%%)", nodeName, systemInfo.RAMUsage, ramThreshold),
		})
	}

	if systemInfo.DiskUsage > diskThreshold {
		api.triggerWebhookEvent("node.metric.disk", map[string]interface{}{
			"node_id":       nodeID,
			"node_name":     nodeName,
			"metric_type":   "disk",
			"current_value": systemInfo.DiskUsage,
			"threshold":     diskThreshold,
			"disk_total":    systemInfo.DiskTotal,
			"message":       fmt.Sprintf("Node '%s' disk usage is %.1f%% (threshold: %.1f%%)", nodeName, systemInfo.DiskUsage, diskThreshold),
		})
	}
}