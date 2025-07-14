package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
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

type API struct {
	db       *sql.DB
	config   *Config
	upgrader websocket.Upgrader
	shells   map[string]*ShellProxy
	shellMu  sync.RWMutex
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
				return true // Allow connections from any origin for now
			},
		},
		shells: make(map[string]*ShellProxy),
	}
	api.initDB()

	r := gin.Default()
	r.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", strings.Join(config.CORS.AllowOrigins, ", "))
		c.Header("Access-Control-Allow-Methods", strings.Join(config.CORS.AllowMethods, ", "))
		c.Header("Access-Control-Allow-Headers", strings.Join(config.CORS.AllowHeaders, ", "))
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	// Auth routes
	r.POST("/auth/login", api.login)
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