package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

// ========================= MODELS =========================

type User struct {
	ID          int       `json:"id"`
	PhoneNumber string    `json:"phoneNumber"`
	Password    string    `json:"-"`
	Role        string    `json:"role"`
	CreatedAt   time.Time `json:"createdAt"`
}

type Client struct {
	ID        int       `json:"id"`
	Username  string    `json:"username"`
	Number    string    `json:"number"`
	Location  string    `json:"location"`
	Longitude float64   `json:"longitude"`
	Latitude  float64   `json:"latitude"`
	CreatedBy int       `json:"createdBy"`
	CreatedAt time.Time `json:"createdAt"`
}

type Product struct {
	ID           int       `json:"id"`
	Name         string    `json:"name"`
	Price        float64   `json:"price"`
	CategoryName string    `json:"categoryName"`
	ImageUrl     string    `json:"imageUrl"`
	Ingredients  string    `json:"ingredients"`
	CreatedAt    time.Time `json:"createdAt"`
}

type Order struct {
	ID           string     `json:"id"`
	OrderPrice   float64    `json:"orderPrice"`
	ClientID     int        `json:"clientId"`
	Comment      string     `json:"comment"`
	Status       string     `json:"status"`
	SentToOrders time.Time  `json:"sentToOrders"`
	CreatedBy    int        `json:"createdBy"`
	SmsSent      int        `json:"smsSent"`
	SmsSentAt    *time.Time `json:"smsSentAt,omitempty"`
	CreatedAt    time.Time  `json:"createdAt"`
}

type OrderItem struct {
	ID           int     `json:"id"`
	OrderID      string  `json:"orderId"`
	ProductID    int     `json:"productId"`
	ProductName  string  `json:"productName"`
	ProductPrice float64 `json:"productPrice"`
	ProductCount int     `json:"productCount"`
}

type LoginRequest struct {
	PhoneNumber string `json:"phoneNumber" binding:"required"`
	Password    string `json:"password" binding:"required"`
}

type LoginResponse struct {
	Success bool   `json:"success"`
	Token   string `json:"token,omitempty"`
	User    *User  `json:"user,omitempty"`
	Error   string `json:"error,omitempty"`
}

type CreateUserRequest struct {
	PhoneNumber string `json:"phoneNumber" binding:"required"`
	Password    string `json:"password" binding:"required"`
	Role        string `json:"role" binding:"required"`
}

type ProductRequest struct {
	Name         string  `json:"name" binding:"required"`
	Price        float64 `json:"price" binding:"required"`
	CategoryName string  `json:"categoryName" binding:"required"`
	ImageUrl     string  `json:"imageUrl"`
	Ingredients  string  `json:"ingredients"`
}

type ClientRequest struct {
	Username  string  `json:"username" binding:"required"`
	Number    string  `json:"number" binding:"required"`
	Location  string  `json:"location"`
	Longitude float64 `json:"longitude"`
	Latitude  float64 `json:"latitude"`
}

type OrderProductRequest struct {
	ProductID    int `json:"productId" binding:"required"`
	ProductCount int `json:"productCount" binding:"required"`
}

type CreateOrderRequest struct {
	ClientID     *int                  `json:"clientId"`
	NewClient    *ClientRequest        `json:"newClient"`
	Products     []OrderProductRequest `json:"products" binding:"required"`
	Comment      string                `json:"comment"`
	SentToOrders string                `json:"sentToOrders" binding:"required"`
}

type UpdateStatusRequest struct {
	Status string `json:"status" binding:"required"`
}

type OrderResponse struct {
	ID           string              `json:"id"`
	Products     []OrderItemResponse `json:"products"`
	OrderPrice   float64             `json:"orderPrice"`
	Client       ClientResponse      `json:"client"`
	Comment      string              `json:"comment"`
	Status       string              `json:"status"`
	SentToOrders string              `json:"sentToOrders"`
	CreatedBy    UserResponse        `json:"createdBy"`
	CreatedAt    string              `json:"createdAt"`
}

type OrderItemResponse struct {
	ProductID    int     `json:"productId"`
	ProductName  string  `json:"productName"`
	ProductPrice float64 `json:"productPrice"`
	ProductCount int     `json:"productCount"`
}

type ClientResponse struct {
	ID        int     `json:"id"`
	Username  string  `json:"username"`
	Number    string  `json:"number"`
	Location  string  `json:"location"`
	Longitude float64 `json:"longitude"`
	Latitude  float64 `json:"latitude"`
}

type UserResponse struct {
	ID          int    `json:"id"`
	PhoneNumber string `json:"phoneNumber"`
	Role        string `json:"role"`
}

type SMSMessage struct {
	Phone string `json:"phone"`
	Code  string `json:"code"`
}

type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// ========================= DATABASE =========================

var DB *sql.DB

func InitDB() error {
	dbPath := os.Getenv("DATABASE_PATH")
	if dbPath == "" {
		dbPath = "./order_system.db"
	}

	var err error
	DB, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		return err
	}

	sqlStmt := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		phone_number TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		role TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS clients (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL,
		number TEXT NOT NULL,
		location TEXT,
		longitude REAL,
		latitude REAL,
		created_by INTEGER,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (created_by) REFERENCES users(id)
	);

	CREATE TABLE IF NOT EXISTS products (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		price REAL,
		category_name TEXT NOT NULL,
		image_url TEXT,
		ingredients TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS orders (
		id TEXT PRIMARY KEY,
		order_price REAL NOT NULL,
		client_id INTEGER NOT NULL,
		comment TEXT,
		status TEXT DEFAULT 'pending',
		sent_to_orders DATETIME,
		created_by INTEGER NOT NULL,
		sms_sent INTEGER DEFAULT 0,
		sms_sent_at DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (client_id) REFERENCES clients(id),
		FOREIGN KEY (created_by) REFERENCES users(id)
	);

	CREATE TABLE IF NOT EXISTS order_items (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		order_id TEXT NOT NULL,
		product_id INTEGER NOT NULL,
		product_name TEXT NOT NULL,
		product_price REAL NOT NULL,
		product_count INTEGER NOT NULL,
		FOREIGN KEY (order_id) REFERENCES orders(id),
		FOREIGN KEY (product_id) REFERENCES products(id)
	);
	`

	_, err = DB.Exec(sqlStmt)
	return err
}

func CreateDefaultAdmin() error {
	var count int
	err := DB.QueryRow("SELECT COUNT(*) FROM users WHERE phone_number = ?", "+998901234567").Scan(&count)
	if err != nil {
		return err
	}

	if count > 0 {
		return nil
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	_, err = DB.Exec(
		"INSERT INTO users (phone_number, password, role) VALUES (?, ?, ?)",
		"+998901234567",
		string(hashedPassword),
		"admin",
	)

	return err
}

// ========================= AUTH =========================

var jwtSecret []byte

func initJWT() {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		secret = "your_secret_key_here"
	}
	jwtSecret = []byte(secret)
}

type Claims struct {
	UserID int    `json:"userId"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

func GenerateToken(userID int, role string) (string, error) {
	claims := Claims{
		UserID: userID,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, APIResponse{
				Success: false,
				Error:   "Token kiritilmagan",
			})
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := ValidateToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, APIResponse{
				Success: false,
				Error:   "Token noto'g'ri yoki muddati o'tgan",
			})
			c.Abort()
			return
		}

		c.Set("userID", claims.UserID)
		c.Set("role", claims.Role)
		c.Next()
	}
}

func AdminOnly() gin.HandlerFunc {
	return func(c *gin.Context) {
		role, exists := c.Get("role")
		if !exists || role != "admin" {
			c.JSON(http.StatusForbidden, APIResponse{
				Success: false,
				Error:   "Bu amalni faqat admin bajara oladi",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

func Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   "Noto'g'ri ma'lumot",
		})
		return
	}

	var user User
	err := DB.QueryRow(
		"SELECT id, phone_number, password, role, created_at FROM users WHERE phone_number = ?",
		req.PhoneNumber,
	).Scan(&user.ID, &user.PhoneNumber, &user.Password, &user.Role, &user.CreatedAt)

	if err != nil {
		c.JSON(http.StatusUnauthorized, LoginResponse{
			Success: false,
			Error:   "Telefon raqam yoki parol noto'g'ri",
		})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, LoginResponse{
			Success: false,
			Error:   "Telefon raqam yoki parol noto'g'ri",
		})
		return
	}

	token, err := GenerateToken(user.ID, user.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, LoginResponse{
			Success: false,
			Error:   "Token yaratishda xatolik",
		})
		return
	}

	user.Password = ""
	c.JSON(http.StatusOK, LoginResponse{
		Success: true,
		Token:   token,
		User:    &user,
	})
}

func CreateUser(c *gin.Context) {
	var req CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   "Noto'g'ri ma'lumot",
		})
		return
	}

	if req.Role != "admin" && req.Role != "agent" {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   "Role faqat 'admin' yoki 'agent' bo'lishi mumkin",
		})
		return
	}

	var count int
	err := DB.QueryRow("SELECT COUNT(*) FROM users WHERE phone_number = ?", req.PhoneNumber).Scan(&count)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "Ma'lumotlar bazasi xatoligi",
		})
		return
	}

	if count > 0 {
		c.JSON(http.StatusConflict, APIResponse{
			Success: false,
			Error:   "Bu telefon raqam allaqachon mavjud",
		})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "Parolni shifrlashda xatolik",
		})
		return
	}

	result, err := DB.Exec(
		"INSERT INTO users (phone_number, password, role) VALUES (?, ?, ?)",
		req.PhoneNumber,
		string(hashedPassword),
		req.Role,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "Foydalanuvchi yaratishda xatolik",
		})
		return
	}

	userID, _ := result.LastInsertId()

	c.JSON(http.StatusCreated, APIResponse{
		Success: true,
		Message: req.Role + " muvaffaqiyatli yaratildi",
		Data: map[string]interface{}{
			"id":          userID,
			"phoneNumber": req.PhoneNumber,
			"role":        req.Role,
		},
	})
}

// ========================= PRODUCTS =========================

func GetProducts(c *gin.Context) {
	rows, err := DB.Query(`
		SELECT id, name, price, category_name, image_url, ingredients, created_at 
		FROM products 
		ORDER BY created_at DESC
	`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "Ma'lumotlarni olishda xatolik",
		})
		return
	}
	defer rows.Close()

	var products []Product
	for rows.Next() {
		var p Product
		err := rows.Scan(&p.ID, &p.Name, &p.Price, &p.CategoryName, &p.ImageUrl, &p.Ingredients, &p.CreatedAt)
		if err != nil {
			continue
		}
		products = append(products, p)
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Data:    products,
	})
}

func CreateProduct(c *gin.Context) {
	var req ProductRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   "Noto'g'ri ma'lumot",
		})
		return
	}

	result, err := DB.Exec(`
		INSERT INTO products (name, price, category_name, image_url, ingredients) 
		VALUES (?, ?, ?, ?, ?)`,
		req.Name, req.Price, req.CategoryName, req.ImageUrl, req.Ingredients,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "Mahsulot qo'shishda xatolik",
		})
		return
	}

	productID, _ := result.LastInsertId()

	c.JSON(http.StatusCreated, APIResponse{
		Success: true,
		Message: "Mahsulot muvaffaqiyatli qo'shildi",
		Data: map[string]interface{}{
			"id":           productID,
			"name":         req.Name,
			"price":        req.Price,
			"categoryName": req.CategoryName,
			"imageUrl":     req.ImageUrl,
			"ingredients":  req.Ingredients,
		},
	})
}

func UpdateProduct(c *gin.Context) {
	productID := c.Param("id")

	var req ProductRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   "Noto'g'ri ma'lumot",
		})
		return
	}

	result, err := DB.Exec(`
		UPDATE products 
		SET name = ?, price = ?, category_name = ?, image_url = ?, ingredients = ? 
		WHERE id = ?`,
		req.Name, req.Price, req.CategoryName, req.ImageUrl, req.Ingredients, productID,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "Mahsulotni yangilashda xatolik",
		})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, APIResponse{
			Success: false,
			Error:   "Mahsulot topilmadi",
		})
		return
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Mahsulot yangilandi",
	})
}

func DeleteProduct(c *gin.Context) {
	productID := c.Param("id")

	result, err := DB.Exec("DELETE FROM products WHERE id = ?", productID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "Mahsulotni o'chirishda xatolik",
		})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, APIResponse{
			Success: false,
			Error:   "Mahsulot topilmadi",
		})
		return
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Mahsulot o'chirildi",
	})
}

// ========================= CLIENTS =========================

func GetClients(c *gin.Context) {
	rows, err := DB.Query(`
		SELECT id, username, number, location, longitude, latitude, created_by, created_at 
		FROM clients 
		ORDER BY created_at DESC
	`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "Ma'lumotlarni olishda xatolik",
		})
		return
	}
	defer rows.Close()

	var clients []Client
	for rows.Next() {
		var cl Client
		err := rows.Scan(&cl.ID, &cl.Username, &cl.Number, &cl.Location, &cl.Longitude, &cl.Latitude, &cl.CreatedBy, &cl.CreatedAt)
		if err != nil {
			continue
		}
		clients = append(clients, cl)
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Data:    clients,
	})
}

func CreateClient(c *gin.Context) {
	var req ClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   "Noto'g'ri ma'lumot",
		})
		return
	}

	userID, _ := c.Get("userID")

	result, err := DB.Exec(`
		INSERT INTO clients (username, number, location, longitude, latitude, created_by) 
		VALUES (?, ?, ?, ?, ?, ?)`,
		req.Username, req.Number, req.Location, req.Longitude, req.Latitude, userID,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "Client qo'shishda xatolik",
		})
		return
	}

	clientID, _ := result.LastInsertId()

	c.JSON(http.StatusCreated, APIResponse{
		Success: true,
		Message: "Client muvaffaqiyatli qo'shildi",
		Data: map[string]interface{}{
			"id":        clientID,
			"username":  req.Username,
			"number":    req.Number,
			"location":  req.Location,
			"longitude": req.Longitude,
			"latitude":  req.Latitude,
		},
	})
}

func UpdateClient(c *gin.Context) {
	clientID := c.Param("id")

	var req ClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   "Noto'g'ri ma'lumot",
		})
		return
	}

	result, err := DB.Exec(`
		UPDATE clients 
		SET username = ?, number = ?, location = ?, longitude = ?, latitude = ? 
		WHERE id = ?`,
		req.Username, req.Number, req.Location, req.Longitude, req.Latitude, clientID,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "Client yangilashda xatolik",
		})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, APIResponse{
			Success: false,
			Error:   "Client topilmadi",
		})
		return
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Client yangilandi",
	})
}

func DeleteClient(c *gin.Context) {
	clientID := c.Param("id")

	result, err := DB.Exec("DELETE FROM clients WHERE id = ?", clientID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "Client o'chirishda xatolik",
		})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, APIResponse{
			Success: false,
			Error:   "Client topilmadi",
		})
		return
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Client o'chirildi",
	})
}

// ========================= ORDERS =========================

func GenerateOrderID() (string, error) {
	now := time.Now()
	dateStr := now.Format("06-01-02")

	var count int
	err := DB.QueryRow(
		"SELECT COUNT(*) FROM orders WHERE id LIKE ?",
		dateStr+"-%",
	).Scan(&count)

	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s-%d", dateStr, count+1), nil
}

func CreateOrder(c *gin.Context) {
	var req CreateOrderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   "Noto'g'ri ma'lumot",
		})
		return
	}

	userID, _ := c.Get("userID")
	var clientID int

	if req.NewClient != nil {
		result, err := DB.Exec(`
			INSERT INTO clients (username, number, location, longitude, latitude, created_by) 
			VALUES (?, ?, ?, ?, ?, ?)`,
			req.NewClient.Username, req.NewClient.Number, req.NewClient.Location,
			req.NewClient.Longitude, req.NewClient.Latitude, userID,
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, APIResponse{
				Success: false,
				Error:   "Mijoz yaratishda xatolik",
			})
			return
		}
		id, _ := result.LastInsertId()
		clientID = int(id)
	} else if req.ClientID != nil {
		clientID = *req.ClientID
	} else {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   "ClientId yoki newClient kiritilishi kerak",
		})
		return
	}

	var client Client
	err := DB.QueryRow(`
		SELECT id, username, number, location, longitude, latitude 
		FROM clients WHERE id = ?`, clientID,
	).Scan(&client.ID, &client.Username, &client.Number, &client.Location, &client.Longitude, &client.Latitude)

	if err != nil {
		c.JSON(http.StatusNotFound, APIResponse{
			Success: false,
			Error:   "Mijoz topilmadi",
		})
		return
	}

	var orderItems []OrderItemResponse
	var totalPrice float64

	for _, p := range req.Products {
		var product Product
		err := DB.QueryRow(
			"SELECT id, name, price FROM products WHERE id = ?",
			p.ProductID,
		).Scan(&product.ID, &product.Name, &product.Price)

		if err != nil {
			c.JSON(http.StatusNotFound, APIResponse{
				Success: false,
				Error:   fmt.Sprintf("Mahsulot ID %d topilmadi", p.ProductID),
			})
			return
		}

		itemTotal := product.Price * float64(p.ProductCount)
		totalPrice += itemTotal

		orderItems = append(orderItems, OrderItemResponse{
			ProductID:    product.ID,
			ProductName:  product.Name,
			ProductPrice: product.Price,
			ProductCount: p.ProductCount,
		})
	}

	orderID, err := GenerateOrderID()
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "Buyurtma ID yaratishda xatolik",
		})
		return
	}

	sentToOrders, err := time.Parse(time.RFC3339, req.SentToOrders)
	if err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   "Noto'g'ri vaqt formati (ISO 8601 kerak)",
		})
		return
	}

	_, err = DB.Exec(`
		INSERT INTO orders (id, order_price, client_id, comment, status, sent_to_orders, created_by) 
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		orderID, totalPrice, clientID, req.Comment, "pending", sentToOrders, userID,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "Buyurtma yaratishda xatolik",
		})
		return
	}

	for _, item := range orderItems {
		_, err = DB.Exec(`
			INSERT INTO order_items (order_id, product_id, product_name, product_price, product_count) 
			VALUES (?, ?, ?, ?, ?)`,
			orderID, item.ProductID, item.ProductName, item.ProductPrice, item.ProductCount,
		)
		if err != nil {
			continue
		}
	}

	var user User
	DB.QueryRow("SELECT id, phone_number, role FROM users WHERE id = ?", userID).
		Scan(&user.ID, &user.PhoneNumber, &user.Role)

	orderResponse := OrderResponse{
		ID:         orderID,
		Products:   orderItems,
		OrderPrice: totalPrice,
		Client: ClientResponse{
			ID:        client.ID,
			Username:  client.Username,
			Number:    client.Number,
			Location:  client.Location,
			Longitude: client.Longitude,
			Latitude:  client.Latitude,
		},
		Comment:      req.Comment,
		Status:       "pending",
		SentToOrders: sentToOrders.Format(time.RFC3339),
		CreatedBy: UserResponse{
			ID:          user.ID,
			PhoneNumber: user.PhoneNumber,
			Role:        user.Role,
		},
		CreatedAt: time.Now().Format(time.RFC3339),
	}

	go SendToPrinter(orderResponse)

	c.JSON(http.StatusCreated, APIResponse{
		Success: true,
		Message: "Buyurtma muvaffaqiyatli yaratildi va printerga yuborildi",
		Data:    orderResponse,
	})
}

func SendToPrinter(order OrderResponse) {
	printerURL := os.Getenv("PRINTER_URL")
	if printerURL == "" {
		printerURL = "https://marxabo1.javohir-jasmina.uz/print"
	}

	jsonData, err := json.Marshal(order)
	if err != nil {
		return
	}

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("POST", printerURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return
	}

	req.Header.Set("Content-Type", "application/json")
	client.Do(req)
}

func GetOrders(c *gin.Context) {
	userID, _ := c.Get("userID")
	role, _ := c.Get("role")

	var rows *sql.Rows
	var err error

	if role == "admin" {
		rows, err = DB.Query(`
			SELECT id, order_price, client_id, comment, status, sent_to_orders, created_by, created_at 
			FROM orders 
			ORDER BY created_at DESC
		`)
	} else {
		rows, err = DB.Query(`
			SELECT id, order_price, client_id, comment, status, sent_to_orders, created_by, created_at 
			FROM orders 
			WHERE created_by = ?
			ORDER BY created_at DESC`, userID,
		)
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "Ma'lumotlarni olishda xatolik",
		})
		return
	}
	defer rows.Close()

	var orders []OrderResponse
	for rows.Next() {
		var order Order
		err := rows.Scan(&order.ID, &order.OrderPrice, &order.ClientID, &order.Comment,
			&order.Status, &order.SentToOrders, &order.CreatedBy, &order.CreatedAt)
		if err != nil {
			continue
		}

		orderResp := buildOrderResponse(order)
		orders = append(orders, orderResp)
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Data:    orders,
	})
}

func GetOrderByID(c *gin.Context) {
	orderID := c.Param("id")
	userID, _ := c.Get("userID")
	role, _ := c.Get("role")

	var order Order
	err := DB.QueryRow(`
		SELECT id, order_price, client_id, comment, status, sent_to_orders, created_by, created_at 
		FROM orders 
		WHERE id = ?`, orderID,
	).Scan(&order.ID, &order.OrderPrice, &order.ClientID, &order.Comment,
		&order.Status, &order.SentToOrders, &order.CreatedBy, &order.CreatedAt)

	if err != nil {
		c.JSON(http.StatusNotFound, APIResponse{
			Success: false,
			Error:   "Buyurtma topilmadi",
		})
		return
	}

	if role != "admin" && order.CreatedBy != userID.(int) {
		c.JSON(http.StatusForbidden, APIResponse{
			Success: false,
			Error:   "Bu buyurtmani ko'rish huquqingiz yo'q",
		})
		return
	}

	orderResp := buildOrderResponse(order)

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Data:    orderResp,
	})
}

func UpdateOrderStatus(c *gin.Context) {
	orderID := c.Param("id")

	var req UpdateStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   "Noto'g'ri ma'lumot",
		})
		return
	}

	validStatuses := []string{"pending", "processing", "delivering", "delivered", "cancelled"}
	isValid := false
	for _, status := range validStatuses {
		if req.Status == status {
			isValid = true
			break
		}
	}

	if !isValid {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   "Noto'g'ri status qiymati",
		})
		return
	}

	result, err := DB.Exec("UPDATE orders SET status = ? WHERE id = ?", req.Status, orderID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "Status yangilashda xatolik",
		})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, APIResponse{
			Success: false,
			Error:   "Buyurtma topilmadi",
		})
		return
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Status muvaffaqiyatli o'zgartirildi",
	})
}

func buildOrderResponse(order Order) OrderResponse {
	itemRows, _ := DB.Query(`
		SELECT product_id, product_name, product_price, product_count 
		FROM order_items 
		WHERE order_id = ?`, order.ID,
	)
	defer itemRows.Close()

	var items []OrderItemResponse
	for itemRows.Next() {
		var item OrderItemResponse
		itemRows.Scan(&item.ProductID, &item.ProductName, &item.ProductPrice, &item.ProductCount)
		items = append(items, item)
	}

	var client Client
	DB.QueryRow(`
		SELECT id, username, number, location, longitude, latitude 
		FROM clients WHERE id = ?`, order.ClientID,
	).Scan(&client.ID, &client.Username, &client.Number, &client.Location, &client.Longitude, &client.Latitude)

	var creator User
	DB.QueryRow("SELECT id, phone_number, role FROM users WHERE id = ?", order.CreatedBy).
		Scan(&creator.ID, &creator.PhoneNumber, &creator.Role)

	return OrderResponse{
		ID:         order.ID,
		Products:   items,
		OrderPrice: order.OrderPrice,
		Client: ClientResponse{
			ID:        client.ID,
			Username:  client.Username,
			Number:    client.Number,
			Location:  client.Location,
			Longitude: client.Longitude,
			Latitude:  client.Latitude,
		},
		Comment:      order.Comment,
		Status:       order.Status,
		SentToOrders: order.SentToOrders.Format("2006-01-02T15:04:05Z07:00"),
		CreatedBy: UserResponse{
			ID:          creator.ID,
			PhoneNumber: creator.PhoneNumber,
			Role:        creator.Role,
		},
		CreatedAt: order.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
}

// ========================= SMS =========================

func GetPendingSMS(c *gin.Context) {
	rows, err := DB.Query(`
		SELECT o.id, o.client_id, o.sent_to_orders, o.order_price
		FROM orders o
		WHERE o.sms_sent = 0
		ORDER BY o.created_at ASC
	`)

	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "Ma'lumotlarni olishda xatolik",
		})
		return
	}
	defer rows.Close()

	var messages []SMSMessage

	for rows.Next() {
		var orderID string
		var clientID int
		var sentToOrders time.Time
		var orderPrice float64

		err := rows.Scan(&orderID, &clientID, &sentToOrders, &orderPrice)
		if err != nil {
			continue
		}

		var clientName, clientNumber string
		err = DB.QueryRow("SELECT username, number FROM clients WHERE id = ?", clientID).
			Scan(&clientName, &clientNumber)
		if err != nil {
			continue
		}

		itemRows, err := DB.Query(`
			SELECT product_name, product_count, product_price 
			FROM order_items 
			WHERE order_id = ?`, orderID,
		)
		if err != nil {
			continue
		}

		var productsText string
		for itemRows.Next() {
			var productName string
			var productCount int
			var productPrice float64

			itemRows.Scan(&productName, &productCount, &productPrice)
			itemTotal := float64(productCount) * productPrice
			productsText += fmt.Sprintf("%s %d*%.0f=%.0f\n", productName, productCount, productPrice, itemTotal)
		}
		itemRows.Close()

		deliveryTime := sentToOrders.Format("2-January soat 15:04")

		smsText := fmt.Sprintf(
			"Assalomu aleykum %s!\n\nSizning buyurtmangiz:\n%s\nJami: %.0f so'm\n\nYetkazib berish: %s",
			clientName,
			productsText,
			orderPrice,
			deliveryTime,
		)

		messages = append(messages, SMSMessage{
			Phone: clientNumber,
			Code:  smsText,
		})
	}

	c.JSON(http.StatusOK, messages)
}

func MarkSMSSent(c *gin.Context) {
	phone := c.Param("phone")

	if phone == "" {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   "Telefon raqam kiritilmagan",
		})
		return
	}

	var clientID int
	err := DB.QueryRow("SELECT id FROM clients WHERE number = ?", phone).Scan(&clientID)
	if err != nil {
		c.JSON(http.StatusNotFound, APIResponse{
			Success: false,
			Error:   "Mijoz topilmadi",
		})
		return
	}

	result, err := DB.Exec(`
		UPDATE orders 
		SET sms_sent = 1, sms_sent_at = CURRENT_TIMESTAMP 
		WHERE client_id = ? AND sms_sent = 0`,
		clientID,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "SMS holatini yangilashda xatolik",
		})
		return
	}

	rowsAffected, _ := result.RowsAffected()

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: fmt.Sprintf("SMS yuborilgani tasdiqlandi (%d ta buyurtma)", rowsAffected),
	})
}

// ========================= ROUTES =========================

func SetupRoutes(router *gin.Engine) {
	api := router.Group("/api")

	auth := api.Group("/auth")
	{
		auth.POST("/login", Login)
		auth.POST("/create-admin", AuthMiddleware(), AdminOnly(), CreateUser)
	}

	products := api.Group("/products")
	products.Use(AuthMiddleware())
	{
		products.GET("", GetProducts)
		products.POST("", AdminOnly(), CreateProduct)
		products.PUT("/:id", AdminOnly(), UpdateProduct)
		products.DELETE("/:id", AdminOnly(), DeleteProduct)
	}

	clients := api.Group("/clients")
	clients.Use(AuthMiddleware())
	{
		clients.GET("", GetClients)
		clients.POST("", CreateClient)
		clients.PUT("/:id", UpdateClient)
		clients.DELETE("/:id", DeleteClient)
	}

	orders := api.Group("/orders")
	orders.Use(AuthMiddleware())
	{
		orders.GET("", GetOrders)
		orders.POST("", CreateOrder)
		orders.GET("/:id", GetOrderByID)
		orders.PATCH("/:id/status", AdminOnly(), UpdateOrderStatus)
	}

	sms := api.Group("/sms")
	sms.Use()
	{
		sms.GET("/pending", GetPendingSMS)
		sms.POST("/sent/:phone", MarkSMSSent)
	}

	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":  "ok",
			"message": "Order Management System API",
		})
	})
}

// ========================= MAIN =========================

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment variables")
	}

	initJWT()

	if err := InitDB(); err != nil {
		log.Fatal("Failed to initialize database:", err)
	}

	if err := CreateDefaultAdmin(); err != nil {
		log.Println("Warning: Could not create default admin:", err)
	}

	router := gin.Default()

	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	SetupRoutes(router)

	port := os.Getenv("PORT")
	if port == "" {
		port = "1313"
	}

	log.Printf("🚀 Server is running on port %s", port)
	log.Printf("📚 API Documentation: http://localhost:%s/health", port)
	log.Printf("👤 Default Admin: +998901234567 / admin123")

	if err := router.Run(":" + port); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
