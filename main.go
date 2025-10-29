package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
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
	Username    string    `json:"username"`
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
	ImageUrl  string    `json:"imageUrl"`
	UserID    int       `json:"userId"`
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
	SupplierID   *int       `json:"supplierId,omitempty"`
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
	Username    string `json:"username" binding:"required"`
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
	ImageUrl  string  `json:"imageUrl"`
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
	SentToOrders string                `json:"sentToOrders" binding:"required"` // MAJBURIY!
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
	Supplier     *UserResponse       `json:"supplier,omitempty"`
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
	ImageUrl  string  `json:"imageUrl"`
}

type UserResponse struct {
	ID          int    `json:"id"`
	Username    string `json:"username"`
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
		username TEXT NOT NULL,
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
		image_url TEXT,
		user_id INTEGER,
		created_by INTEGER,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id),
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
		sent_to_orders DATETIME NOT NULL,
		created_by INTEGER NOT NULL,
		supplier_id INTEGER,
		sms_sent INTEGER DEFAULT 0,
		sms_sent_at DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (client_id) REFERENCES clients(id),
		FOREIGN KEY (created_by) REFERENCES users(id),
		FOREIGN KEY (supplier_id) REFERENCES users(id)
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
		"INSERT INTO users (username, phone_number, password, role) VALUES (?, ?, ?, ?)",
		"Admin",
		"+998901234567",
		string(hashedPassword),
		"admin",
	)

	return err
}

// ========================= TELEGRAM =========================

const (
	TelegramBotToken = "6716187239:AAHoxfoLCRnu_o-jSqE3j_7QesnDBtZjoZE"
	TelegramChatID   = "-1003173379469"
)

type TelegramMessage struct {
	ChatID    string `json:"chat_id"`
	Text      string `json:"text"`
	ParseMode string `json:"parse_mode"`
}

func SendTelegramNotification(orderID string, client Client, products []OrderItemResponse, orderPrice float64, sentToOrders time.Time, comment string) error {
	// Mahsulotlar ro'yxatini yaratish
	var productsList string
	for _, p := range products {
		itemTotal := p.ProductPrice * float64(p.ProductCount)
		productsList += fmt.Sprintf("• %s - %d x %.0f so'm = %.0f so'm\n",
			p.ProductName, p.ProductCount, p.ProductPrice, itemTotal)
	}

	// Yetkazish vaqti
	deliveryTime := sentToOrders.Format("2-January soat 15:04")

	// Telegram xabari
	message := fmt.Sprintf(
		"🆕 *YANGI BUYURTMA!*\n\n"+
			"📋 Buyurtma ID: `%s`\n"+
			"👤 Mijoz: %s\n"+
			"📞 Telefon: %s\n"+
			"📍 Manzil: %s\n\n"+
			"🛒 *Mahsulotlar:*\n%s\n"+
			"💰 *Jami summa:* %.0f so'm\n"+
			"🕐 *Yetkazish vaqti:* %s\n"+
			"💬 *Izoh:* %s",
		orderID,
		client.Username,
		client.Number,
		client.Location,
		productsList,
		orderPrice,
		deliveryTime,
		comment,
	)

	if comment == "" {
		message = fmt.Sprintf(
			"🆕 *YANGI BUYURTMA!*\n\n"+
				"📋 Buyurtma ID: `%s`\n"+
				"👤 Mijoz: %s\n"+
				"📞 Telefon: %s\n"+
				"📍 Manzil: %s\n\n"+
				"🛒 *Mahsulotlar:*\n%s\n"+
				"💰 *Jami summa:* %.0f so'm\n"+
				"🕐 *Yetkazish vaqti:* %s",
			orderID,
			client.Username,
			client.Number,
			client.Location,
			productsList,
			orderPrice,
			deliveryTime,
		)
	}

	telegramMsg := TelegramMessage{
		ChatID:    TelegramChatID,
		Text:      message,
		ParseMode: "Markdown",
	}

	jsonData, err := json.Marshal(telegramMsg)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", TelegramBotToken)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram API error: %s", string(body))
	}

	return nil
}

// ========================= FILE UPLOAD =========================

func UploadImage(c *gin.Context) {
	file, err := c.FormFile("image")
	if err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   "Rasm yuklanmadi",
		})
		return
	}

	// Faqat rasm formatlarini qabul qilish
	ext := strings.ToLower(filepath.Ext(file.Filename))
	allowedExts := map[string]bool{
		".jpg":  true,
		".jpeg": true,
		".png":  true,
		".gif":  true,
		".webp": true,
	}

	if !allowedExts[ext] {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   "Faqat rasm fayllari qabul qilinadi (jpg, jpeg, png, gif, webp)",
		})
		return
	}

	// Rasmlar uchun papka yaratish
	uploadDir := "./uploads"
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "Papka yaratishda xatolik",
		})
		return
	}

	// Unique filename yaratish
	filename := fmt.Sprintf("%d%s", time.Now().UnixNano(), ext)
	filepath := filepath.Join(uploadDir, filename)

	// Faylni saqlash
	if err := c.SaveUploadedFile(file, filepath); err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "Faylni saqlashda xatolik",
		})
		return
	}

	// URL qaytarish (faqat path, base URL yo'q)
	imageURL := "/uploads/" + filename

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Rasm muvaffaqiyatli yuklandi",
		Data: map[string]interface{}{
			"url": imageURL,
		},
	})
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
				Error:   "Authorization header yo'q",
			})
			c.Abort()
			return
		}

		bearerToken := strings.Split(authHeader, " ")
		if len(bearerToken) != 2 {
			c.JSON(http.StatusUnauthorized, APIResponse{
				Success: false,
				Error:   "Token formati noto'g'ri",
			})
			c.Abort()
			return
		}

		claims, err := ValidateToken(bearerToken[1])
		if err != nil {
			c.JSON(http.StatusUnauthorized, APIResponse{
				Success: false,
				Error:   "Yaroqsiz token",
			})
			c.Abort()
			return
		}

		c.Set("userId", claims.UserID)
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
				Error:   "Sizda bu amalni bajarish uchun ruxsat yo'q",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

// ========================= HANDLERS =========================

func Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, LoginResponse{
			Success: false,
			Error:   "Ma'lumotlar to'liq emas",
		})
		return
	}

	var user User
	// Telefon raqam yoki username bilan login qilish
	err := DB.QueryRow(
		"SELECT id, username, phone_number, password, role FROM users WHERE phone_number = ? OR username = ?",
		req.PhoneNumber, req.PhoneNumber,
	).Scan(&user.ID, &user.Username, &user.PhoneNumber, &user.Password, &user.Role)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusUnauthorized, LoginResponse{
			Success: false,
			Error:   "Login yoki parol noto'g'ri",
		})
		return
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, LoginResponse{
			Success: false,
			Error:   "Serverda xatolik",
		})
		return
	}

	// Parolni tekshirish - client uchun telefon raqam parol bo'ladi
	// Agar user rolida "client" bo'lsa, telefon raqamni tekshirish
	if user.Role == "client" {
		// Client uchun parol = telefon raqam (hashed)
		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
			c.JSON(http.StatusUnauthorized, LoginResponse{
				Success: false,
				Error:   "Login yoki parol noto'g'ri",
			})
			return
		}
	} else {
		// Boshqa rollar uchun oddiy parol tekshirish
		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
			c.JSON(http.StatusUnauthorized, LoginResponse{
				Success: false,
				Error:   "Login yoki parol noto'g'ri",
			})
			return
		}
	}

	token, err := GenerateToken(user.ID, user.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, LoginResponse{
			Success: false,
			Error:   "Token yaratishda xatolik",
		})
		return
	}

	c.JSON(http.StatusOK, LoginResponse{
		Success: true,
		Token:   token,
		User: &User{
			ID:          user.ID,
			Username:    user.Username,
			PhoneNumber: user.PhoneNumber,
			Role:        user.Role,
		},
	})
}

func CreateUser(c *gin.Context) {
	var req CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   "Ma'lumotlar to'liq emas",
		})
		return
	}

	// Rolni tekshirish
	validRoles := []string{"admin", "operator", "user", "supplier"}
	isValidRole := false
	for _, role := range validRoles {
		if req.Role == role {
			isValidRole = true
			break
		}
	}

	if !isValidRole {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   "Rol faqat 'admin', 'operator', 'user' yoki 'supplier' bo'lishi mumkin",
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
		"INSERT INTO users (username, phone_number, password, role) VALUES (?, ?, ?, ?)",
		req.Username,
		req.PhoneNumber,
		string(hashedPassword),
		req.Role,
	)

	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			c.JSON(http.StatusConflict, APIResponse{
				Success: false,
				Error:   "Bu telefon raqam allaqachon ro'yxatdan o'tgan",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "Foydalanuvchi yaratishda xatolik",
		})
		return
	}

	userID, _ := result.LastInsertId()

	c.JSON(http.StatusCreated, APIResponse{
		Success: true,
		Message: "Foydalanuvchi muvaffaqiyatli yaratildi",
		Data: map[string]interface{}{
			"id":          userID,
			"username":    req.Username,
			"phoneNumber": req.PhoneNumber,
			"role":        req.Role,
		},
	})
}

func Register(c *gin.Context) {
	var req CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   "Ma'lumotlar to'liq emas",
		})
		return
	}

	// Register orqali faqat user yaratiladi
	req.Role = "user"

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "Parolni shifrlashda xatolik",
		})
		return
	}

	result, err := DB.Exec(
		"INSERT INTO users (username, phone_number, password, role) VALUES (?, ?, ?, ?)",
		req.Username,
		req.PhoneNumber,
		string(hashedPassword),
		"user",
	)

	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			c.JSON(http.StatusConflict, APIResponse{
				Success: false,
				Error:   "Bu telefon raqam allaqachon ro'yxatdan o'tgan",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "Ro'yxatdan o'tishda xatolik",
		})
		return
	}

	userID, _ := result.LastInsertId()

	// Avtomatik login qilish
	token, err := GenerateToken(int(userID), "user")
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "Token yaratishda xatolik",
		})
		return
	}

	c.JSON(http.StatusCreated, APIResponse{
		Success: true,
		Message: "Ro'yxatdan muvaffaqiyatli o'tdingiz",
		Data: map[string]interface{}{
			"token": token,
			"user": map[string]interface{}{
				"id":          userID,
				"username":    req.Username,
				"phoneNumber": req.PhoneNumber,
				"role":        "user",
			},
		},
	})
}

// ========================= PRODUCTS =========================

func GetProducts(c *gin.Context) {
	rows, err := DB.Query("SELECT id, name, price, category_name, image_url, ingredients, created_at FROM products")
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "Mahsulotlarni olishda xatolik",
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
			Error:   "Ma'lumotlar to'liq emas",
		})
		return
	}

	result, err := DB.Exec(
		"INSERT INTO products (name, price, category_name, image_url, ingredients) VALUES (?, ?, ?, ?, ?)",
		req.Name, req.Price, req.CategoryName, req.ImageUrl, req.Ingredients,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "Mahsulot yaratishda xatolik",
		})
		return
	}

	productID, _ := result.LastInsertId()

	c.JSON(http.StatusCreated, APIResponse{
		Success: true,
		Message: "Mahsulot muvaffaqiyatli yaratildi",
		Data: map[string]interface{}{
			"id": productID,
		},
	})
}

func UpdateProduct(c *gin.Context) {
	productID := c.Param("id")

	var req ProductRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   "Ma'lumotlar to'liq emas",
		})
		return
	}

	result, err := DB.Exec(
		"UPDATE products SET name = ?, price = ?, category_name = ?, image_url = ?, ingredients = ? WHERE id = ?",
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
		Message: "Mahsulot muvaffaqiyatli yangilandi",
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
		Message: "Mahsulot muvaffaqiyatli o'chirildi",
	})
}

// ========================= CLIENTS =========================

func GetClients(c *gin.Context) {
	userID, _ := c.Get("userId")

	rows, err := DB.Query(
		"SELECT id, username, number, location, longitude, latitude, image_url, user_id, created_at FROM clients WHERE created_by = ?",
		userID,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "Mijozlarni olishda xatolik",
		})
		return
	}
	defer rows.Close()

	var clients []Client
	for rows.Next() {
		var cl Client
		var userIDNull sql.NullInt64
		err := rows.Scan(&cl.ID, &cl.Username, &cl.Number, &cl.Location, &cl.Longitude, &cl.Latitude, &cl.ImageUrl, &userIDNull, &cl.CreatedAt)
		if err != nil {
			continue
		}
		if userIDNull.Valid {
			cl.UserID = int(userIDNull.Int64)
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
			Error:   "Ma'lumotlar to'liq emas",
		})
		return
	}

	userID, _ := c.Get("userId")

	// 1. Avval user yaratish (client roli bilan)
	// Parol = telefon raqami (hashed)
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Number), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "Parolni shifrlashda xatolik",
		})
		return
	}

	// User yaratish
	userResult, err := DB.Exec(
		"INSERT INTO users (username, phone_number, password, role) VALUES (?, ?, ?, ?)",
		req.Username,
		req.Number,
		string(hashedPassword),
		"client",
	)

	if err != nil {
		// Agar telefon raqam allaqachon mavjud bo'lsa
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			c.JSON(http.StatusConflict, APIResponse{
				Success: false,
				Error:   "Bu telefon raqam allaqachon ro'yxatdan o'tgan",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "User yaratishda xatolik",
		})
		return
	}

	newUserID, _ := userResult.LastInsertId()

	// 2. Client yaratish
	result, err := DB.Exec(
		"INSERT INTO clients (username, number, location, longitude, latitude, image_url, user_id, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		req.Username, req.Number, req.Location, req.Longitude, req.Latitude, req.ImageUrl, newUserID, userID,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "Mijoz yaratishda xatolik",
		})
		return
	}

	clientID, _ := result.LastInsertId()

	c.JSON(http.StatusCreated, APIResponse{
		Success: true,
		Message: "Mijoz muvaffaqiyatli yaratildi (Login: username, Parol: telefon raqam)",
		Data: map[string]interface{}{
			"id":     clientID,
			"userId": newUserID,
		},
	})
}

func UpdateClient(c *gin.Context) {
	clientID := c.Param("id")

	var req ClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   "Ma'lumotlar to'liq emas",
		})
		return
	}

	// Client ma'lumotlarini olish
	var existingClient Client
	var userIDNull sql.NullInt64
	err := DB.QueryRow("SELECT user_id FROM clients WHERE id = ?", clientID).Scan(&userIDNull)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, APIResponse{
			Success: false,
			Error:   "Mijoz topilmadi",
		})
		return
	}

	// Client update qilish
	result, err := DB.Exec(
		"UPDATE clients SET username = ?, number = ?, location = ?, longitude = ?, latitude = ?, image_url = ? WHERE id = ?",
		req.Username, req.Number, req.Location, req.Longitude, req.Latitude, req.ImageUrl, clientID,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "Mijozni yangilashda xatolik",
		})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, APIResponse{
			Success: false,
			Error:   "Mijoz topilmadi",
		})
		return
	}

	// Agar user_id mavjud bo'lsa, user ham yangilansin
	if userIDNull.Valid {
		existingClient.UserID = int(userIDNull.Int64)

		// Parolni yangi telefon raqamdan hash qilish
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Number), bcrypt.DefaultCost)
		if err == nil {
			// User yangilash
			DB.Exec(
				"UPDATE users SET username = ?, phone_number = ?, password = ? WHERE id = ?",
				req.Username, req.Number, string(hashedPassword), existingClient.UserID,
			)
		}
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Mijoz muvaffaqiyatli yangilandi",
	})
}

func DeleteClient(c *gin.Context) {
	clientID := c.Param("id")

	// Avval client'ning user_id sini olish
	var userIDNull sql.NullInt64
	err := DB.QueryRow("SELECT user_id FROM clients WHERE id = ?", clientID).Scan(&userIDNull)

	// Client o'chirish
	result, err := DB.Exec("DELETE FROM clients WHERE id = ?", clientID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "Mijozni o'chirishda xatolik",
		})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, APIResponse{
			Success: false,
			Error:   "Mijoz topilmadi",
		})
		return
	}

	// Agar user mavjud bo'lsa, uni ham o'chirish
	if userIDNull.Valid {
		DB.Exec("DELETE FROM users WHERE id = ?", int(userIDNull.Int64))
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Mijoz muvaffaqiyatli o'chirildi",
	})
}

// ========================= ORDERS =========================

// YANGILANGAN: Yetkazib berish sanasiga ko'ra ID generatsiya qilish
func GenerateOrderID(deliveryDate time.Time) (string, error) {
	// Yetkazib berish kunidan yil, oy, kun olish
	year := deliveryDate.Format("06")  // 25
	month := deliveryDate.Format("01") // 01-12
	day := deliveryDate.Format("02")   // 01-31

	// Shu kunga qancha buyurtma bor ekanini tekshirish
	// Format: 25-11-01-%
	prefix := fmt.Sprintf("%s-%s-%s-", year, month, day)

	var count int
	err := DB.QueryRow(
		"SELECT COUNT(*) FROM orders WHERE id LIKE ?",
		prefix+"%",
	).Scan(&count)

	if err != nil {
		return "", err
	}

	// Keyingi counter raqami
	counter := count + 1
	orderID := fmt.Sprintf("%s-%s-%s-%02d", year, month, day, counter)

	return orderID, nil
}

func CreateOrder(c *gin.Context) {
	var req CreateOrderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   "Ma'lumotlar to'liq emas",
		})
		return
	}

	// YANGI: Yetkazib berish vaqti majburiy tekshirish
	if req.SentToOrders == "" {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   "Yetkazib berish vaqti kiritilishi shart",
		})
		return
	}

	// Yetkazib berish vaqtini parse qilish
	deliveryTime, err := time.Parse(time.RFC3339, req.SentToOrders)
	if err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   "Yetkazib berish vaqti formati noto'g'ri (ISO 8601 formatda bo'lishi kerak)",
		})
		return
	}

	userID, _ := c.Get("userId")

	// Mijoz ID ni aniqlash yoki yangi mijoz yaratish
	var clientID int
	if req.ClientID != nil {
		clientID = *req.ClientID
	} else if req.NewClient != nil {
		// 1. User yaratish
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewClient.Number), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, APIResponse{
				Success: false,
				Error:   "Parolni shifrlashda xatolik",
			})
			return
		}

		userResult, err := DB.Exec(
			"INSERT INTO users (username, phone_number, password, role) VALUES (?, ?, ?, ?)",
			req.NewClient.Username,
			req.NewClient.Number,
			string(hashedPassword),
			"client",
		)

		var newUserID int64
		if err != nil {
			// Agar user allaqachon mavjud bo'lsa, uning ID sini olish
			if strings.Contains(err.Error(), "UNIQUE constraint failed") {
				var existingUserID int
				err = DB.QueryRow("SELECT id FROM users WHERE phone_number = ?", req.NewClient.Number).Scan(&existingUserID)
				if err != nil {
					c.JSON(http.StatusInternalServerError, APIResponse{
						Success: false,
						Error:   "User tekshirishda xatolik",
					})
					return
				}
				newUserID = int64(existingUserID)
			} else {
				c.JSON(http.StatusInternalServerError, APIResponse{
					Success: false,
					Error:   "User yaratishda xatolik",
				})
				return
			}
		} else {
			newUserID, _ = userResult.LastInsertId()
		}

		// 2. Client yaratish
		result, err := DB.Exec(
			"INSERT INTO clients (username, number, location, longitude, latitude, image_url, user_id, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
			req.NewClient.Username,
			req.NewClient.Number,
			req.NewClient.Location,
			req.NewClient.Longitude,
			req.NewClient.Latitude,
			req.NewClient.ImageUrl,
			newUserID,
			userID,
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, APIResponse{
				Success: false,
				Error:   "Yangi mijoz yaratishda xatolik",
			})
			return
		}
		newClientID, _ := result.LastInsertId()
		clientID = int(newClientID)
	} else {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   "Mijoz ID yoki yangi mijoz ma'lumotlari kiritilishi shart",
		})
		return
	}

	// Mahsulotlar narxini hisoblash
	var totalPrice float64
	var orderItems []OrderItem

	for _, p := range req.Products {
		var product Product
		err := DB.QueryRow("SELECT id, name, price FROM products WHERE id = ?", p.ProductID).
			Scan(&product.ID, &product.Name, &product.Price)

		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, APIResponse{
				Success: false,
				Error:   fmt.Sprintf("Mahsulot ID %d topilmadi", p.ProductID),
			})
			return
		}

		if err != nil {
			c.JSON(http.StatusInternalServerError, APIResponse{
				Success: false,
				Error:   "Mahsulot ma'lumotlarini olishda xatolik",
			})
			return
		}

		itemPrice := product.Price * float64(p.ProductCount)
		totalPrice += itemPrice

		orderItems = append(orderItems, OrderItem{
			ProductID:    product.ID,
			ProductName:  product.Name,
			ProductPrice: product.Price,
			ProductCount: p.ProductCount,
		})
	}

	// YANGILANGAN: Yetkazib berish sanasiga ko'ra Order ID generatsiya qilish
	orderID, err := GenerateOrderID(deliveryTime)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "Buyurtma ID yaratishda xatolik",
		})
		return
	}

	// Buyurtmani saqlash
	_, err = DB.Exec(
		"INSERT INTO orders (id, order_price, client_id, comment, status, sent_to_orders, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)",
		orderID,
		totalPrice,
		clientID,
		req.Comment,
		"pending",
		deliveryTime,
		userID,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "Buyurtmani saqlashda xatolik",
		})
		return
	}

	// Buyurtma itemlarini saqlash
	for _, item := range orderItems {
		_, err := DB.Exec(
			"INSERT INTO order_items (order_id, product_id, product_name, product_price, product_count) VALUES (?, ?, ?, ?, ?)",
			orderID,
			item.ProductID,
			item.ProductName,
			item.ProductPrice,
			item.ProductCount,
		)
		if err != nil {
			log.Printf("Order item saqlashda xatolik: %v", err)
		}
	}

	// Mijoz ma'lumotlarini olish
	var client Client
	err = DB.QueryRow(`
		SELECT id, username, number, location, longitude, latitude, image_url 
		FROM clients WHERE id = ?`, clientID,
	).Scan(&client.ID, &client.Username, &client.Number, &client.Location, &client.Longitude, &client.Latitude, &client.ImageUrl)

	if err != nil {
		log.Printf("Mijoz ma'lumotlarini olishda xatolik: %v", err)
	}

	// Telegram guruhga xabar yuborish
	go func() {
		productsResp := make([]OrderItemResponse, 0, len(orderItems))
		for _, it := range orderItems {
			productsResp = append(productsResp, OrderItemResponse{
				ProductID:    it.ProductID,
				ProductName:  it.ProductName,
				ProductPrice: it.ProductPrice,
				ProductCount: it.ProductCount,
			})
		}

		err := SendTelegramNotification(orderID, client, productsResp, totalPrice, deliveryTime, req.Comment)
		if err != nil {
			log.Printf("Telegram xabar yuborishda xatolik: %v", err)
		}
	}()
	c.JSON(http.StatusCreated, APIResponse{
		Success: true,
		Message: "Buyurtma muvaffaqiyatli yaratildi",
		Data: map[string]interface{}{
			"orderId": orderID,
		},
	})
}

func GetOrders(c *gin.Context) {
	userID, _ := c.Get("userId")
	role, _ := c.Get("role")

	dateFilter := c.Query("date")
	statusFilter := c.Query("status")

	query := `
		SELECT id, order_price, client_id, comment, status, sent_to_orders, created_by, supplier_id, sms_sent, sms_sent_at, created_at 
		FROM orders WHERE 1=1`

	var args []interface{}

	// Role bo'yicha filtr
	switch role {
	case "admin":
		// Admin barcha buyurtmalarni ko'radi
		// Hech qanday qo'shimcha filtr yo'q

	case "client":
		// Client faqat o'z buyurtmalarini ko'radi
		var clientID int
		err := DB.QueryRow("SELECT id FROM clients WHERE user_id = ?", userID).Scan(&clientID)
		if err != nil {
			c.JSON(http.StatusNotFound, APIResponse{
				Success: false,
				Error:   "Client ma'lumotlari topilmadi",
			})
			return
		}
		query += " AND client_id = ?"
		args = append(args, clientID)

	case "operator":
		// Operator faqat o'zi yaratgan buyurtmalarni ko'radi
		query += " AND created_by = ?"
		args = append(args, userID)

	case "supplier":
		// Supplier faqat tayyor buyurtmalarni yoki o'ziga biriktirilgan buyurtmalarni ko'radi
		query += " AND (status = 'ready' OR supplier_id = ?)"
		args = append(args, userID)

	default:
		// Boshqa rollar faqat o'zlari yaratgan buyurtmalarni ko'radi
		query += " AND created_by = ?"
		args = append(args, userID)
	}

	if dateFilter != "" {
		query += " AND DATE(sent_to_orders) = ?"
		args = append(args, dateFilter)
	}

	if statusFilter != "" {
		query += " AND status = ?"
		args = append(args, statusFilter)
	}

	query += " ORDER BY sent_to_orders DESC, created_at DESC"

	rows, err := DB.Query(query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "Buyurtmalarni olishda xatolik",
		})
		return
	}
	defer rows.Close()

	var orders []OrderResponse
	for rows.Next() {
		var order Order
		var smsSentAt sql.NullTime
		var supplierID sql.NullInt64

		err := rows.Scan(
			&order.ID,
			&order.OrderPrice,
			&order.ClientID,
			&order.Comment,
			&order.Status,
			&order.SentToOrders,
			&order.CreatedBy,
			&supplierID,
			&order.SmsSent,
			&smsSentAt,
			&order.CreatedAt,
		)

		if err != nil {
			continue
		}

		if smsSentAt.Valid {
			order.SmsSentAt = &smsSentAt.Time
		}

		if supplierID.Valid {
			suppID := int(supplierID.Int64)
			order.SupplierID = &suppID
		}

		orders = append(orders, buildOrderResponse(order))
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Data:    orders,
	})
}

func GetOrderByID(c *gin.Context) {
	orderID := c.Param("id")

	var order Order
	var smsSentAt sql.NullTime
	var supplierID sql.NullInt64

	err := DB.QueryRow(`
		SELECT id, order_price, client_id, comment, status, sent_to_orders, created_by, supplier_id, sms_sent, sms_sent_at, created_at 
		FROM orders WHERE id = ?`, orderID,
	).Scan(
		&order.ID,
		&order.OrderPrice,
		&order.ClientID,
		&order.Comment,
		&order.Status,
		&order.SentToOrders,
		&order.CreatedBy,
		&supplierID,
		&order.SmsSent,
		&smsSentAt,
		&order.CreatedAt,
	)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, APIResponse{
			Success: false,
			Error:   "Buyurtma topilmadi",
		})
		return
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "Buyurtmani olishda xatolik",
		})
		return
	}

	if smsSentAt.Valid {
		order.SmsSentAt = &smsSentAt.Time
	}

	if supplierID.Valid {
		suppID := int(supplierID.Int64)
		order.SupplierID = &suppID
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Data:    buildOrderResponse(order),
	})
}

func UpdateOrderStatus(c *gin.Context) {
	orderID := c.Param("id")

	var req UpdateStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   "Ma'lumotlar to'liq emas",
		})
		return
	}

	validStatuses := []string{"pending", "confirmed", "preparing", "ready", "delivering", "delivered", "cancelled"}
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
	var userIDNull sql.NullInt64
	DB.QueryRow(`
		SELECT id, username, number, location, longitude, latitude, image_url, user_id 
		FROM clients WHERE id = ?`, order.ClientID,
	).Scan(&client.ID, &client.Username, &client.Number, &client.Location, &client.Longitude, &client.Latitude, &client.ImageUrl, &userIDNull)

	if userIDNull.Valid {
		client.UserID = int(userIDNull.Int64)
	}

	var creator User
	DB.QueryRow("SELECT id, username, phone_number, role FROM users WHERE id = ?", order.CreatedBy).
		Scan(&creator.ID, &creator.Username, &creator.PhoneNumber, &creator.Role)

	response := OrderResponse{
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
			ImageUrl:  client.ImageUrl,
		},
		Comment:      order.Comment,
		Status:       order.Status,
		SentToOrders: order.SentToOrders.Format("2006-01-02T15:04:05Z07:00"),
		CreatedBy: UserResponse{
			ID:          creator.ID,
			Username:    creator.Username,
			PhoneNumber: creator.PhoneNumber,
			Role:        creator.Role,
		},
		CreatedAt: order.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	// Agar supplier biriktirilgan bo'lsa, uning ma'lumotlarini qo'shish
	if order.SupplierID != nil {
		var supplier User
		err := DB.QueryRow("SELECT id, username, phone_number, role FROM users WHERE id = ?", *order.SupplierID).
			Scan(&supplier.ID, &supplier.Username, &supplier.PhoneNumber, &supplier.Role)
		if err == nil {
			response.Supplier = &UserResponse{
				ID:          supplier.ID,
				Username:    supplier.Username,
				PhoneNumber: supplier.PhoneNumber,
				Role:        supplier.Role,
			}
		}
	}

	return response
}

// ========================= SUPPLIER =========================

// Supplier buyurtmani qabul qilishi
func AcceptOrder(c *gin.Context) {
	orderID := c.Param("id")
	userID, _ := c.Get("userId")
	role, _ := c.Get("role")

	// Faqat supplier qabul qila oladi
	if role != "supplier" {
		c.JSON(http.StatusForbidden, APIResponse{
			Success: false,
			Error:   "Sizda bu amalni bajarish uchun ruxsat yo'q",
		})
		return
	}

	// Buyurtma statusini tekshirish
	var currentStatus string
	var currentSupplierID sql.NullInt64
	err := DB.QueryRow("SELECT status, supplier_id FROM orders WHERE id = ?", orderID).
		Scan(&currentStatus, &currentSupplierID)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, APIResponse{
			Success: false,
			Error:   "Buyurtma topilmadi",
		})
		return
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "Buyurtmani tekshirishda xatolik",
		})
		return
	}

	// Faqat "ready" statusdagi buyurtmalarni qabul qilish mumkin
	if currentStatus != "ready" {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   "Faqat tayyor buyurtmalarni qabul qilish mumkin",
		})
		return
	}

	// Agar allaqachon boshqa supplier qabul qilgan bo'lsa
	if currentSupplierID.Valid {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   "Bu buyurtma allaqachon boshqa yetkazib beruvchi tomonidan qabul qilingan",
		})
		return
	}

	// Buyurtmani supplierga biriktrish va statusni o'zgartirish
	result, err := DB.Exec(
		"UPDATE orders SET supplier_id = ?, status = 'delivering' WHERE id = ?",
		userID, orderID,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "Buyurtmani qabul qilishda xatolik",
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
		Message: "Buyurtma muvaffaqiyatli qabul qilindi",
	})
}

// Supplier yetkazib bo'lgandan keyin yetkazildi deb belgilaydi
func CompleteDelivery(c *gin.Context) {
	orderID := c.Param("id")
	userID, _ := c.Get("userId")
	role, _ := c.Get("role")

	// Faqat supplier bajarishi mumkin
	if role != "supplier" {
		c.JSON(http.StatusForbidden, APIResponse{
			Success: false,
			Error:   "Sizda bu amalni bajarish uchun ruxsat yo'q",
		})
		return
	}

	// Buyurtma o'sha supplierga tegishli ekanligini tekshirish
	var supplierID sql.NullInt64
	var currentStatus string
	err := DB.QueryRow("SELECT supplier_id, status FROM orders WHERE id = ?", orderID).
		Scan(&supplierID, &currentStatus)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, APIResponse{
			Success: false,
			Error:   "Buyurtma topilmadi",
		})
		return
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "Buyurtmani tekshirishda xatolik",
		})
		return
	}

	// Buyurtma shu supplierga tegishli ekanligini tekshirish
	if !supplierID.Valid || int(supplierID.Int64) != userID.(int) {
		c.JSON(http.StatusForbidden, APIResponse{
			Success: false,
			Error:   "Bu buyurtma sizga biriktirilmagan",
		})
		return
	}

	// Statusni yetkazildi qilish
	result, err := DB.Exec(
		"UPDATE orders SET status = 'delivered' WHERE id = ?",
		orderID,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "Buyurtma statusini yangilashda xatolik",
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
		Message: "Buyurtma yetkazildi deb belgilandi",
	})
}

// GetMyDeliveries - Supplier faqat o'zi qabul qilgan buyurtmalarni ko'radi
func GetMyDeliveries(c *gin.Context) {
	userID, _ := c.Get("userId")
	role, _ := c.Get("role")

	// Faqat supplier chaqira oladi
	if role != "supplier" {
		c.JSON(http.StatusForbidden, APIResponse{
			Success: false,
			Error:   "Sizda bu amalni bajarish uchun ruxsat yo'q",
		})
		return
	}

	rows, err := DB.Query(`
		SELECT id, order_price, client_id, comment, status, sent_to_orders, created_by, supplier_id, sms_sent, sms_sent_at, created_at 
		FROM orders 
		WHERE supplier_id = ?
		ORDER BY sent_to_orders DESC, created_at DESC
	`, userID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "Buyurtmalarni olishda xatolik",
		})
		return
	}
	defer rows.Close()

	var orders []OrderResponse
	for rows.Next() {
		var order Order
		var smsSentAt sql.NullTime
		var supplierID sql.NullInt64

		err := rows.Scan(
			&order.ID,
			&order.OrderPrice,
			&order.ClientID,
			&order.Comment,
			&order.Status,
			&order.SentToOrders,
			&order.CreatedBy,
			&supplierID,
			&order.SmsSent,
			&smsSentAt,
			&order.CreatedAt,
		)

		if err != nil {
			log.Printf("Row scan error: %v", err)
			continue
		}

		if supplierID.Valid {
			suppID := int(supplierID.Int64)
			order.SupplierID = &suppID
		}

		if smsSentAt.Valid {
			order.SmsSentAt = &smsSentAt.Time
		}

		orderResponse := buildOrderResponse(order)
		orders = append(orders, orderResponse)
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Data:    orders,
	})
}

// ========================= USERS MANAGEMENT =========================

func GetAllUsers(c *gin.Context) {
	role, _ := c.Get("role")

	if role != "admin" {
		c.JSON(http.StatusForbidden, APIResponse{
			Success: false,
			Error:   "Sizda bu amalni bajarish uchun ruxsat yo'q",
		})
		return
	}

	rows, err := DB.Query(`
		SELECT id, username, phone_number, role, created_at 
		FROM users 
		ORDER BY created_at DESC
	`)

	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "Foydalanuvchilarni olishda xatolik",
		})
		return
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		err := rows.Scan(
			&user.ID,
			&user.Username,
			&user.PhoneNumber,
			&user.Role,
			&user.CreatedAt,
		)

		if err != nil {
			log.Printf("Row scan error: %v", err)
			continue
		}

		users = append(users, user)
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Data:    users,
	})
}

func GetUserByID(c *gin.Context) {
	userID := c.Param("id")
	role, _ := c.Get("role")

	if role != "admin" {
		c.JSON(http.StatusForbidden, APIResponse{
			Success: false,
			Error:   "Sizda bu amalni bajarish uchun ruxsat yo'q",
		})
		return
	}

	var user User
	err := DB.QueryRow(
		"SELECT id, username, phone_number, role, created_at FROM users WHERE id = ?",
		userID,
	).Scan(&user.ID, &user.Username, &user.PhoneNumber, &user.Role, &user.CreatedAt)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, APIResponse{
			Success: false,
			Error:   "Foydalanuvchi topilmadi",
		})
		return
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "Foydalanuvchini olishda xatolik",
		})
		return
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Data:    user,
	})
}

func UpdateUser(c *gin.Context) {
	userID := c.Param("id")
	role, _ := c.Get("role")

	if role != "admin" {
		c.JSON(http.StatusForbidden, APIResponse{
			Success: false,
			Error:   "Sizda bu amalni bajarish uchun ruxsat yo'q",
		})
		return
	}

	var req struct {
		Username    string `json:"username"`
		PhoneNumber string `json:"phoneNumber"`
		Password    string `json:"password"`
		Role        string `json:"role"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   "Ma'lumotlar to'liq emas",
		})
		return
	}

	validRoles := []string{"admin", "operator", "user", "supplier", "client"}
	isValidRole := false
	for _, r := range validRoles {
		if req.Role == r {
			isValidRole = true
			break
		}
	}

	if !isValidRole {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   "Noto'g'ri rol qiymati",
		})
		return
	}

	var existingUser User
	err := DB.QueryRow("SELECT id, username, phone_number, role FROM users WHERE id = ?", userID).
		Scan(&existingUser.ID, &existingUser.Username, &existingUser.PhoneNumber, &existingUser.Role)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, APIResponse{
			Success: false,
			Error:   "Foydalanuvchi topilmadi",
		})
		return
	}

	if req.Password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, APIResponse{
				Success: false,
				Error:   "Parolni shifrlashda xatolik",
			})
			return
		}

		result, err := DB.Exec(
			"UPDATE users SET username = ?, phone_number = ?, password = ?, role = ? WHERE id = ?",
			req.Username, req.PhoneNumber, string(hashedPassword), req.Role, userID,
		)

		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE constraint failed") {
				c.JSON(http.StatusConflict, APIResponse{
					Success: false,
					Error:   "Bu telefon raqam allaqachon ro'yxatdan o'tgan",
				})
				return
			}
			c.JSON(http.StatusInternalServerError, APIResponse{
				Success: false,
				Error:   "Foydalanuvchini yangilashda xatolik",
			})
			return
		}

		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			c.JSON(http.StatusNotFound, APIResponse{
				Success: false,
				Error:   "Foydalanuvchi topilmadi",
			})
			return
		}
	} else {
		result, err := DB.Exec(
			"UPDATE users SET username = ?, phone_number = ?, role = ? WHERE id = ?",
			req.Username, req.PhoneNumber, req.Role, userID,
		)

		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE constraint failed") {
				c.JSON(http.StatusConflict, APIResponse{
					Success: false,
					Error:   "Bu telefon raqam allaqachon ro'yxatdan o'tgan",
				})
				return
			}
			c.JSON(http.StatusInternalServerError, APIResponse{
				Success: false,
				Error:   "Foydalanuvchini yangilashda xatolik",
			})
			return
		}

		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			c.JSON(http.StatusNotFound, APIResponse{
				Success: false,
				Error:   "Foydalanuvchi topilmadi",
			})
			return
		}
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Foydalanuvchi muvaffaqiyatli yangilandi",
		Data: map[string]interface{}{
			"id":          userID,
			"username":    req.Username,
			"phoneNumber": req.PhoneNumber,
			"role":        req.Role,
		},
	})
}

func DeleteUser(c *gin.Context) {
	userID := c.Param("id")
	role, _ := c.Get("role")
	currentUserID, _ := c.Get("userId")

	if role != "admin" {
		c.JSON(http.StatusForbidden, APIResponse{
			Success: false,
			Error:   "Sizda bu amalni bajarish uchun ruxsat yo'q",
		})
		return
	}

	if fmt.Sprintf("%d", currentUserID) == userID {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   "O'zingizni o'chira olmaysiz",
		})
		return
	}

	var existingRole string
	err := DB.QueryRow("SELECT role FROM users WHERE id = ?", userID).Scan(&existingRole)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, APIResponse{
			Success: false,
			Error:   "Foydalanuvchi topilmadi",
		})
		return
	}

	if existingRole == "client" {
		DB.Exec("DELETE FROM clients WHERE user_id = ?", userID)
	}

	result, err := DB.Exec("DELETE FROM users WHERE id = ?", userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "Foydalanuvchini o'chirishda xatolik",
		})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, APIResponse{
			Success: false,
			Error:   "Foydalanuvchi topilmadi",
		})
		return
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Foydalanuvchi muvaffaqiyatli o'chirildi",
	})
}

// ========================= UPCOMING DELIVERIES =========================

func GetUpcomingDeliveries(c *gin.Context) {
	hoursParam := c.DefaultQuery("hours", "2")
	
	hours := 2
	fmt.Sscanf(hoursParam, "%d", &hours)

	now := time.Now()
	upcoming := now.Add(time.Duration(hours) * time.Hour)

	rows, err := DB.Query(`
		SELECT id, order_price, client_id, comment, status, sent_to_orders, created_by, supplier_id, sms_sent, sms_sent_at, created_at 
		FROM orders 
		WHERE sent_to_orders BETWEEN ? AND ?
		AND status NOT IN ('delivered', 'cancelled')
		ORDER BY sent_to_orders ASC
	`, now.Format("2006-01-02 15:04:05"), upcoming.Format("2006-01-02 15:04:05"))

	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "Buyurtmalarni olishda xatolik",
		})
		return
	}
	defer rows.Close()

	var orders []OrderResponse
	for rows.Next() {
		var order Order
		var smsSentAt sql.NullTime
		var supplierID sql.NullInt64

		err := rows.Scan(
			&order.ID,
			&order.OrderPrice,
			&order.ClientID,
			&order.Comment,
			&order.Status,
			&order.SentToOrders,
			&order.CreatedBy,
			&supplierID,
			&order.SmsSent,
			&smsSentAt,
			&order.CreatedAt,
		)

		if err != nil {
			log.Printf("Row scan error: %v", err)
			continue
		}

		if supplierID.Valid {
			suppID := int(supplierID.Int64)
			order.SupplierID = &suppID
		}

		if smsSentAt.Valid {
			order.SmsSentAt = &smsSentAt.Time
		}

		orderResponse := buildOrderResponse(order)
		orders = append(orders, orderResponse)
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Data:    orders,
		Message: fmt.Sprintf("Kelgusi %d soat ichida yetkazilishi kerak bo'lgan buyurtmalar", hours),
	})
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

	// 1. Shu raqamga tegishli barcha client_id larni olish
	rows, err := DB.Query("SELECT id FROM clients WHERE number = ?", phone)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   "Mijozlarni olishda xatolik",
		})
		return
	}
	defer rows.Close()

	var clientIDs []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err == nil {
			clientIDs = append(clientIDs, id)
		}
	}

	if len(clientIDs) == 0 {
		c.JSON(http.StatusNotFound, APIResponse{
			Success: false,
			Error:   "Bu raqamga tegishli mijoz topilmadi",
		})
		return
	}

	// 2. IN (...) uchun placeholderlar yaratish
	placeholders := make([]string, len(clientIDs))
	args := make([]interface{}, len(clientIDs))
	for i, id := range clientIDs {
		placeholders[i] = "?"
		args[i] = id
	}

	query := fmt.Sprintf(`
		UPDATE orders 
		SET sms_sent = 1, sms_sent_at = CURRENT_TIMESTAMP 
		WHERE client_id IN (%s) AND sms_sent = 0`,
		strings.Join(placeholders, ","),
	)

	// 3. Yangilash
	result, err := DB.Exec(query, args...)
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
		Message: fmt.Sprintf("SMS yuborilgani tasdiqlandi (%d ta buyurtma yangilandi)", rowsAffected),
	})
}

// ========================= ROUTES =========================

func SetupRoutes(router *gin.Engine) {
	// Static fayllar uchun (rasmlar)
	router.Static("/uploads", "./uploads")

	api := router.Group("/api")

	// Upload endpoint (authentication kerak emas)
	api.POST("/upload", UploadImage)

	auth := api.Group("/auth")
	{
		auth.POST("/login", Login)
		auth.POST("/register", Register)
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

		// Supplier uchun
		orders.GET("/my-deliveries", GetMyDeliveries)
		orders.POST("/:id/accept", AcceptOrder)
		orders.POST("/:id/complete", CompleteDelivery)
	}

	sms := api.Group("/sms")
	sms.Use()
	{
		sms.GET("/pending", GetPendingSMS)
		sms.POST("/sent/:phone", MarkSMSSent)
	}

	// Users management (faqat admin)
	users := api.Group("/users")
	users.Use(AuthMiddleware(), AdminOnly())
	{
		users.GET("", GetAllUsers)
		users.GET("/:id", GetUserByID)
		users.PUT("/:id", UpdateUser)
		users.DELETE("/:id", DeleteUser)
	}

	// Upcoming deliveries
	deliveries := api.Group("/deliveries")
	deliveries.Use(AuthMiddleware())
	{
		deliveries.GET("/upcoming", GetUpcomingDeliveries)
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
