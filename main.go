package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"image"
	"image/jpeg"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/adrium/goheif" // HEIC/HEIF support
	"github.com/gorilla/mux"
	"github.com/nfnt/resize"
	_ "golang.org/x/image/webp" // WebP support
)

const (
	BOT_TOKEN = "8157743798:AAELzxyyFLSMxbT-XL4l-3ZVmxVBXYOY0Ro"
	CHAT_ID   = "-4800613243"
)

func main() {
	fmt.Println("🚀 Server ishga tushmoqda...")
	initData()

	// Telegram backup service ni ishga tushirish
	startBackupService()
	log.Println("✅ Backup service ishga tushdi (har kuni soat 00:00)")

	r := mux.NewRouter()

	// CORS middleware
	r.Use(corsMiddleware)

	// Health check
	r.HandleFunc("/", healthCheck).Methods("GET", "OPTIONS")
	r.HandleFunc("/health", healthCheck).Methods("GET", "OPTIONS")

	// API routes
	api := r.PathPrefix("/api").Subrouter()

	// ================= AUTH ROUTES =================
	api.HandleFunc("/login", login).Methods("POST", "OPTIONS")
	api.HandleFunc("/register", register).Methods("POST", "OPTIONS")

	// ================= USER ROUTES =================
	api.HandleFunc("/products1", getProductsHandler).Methods("GET", "OPTIONS")
	// api.HandleFunc("/products", authenticateJWT(getProductsHandler)).Methods("GET", "OPTIONS")
	api.HandleFunc("/orders", authenticateJWT(createOrderHandler)).Methods("POST", "OPTIONS")
	api.HandleFunc("/orders", authenticateJWT(getOrdersHandler)).Methods("GET", "OPTIONS")
	api.HandleFunc("/orders/{id:[0-9]+}", authenticateJWT(getOrderHandler)).Methods("GET", "OPTIONS")

	api.HandleFunc("/filials", authenticateJWT(getFilialsHandler)).Methods("GET", "OPTIONS")
	api.HandleFunc("/categories", authenticateJWT(getCategoriesHandler)).Methods("GET", "OPTIONS")

	// ================= ADMIN ROUTES =================
	api.HandleFunc("/filials", requireAdmin(addFilialHandler)).Methods("POST", "OPTIONS")
	api.HandleFunc("/filials/{id:[0-9]+}", requireAdmin(getFilialHandler)).Methods("GET", "OPTIONS")
	api.HandleFunc("/filials/{id:[0-9]+}", requireAdmin(updateFilialHandler)).Methods("PUT", "OPTIONS")
	api.HandleFunc("/filials/{id:[0-9]+}", requireAdmin(deleteFilialHandler)).Methods("DELETE", "OPTIONS")

	api.HandleFunc("/categories", requireAdmin(addCategoryHandler)).Methods("POST", "OPTIONS")
	api.HandleFunc("/categories/{id:[0-9]+}", requireAdmin(getCategoryHandler)).Methods("GET", "OPTIONS")
	api.HandleFunc("/categories/{id:[0-9]+}", requireAdmin(updateCategoryHandler)).Methods("PUT", "OPTIONS")
	api.HandleFunc("/categories/{id:[0-9]+}", requireAdmin(deleteCategoryHandler)).Methods("DELETE", "OPTIONS")

	// Products
	api.HandleFunc("/products/all", requireAdmin(getAllProductsHandler)).Methods("GET", "OPTIONS")
	api.HandleFunc("/products", requireAdmin(addProductHandler)).Methods("POST", "OPTIONS")
	api.HandleFunc("/products/{id:[0-9]+}", requireAdmin(getProductHandler)).Methods("GET", "OPTIONS")
	api.HandleFunc("/products/{id:[0-9]+}", requireAdmin(updateProductHandler)).Methods("PUT", "OPTIONS")
	api.HandleFunc("/products/{id:[0-9]+}", requireAdmin(deleteProductHandler)).Methods("DELETE", "OPTIONS")

	// Users
	api.HandleFunc("/users", requireAdmin(getUsersHandler)).Methods("GET", "OPTIONS")
	api.HandleFunc("/users/{id:[0-9]+}", requireAdmin(getUserHandler)).Methods("GET", "OPTIONS")
	api.HandleFunc("/users/{id:[0-9]+}", requireAdmin(updateUserHandler)).Methods("PUT", "OPTIONS")
	api.HandleFunc("/users/{id:[0-9]+}", requireAdmin(deleteUserHandler)).Methods("DELETE", "OPTIONS")
	api.HandleFunc("/users/{id:[0-9]+}/assign-filial", requireAdmin(assignFilialHandler)).Methods("PUT", "OPTIONS")

	// Orders
	api.HandleFunc("/orderslist", requireAdmin(getOrdersListHandler)).Methods("GET", "OPTIONS")
	api.HandleFunc("/orders/{id:[0-9]+}", requireAdmin(updateOrderHandler)).Methods("PUT", "OPTIONS")
	api.HandleFunc("/orders/{id:[0-9]+}", requireAdmin(deleteOrderHandler)).Methods("DELETE", "OPTIONS")

	// Category Items
	api.HandleFunc("/category-items", requireAdmin(getCategoryItemsHandler)).Methods("GET", "OPTIONS")
	api.HandleFunc("/category-items/{id:[0-9]+}", requireAdmin(getCategoryItemHandler)).Methods("GET", "OPTIONS")
	api.HandleFunc("/categories/{id:[0-9]+}/items", authenticateJWT(getCategoryItemsByCategoryHandler)).Methods("GET", "OPTIONS")

	api.HandleFunc("/category-items", requireAdmin(addCategoryItemHandler)).Methods("POST", "OPTIONS")
	api.HandleFunc("/category-items/{id:[0-9]+}", requireAdmin(updateCategoryItemHandler)).Methods("PUT", "OPTIONS")
	api.HandleFunc("/category-items/{id:[0-9]+}", requireAdmin(deleteCategoryItemHandler)).Methods("DELETE", "OPTIONS")

	// ================= IMAGE UPLOAD =================
	api.HandleFunc("/upload", authenticateJWT(uploadImageHandler)).Methods("POST", "OPTIONS")

	// Static files
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("uploads"))))

	// Run server
	log.Fatal(http.ListenAndServe(":1010", r))
}

//////////////////////////////////////////////////////
// TELEGRAM BACKUP SERVICE
//////////////////////////////////////////////////////

// Backup service - har kuni soat 00:00 da ishga tushadi
func startBackupService() {
	go func() {
		for {
			now := time.Now()
			// Ertangi kunning 00:00 ini hisoblaymiz
			next := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, now.Location())
			duration := next.Sub(now)

			log.Printf("⏰ Keyingi backup vaqti: %s (%.0f soatdan keyin)", next.Format("02.01.2006 15:04"), duration.Hours())

			// Belgilangan vaqtgacha kutamiz
			time.Sleep(duration)

			// Backup yuborish
			log.Println("🔄 Backup jarayoni boshlandi...")
			err := sendBackupToTelegram()
			if err != nil {
				log.Printf("❌ Backup yuborishda xatolik: %v", err)
			} else {
				log.Println("✅ Backup muvaffaqiyatli yuborildi!")
			}
		}
	}()
}

// Papkalarni zip qilish
func createZipArchive(folders []string, zipPath string) error {
	zipFile, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	for _, folder := range folders {
		// Papka mavjudligini tekshirish
		if _, err := os.Stat(folder); os.IsNotExist(err) {
			log.Printf("⚠️ Papka topilmadi: %s", folder)
			continue
		}

		err := filepath.Walk(folder, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			// Papkani o'tkazib yuboramiz, faqat fayllarni qo'shamiz
			if info.IsDir() {
				return nil
			}

			// Zip ichidagi relative path
			relPath, err := filepath.Rel(".", path)
			if err != nil {
				return err
			}

			// Zip ichiga fayl qo'shish
			zipEntry, err := zipWriter.Create(relPath)
			if err != nil {
				return err
			}

			// Faylni o'qish
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()

			// Zip ga yozish
			_, err = io.Copy(zipEntry, file)
			return err
		})

		if err != nil {
			return err
		}
	}

	return nil
}

// Telegram ga yuborish
func sendBackupToTelegram() error {
	// Vaqt belgisi
	timestamp := time.Now().Format("2006-01-02_15-04")
	zipFileName := fmt.Sprintf("backup_%s.zip", timestamp)

	// Zip fayl yaratish
	log.Println("📦 Zip arxiv yaratilmoqda...")
	err := createZipArchive([]string{"uploads", "data"}, zipFileName)
	if err != nil {
		return fmt.Errorf("zip yaratishda xatolik: %v", err)
	}
	defer os.Remove(zipFileName) // Yuborilgandan keyin o'chirish

	// Fayl hajmini tekshirish
	fileInfo, err := os.Stat(zipFileName)
	if err != nil {
		return err
	}
	sizeMB := float64(fileInfo.Size()) / (1024 * 1024)
	log.Printf("📊 Arxiv hajmi: %.2f MB", sizeMB)

	// Telegram API ga yuborish
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument", BOT_TOKEN)

	file, err := os.Open(zipFileName)
	if err != nil {
		return err
	}
	defer file.Close()

	// Multipart form yaratish
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// chat_id parametri
	_ = writer.WriteField("chat_id", CHAT_ID)
	_ = writer.WriteField("caption", fmt.Sprintf("📅 Kunlik backup\n🕐 Vaqt: %s\n📦 Hajm: %.2f MB",
		time.Now().Format("02.01.2006 15:04"), sizeMB))

	// Fayl qo'shish
	part, err := writer.CreateFormFile("document", zipFileName)
	if err != nil {
		return err
	}

	_, err = io.Copy(part, file)
	if err != nil {
		return err
	}

	err = writer.Close()
	if err != nil {
		return err
	}

	// HTTP request
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram API xatolik: %s", string(bodyBytes))
	}

	return nil
}

// ////////////////////////////////////////////////////
// Image upload handler
// ////////////////////////////////////////////////////
func uploadImageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Faqat POST request!", http.StatusMethodNotAllowed)
		return
	}

	err := r.ParseMultipartForm(20 << 20)
	if err != nil {
		http.Error(w, "Formani parse qilishda xatolik: "+err.Error(), http.StatusBadRequest)
		return
	}

	file, handler, err := r.FormFile("image")
	if err != nil {
		http.Error(w, "Rasmni olishda xatolik: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	err = os.MkdirAll("uploads", os.ModePerm)
	if err != nil {
		http.Error(w, "Papka yaratishda xatolik: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Faylning kengaytmasini tekshirish
	ext := strings.ToLower(filepath.Ext(handler.Filename))

	var img image.Image
	var format string

	// HEIC/HEIF formatni alohida qayta ishlash
	if ext == ".heic" || ext == ".heif" {
		// Faylni boshidan o'qish uchun qayta ochish
		file.Seek(0, 0)
		img, err = goheif.Decode(file)
		if err != nil {
			http.Error(w, "HEIC rasmni decode qilishda xatolik: "+err.Error(), http.StatusBadRequest)
			return
		}
		format = "heic"
	} else {
		// Boshqa formatlar uchun standart decoder
		file.Seek(0, 0)
		img, format, err = image.Decode(file)
		if err != nil {
			http.Error(w, "Rasmni decode qilishda xatolik: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	log.Println("Image format:", format)

	// Rasmni kichraytirish
	newImg := resize.Resize(1024, 0, img, resize.Lanczos3)

	// Fayl nomini yaratish (kengaytmasiz)
	baseFilename := strings.TrimSuffix(handler.Filename, filepath.Ext(handler.Filename))
	savePath := fmt.Sprintf("uploads/%s.jpg", baseFilename)

	out, err := os.Create(savePath)
	if err != nil {
		http.Error(w, "Faylni yaratishda xatolik: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer out.Close()

	// JPEG sifatida saqlash
	opts := &jpeg.Options{Quality: 85}
	err = jpeg.Encode(out, newImg, opts)
	if err != nil {
		http.Error(w, "JPEG encode qilishda xatolik: "+err.Error(), http.StatusInternalServerError)
		return
	}

	imageURL := "/static/" + filepath.Base(savePath)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`{"message":"Yuklandi","url":"%s"}`, imageURL)))
}
