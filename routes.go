package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
)

// Health check endpoint
func healthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Server ishlamoqda",
		Data: map[string]interface{}{
			"time":           time.Now().Format(time.RFC3339),
			"filials":        len(filials),
			"categories":     len(categories),
			"users":          len(users),
			"products":       len(products),
			"orders":         len(orders),
			"categoryItems":  len(categoryItems),
			"iphoneVersion":  "0.1.4",
			"appstoreUrl":    "https://apps.apple.com/us/app/uzaidev/id6752371524",
			"androidVersion": "0.0.1",
			"playstoreUrl":   "https://play.google.com/store/apps/details?id=com.example.app",
		},
	})
}

// ================= CATEGORY ITEMS ROUTES =================

// GET /api/category-items
func getCategoryItemsHandler(w http.ResponseWriter, r *http.Request) {
	items := GetAllCategoryItems()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Category Items",
		Data:    items,
	})
}

// GET /api/category-items/{id}
func getCategoryItemHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid category item ID", http.StatusBadRequest)
		return
	}

	item := GetCategoryItemByID(uint(id))
	if item == nil {
		http.Error(w, "Category item not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Category Item",
		Data:    item,
	})
}

// GET /api/categories/{id}/items
func getCategoryItemsByCategoryHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	categoryID, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid category ID", http.StatusBadRequest)
		return
	}

	items := GetCategoryItemsByCategoryID(uint(categoryID))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Category Items by Category",
		Data:    items,
	})
}

// POST /api/category-items
func addCategoryItemHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CategoryID uint   `json:"category_id"`
		Name       string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	item := CreateCategoryItem(req.CategoryID, req.Name)
	if item == nil {
		http.Error(w, "Category not found", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Category Item qo'shildi",
		Data:    item,
	})
}

// PUT /api/category-items/{id}
func updateCategoryItemHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid category item ID", http.StatusBadRequest)
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	item := UpdateCategoryItem(uint(id), req.Name)
	if item == nil {
		http.Error(w, "Category item not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Category Item yangilandi",
		Data:    item,
	})
}

// DELETE /api/category-items/{id}
func deleteCategoryItemHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid category item ID", http.StatusBadRequest)
		return
	}

	if DeleteCategoryItem(uint(id)) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(Response{
			Success: true,
			Message: "Category Item o'chirildi",
		})
	} else {
		http.Error(w, "Category item not found", http.StatusNotFound)
	}
}

// ================= AUTH ROUTES =================

// POST /api/login
func login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Invalid JSON",
		})
		return
	}

	user := findUserByPhone(req.Phone)
	if user == nil || !checkPassword(req.Password, user.Password) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Login yoki parol noto'g'ri",
		})
		return
	}

	token, err := generateToken(user.ID, user.Phone, user.IsAdmin)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Token yaratishda xatolik",
		})
		return
	}

	userProfile := UserProfile{
		ID:      user.ID,
		Name:    user.Name,
		Phone:   user.Phone,
		IsAdmin: user.IsAdmin,
	}

	if user.FilialID > 0 {
		if filial := findFilialByID(user.FilialID); filial != nil {
			userProfile.Filial = *filial
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Muvaffaqiyatli login",
		Data: LoginResponse{
			Token: token,
			User:  userProfile,
		},
	})
}

// POST /api/register
func register(w http.ResponseWriter, r *http.Request) {
	var req RegisterUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Invalid JSON",
		})
		return
	}

	if findUserByPhone(req.Phone) != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Bu telefon raqami allaqachon ro'yxatdan o'tgan",
		})
		return
	}
	if req.FilialID == 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Filial ID majburiy, null bo‘lishi mumkin emas",
		})
		return
	}

	user := CreateUser(req)
	token, _ := generateToken(user.ID, user.Phone, user.IsAdmin)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Muvaffaqiyatli ro'yxatdan o'tdingiz",
		Data: LoginResponse{
			Token: token,
			User: UserProfile{
				ID:      user.ID,
				Name:    user.Name,
				Phone:   user.Phone,
				IsAdmin: user.IsAdmin,
				Filial:  *findFilialByID(user.FilialID),
			},
		},
	})
}

// ================= FILIALS ROUTES =================

// GET /api/filials
func getFilialsHandler(w http.ResponseWriter, r *http.Request) {
	filials := GetAllFilials()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Filiallar",
		Data:    filials,
	})
}

// GET /api/filials/{id}
func getFilialHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Invalid filial ID",
		})
		return
	}

	filial := GetFilialByID(uint(id))
	if filial == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Filial topilmadi",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Filial",
		Data:    filial,
	})
}

// POST /api/filials
func addFilialHandler(w http.ResponseWriter, r *http.Request) {
	var req AddFilialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Invalid JSON",
		})
		return
	}

	filial := CreateFilial(req)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Filial qo'shildi",
		Data:    filial,
	})
}

// PUT /api/filials/{id}
func updateFilialHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Invalid filial ID",
		})
		return
	}

	var req UpdateFilialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Invalid JSON",
		})
		return
	}

	filial := UpdateFilial(uint(id), req)
	if filial == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Filial topilmadi",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Filial yangilandi",
		Data:    filial,
	})
}

// DELETE /api/filials/{id}
func deleteFilialHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Invalid filial ID",
		})
		return
	}

	if DeleteFilial(uint(id)) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(Response{
			Success: true,
			Message: "Filial o'chirildi",
		})
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Filial topilmadi",
		})
	}
}

// ================= CATEGORIES ROUTES =================

// GET /api/categories
func getCategoriesHandler(w http.ResponseWriter, r *http.Request) {
	categories := GetAllCategories()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Kategoriyalr",
		Data:    categories,
	})
}

// func getProductsByCategoryHandler(w http.ResponseWriter, r *http.Request) {

// 	w.Header().Set("Content-Type", "application/json")
// 	vars := mux.Vars(r)
// 	id, err := strconv.Atoi(vars["id"])

// 	if err != nil {
// 		w.Header().Set("Content-Type", "application/json")
// 		w.WriteHeader(http.StatusBadRequest)
// 		json.NewEncoder(w).Encode(Response{
// 			Success: false,
// 			Message: "Invalid category ID",
// 		})
// 		return
// 	}
// 	products := GetProductsByCategoryID(uint(id))
// 	w.WriteHeader(http.StatusOK)
// 	json.NewEncoder(w).Encode(Response{
// 		Success: true,
// 		Message: "Kategoriya",
// 		Data:    products,
// 	})
// }

// GET /api/categories/{id}
func getCategoryHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Invalid category ID",
		})
		return
	}

	category := GetCategoryByID(uint(id))
	if category == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Kategoriya topilmadi",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Kategoriya",
		Data:    category,
	})
}

// POST /api/categories
func addCategoryHandler(w http.ResponseWriter, r *http.Request) {
	var req AddCategoryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Invalid JSON",
		})
		return
	}

	category := CreateCategory(req)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Kategoriya qo'shildi",
		Data:    category,
	})
}

// PUT /api/categories/{id}
func updateCategoryHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Invalid category ID",
		})
		return
	}

	var req UpdateCategoryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Invalid JSON",
		})
		return
	}

	category := UpdateCategory(uint(id), req)
	if category == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Kategoriya topilmadi",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Kategoriya yangilandi",
		Data:    category,
	})
}

// DELETE /api/categories/{id}
func deleteCategoryHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Invalid category ID",
		})
		return
	}

	if DeleteCategory(uint(id)) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(Response{
			Success: true,
			Message: "Kategoriya o'chirildi",
		})
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Kategoriya topilmadi",
		})
	}
}

func getProductsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	groupedData := make(map[string][]ProductSimple)

	for _, product := range products {
		category := findCategoryByID(product.CategoryID)
		if category == nil || category.Name == "" {
			continue
		}

		groupedData[category.Name] = append(groupedData[category.Name], ProductSimple{
			ID:          product.ID,
			Type:        product.Type,
			Name:        product.Name,
			Ingredients: product.Ingredients,
			ImageUrl:    product.ImageUrl,
		})
	}

	json.NewEncoder(w).Encode(GroupedProductsResponse{
		Success: true,
		Message: "Barcha mahsulotlar olindi",
		Data:    groupedData,
	})
}

// GET /api/products/all (Admin uchun barcha mahsulotlar)
func getAllProductsHandler(w http.ResponseWriter, r *http.Request) {
	var productList []ProductDetails

	for _, product := range products {
		details := ProductDetails{
			ID:          product.ID,
			Name:        product.Name,
			Type:        product.Type,
			CategoryID:  product.CategoryID,
			Ingredients: product.Ingredients,
			Filials:     product.Filials,
			ImageUrl:    product.ImageUrl,
			FilialNames: []string{},
		}

		// Kategoriya mavjud bo‘lmasa ham "Unknown" deb beramiz
		if category := findCategoryByID(product.CategoryID); category != nil && category.Name != "" {
			details.CategoryName = category.Name
		} else {
			details.CategoryName = "Unknown"
		}

		// Filiallar mavjud bo‘lmasa ham, bo‘sh massiv sifatida qoladi
		if len(product.Filials) == 0 {
			details.FilialNames = []string{"Unknown"}
		} else {
			for _, filialID := range product.Filials {
				if filial := findFilialByID(filialID); filial != nil && filial.Name != "" {
					details.FilialNames = append(details.FilialNames, filial.Name)
				} else {
					// Agar filial topilmasa, "Unknown" deb yozamiz
					details.FilialNames = append(details.FilialNames, "Unknown")
				}
			}
		}

		productList = append(productList, details)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: fmt.Sprintf("Jami %d ta mahsulot topildi", len(productList)),
		Data:    productList,
	})
}

// GET /api/products/{id}
func getProductHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Invalid product ID",
		})
		return
	}

	product := GetProductByID(uint(id))
	if product == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Mahsulot topilmadi",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Mahsulot",
		Data:    product,
	})
}

// POST /api/products
func addProductHandler(w http.ResponseWriter, r *http.Request) {
	var req AddProductRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Invalid JSON",
		})
		return
	}

	product := CreateProduct(req)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Mahsulot qo'shildi",
		Data:    product,
	})
}

// PUT /api/products/{id}
func updateProductHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Invalid product ID",
		})
		return
	}

	var req UpdateProductRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Invalid JSON",
		})
		return
	}

	product := UpdateProduct(uint(id), req)
	if product == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Mahsulot topilmadi",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Mahsulot yangilandi",
		Data:    product,
	})
}

// DELETE /api/products/{id}
func deleteProductHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Invalid product ID",
		})
		return
	}

	if DeleteProduct(uint(id)) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(Response{
			Success: true,
			Message: "Mahsulot o'chirildi",
		})
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Mahsulot topilmadi",
		})
	}
}

// ================= USERS ROUTES =================

// GET /api/users
func getUsersHandler(w http.ResponseWriter, r *http.Request) {
	var userList []UserProfile
	for _, user := range users {
		profile := UserProfile{
			ID:      user.ID,
			Name:    user.Name,
			Phone:   user.Phone,
			IsAdmin: user.IsAdmin,
		}
		if user.FilialID > 0 {
			if filial := findFilialByID(user.FilialID); filial != nil {
				profile.Filial = *filial
			}
		}
		userList = append(userList, profile)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Foydalanuvchilar",
		Data:    userList,
	})
}

// GET /api/users/{id}
func getUserHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Invalid user ID",
		})
		return
	}

	user := GetUserByID(uint(id))
	if user == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "User topilmadi",
		})
		return
	}

	profile := UserProfile{
		ID:      user.ID,
		Name:    user.Name,
		Phone:   user.Phone,
		IsAdmin: user.IsAdmin,
	}
	if user.FilialID > 0 {
		if filial := findFilialByID(user.FilialID); filial != nil {
			profile.Filial = *filial
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "User",
		Data:    profile,
	})
}

// PUT /api/users/{id}
// Sizning handleringizni to‘liq ishlaydigan ko‘rinishi
func updateUserHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Invalid user ID",
		})
		return
	}

	var req UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Invalid JSON",
		})
		return
	}

	user := UpdateUser(uint(id), req)
	if user == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "User topilmadi",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "User yangilandi",
		Data:    user,
	})
}

// DELETE /api/users/{id}
func deleteUserHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Invalid user ID",
		})
		return
	}

	if DeleteUser(uint(id)) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(Response{
			Success: true,
			Message: "User o'chirildi",
		})
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "User topilmadi",
		})
	}
}

// PUT /api/users/{id}/assign-filial
func assignFilialHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Invalid user ID",
		})
		return
	}

	var req AssignFilialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Invalid JSON",
		})
		return
	}

	user := AssignUserFilial(uint(id), req.FilialID)
	if user == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "User topilmadi",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Filial belgilandi",
	})
}

// ================= ORDERS ROUTES =================

// GET /api/orders (User o'z orderlarini ko'radi, Admin barcha orderlarni)
func getOrdersHandler(w http.ResponseWriter, r *http.Request) {
	userIDStr := r.Header.Get("User-ID")
	userID, _ := strconv.Atoi(userIDStr)
	isAdmin := r.Header.Get("User-IsAdmin") == "true"

	var filteredOrders []Order

	if isAdmin {
		filteredOrders = GetAllOrders()
	} else {
		filteredOrders = GetOrdersByUserID(uint(userID))
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Orderlar",
		Data:    filteredOrders,
	})
}

// GET /api/orders/{id}
func getOrderHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Invalid order ID",
		})
		return
	}

	order := GetOrderByID(uint(id))
	if order == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Order topilmadi",
		})
		return
	}

	// Faqat admin yoki order egasi ko'ra oladi
	userIDStr := r.Header.Get("User-ID")
	userID, _ := strconv.Atoi(userIDStr)
	isAdmin := r.Header.Get("User-IsAdmin") == "true"

	if !isAdmin && order.UserID != uint(userID) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Bu orderni ko'rish huquqingiz yo'q",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Order",
		Data:    order,
	})
}

// POST /api/orders
func createOrderHandler(w http.ResponseWriter, r *http.Request) {
	userIDStr := r.Header.Get("User-ID")
	userID, _ := strconv.Atoi(userIDStr)

	var req CreateOrderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Invalid JSON",
		})
		return
	}

	if len(req.Items) == 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Order bo'sh bo'lishi mumkin emas",
		})
		return
	}

	order, err := CreateOrder(uint(userID), req)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: err.Error(),
		})
		return
	}

	// Order yaratilganidan keyin printerga yuborish
	order.Status = "confirmed"
	printErr := sendToPrinter(order)

	var response Response
	var statusCode int

	if printErr != nil {
		if orderPtr := findOrderByID(order.ID); orderPtr != nil {
			orderPtr.Status = "print_error"
			orderPtr.Updated = time.Now()
			saveData()
		}

		statusCode = http.StatusInternalServerError
		response = Response{
			Success: false,
			Message: fmt.Sprintf("Order yaratildi lekin chek yuborilmadi (%s - %s)", order.Username, order.FilialName),
			Data:    order,
		}
	} else {
		if orderPtr := findOrderByID(order.ID); orderPtr != nil {
			orderPtr.Comment = order.Comment
			orderPtr.Status = "sent_to_printer"
			orderPtr.Updated = time.Now()
			saveData()
		}

		statusCode = http.StatusOK
		response = Response{
			Success: true,
			Comment: order.Comment,
			Message: fmt.Sprintf("Order yaratildi va chek yuborildi (%s - %s) - Order ID: %s", order.Username, order.FilialName, order.OrderID),
			Data:    order,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}

// PUT /api/orders/{id}
func updateOrderHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Invalid order ID",
		})
		return
	}

	var req UpdateOrderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Invalid JSON",
		})
		return
	}

	order := UpdateOrder(uint(id), req)
	if order == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Order topilmadi",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Order yangilandi",
		Data:    order,
	})
}

// DELETE /api/orders/{id}
func deleteOrderHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Invalid order ID",
		})
		return
	}

	if DeleteOrder(uint(id)) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(Response{
			Success: true,
			Message: "Order o'chirildi",
		})
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Order topilmadi",
		})
	}
}

// GET /api/orderslist (Admin uchun filter bilan orderlarni ko'rish)
func getOrdersListHandler(w http.ResponseWriter, r *http.Request) {
	filialID := r.URL.Query().Get("filial_id")
	status := r.URL.Query().Get("status")
	date := r.URL.Query().Get("date")

	filteredOrders := GetFilteredOrders(filialID, status, date)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: fmt.Sprintf("Jami %d ta order topildi", len(filteredOrders)),
		Data:    filteredOrders,
	})
}
