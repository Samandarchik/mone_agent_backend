package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"
)

type CategoryItem struct {
	ID         uint   `json:"id"`
	CategoryID uint   `json:"category_id"`
	Name       string `json:"name"`
}

var (
	categoryItems      []CategoryItem
	nextCategoryItemID uint = 1
)

const categoryItemsFile = "data/category_items.json"

// Global data
var (
	filials    []Filial
	categories []Category
	users      []User
	products   []Product
	orders     []Order

	nextFilialID   uint = 1
	nextCategoryID uint = 1
	nextUserID     uint = 1
	nextProductID  uint = 1
	nextOrderID    uint = 1

	// Kunlik order counter
	dailyOrderCounter = make(map[string]uint)
)

// File paths
const (
	dataDir        = "data"
	filialsFile    = "data/filials.json"
	categoriesFile = "data/categories.json"
	usersFile      = "data/users.json"
	productsFile   = "data/products.json"
	ordersFile     = "data/orders.json"
)

// Data initialization
func initData() {
	fmt.Println("📂 Ma'lumotlar yuklanmoqda...")
	os.MkdirAll(dataDir, 0755)
	loadData()
}

func loadData() {
	loadFilials()
	loadCategories()
	loadUsers()
	loadProducts()
	loadOrders()
	loadCategoryItems()

	fmt.Printf("✅ Ma'lumotlar yuklandi:\n")
	fmt.Printf("   📍 Filiallar: %d ta\n", len(filials))
	fmt.Printf("   📂 Kategoriyalar: %d ta\n", len(categories))
	fmt.Printf("   📂 CategoryItems: %d ta\n", len(categoryItems))
	fmt.Printf("   👥 Userlar: %d ta\n", len(users))
	fmt.Printf("   📦 Mahsulotlar: %d ta\n", len(products))
	fmt.Printf("   📋 Orderlar: %d ta\n", len(orders))
}

func loadFilials() {
	if data, err := ioutil.ReadFile(filialsFile); err == nil {
		json.Unmarshal(data, &filials)
		for _, f := range filials {
			if f.ID >= nextFilialID {
				nextFilialID = f.ID + 1
			}
		}
	}
}

func loadCategories() {
	if data, err := ioutil.ReadFile(categoriesFile); err == nil {
		json.Unmarshal(data, &categories)
		for _, c := range categories {
			if c.ID >= nextCategoryID {
				nextCategoryID = c.ID + 1
			}
		}
	}
}

func loadUsers() {
	if data, err := ioutil.ReadFile(usersFile); err == nil {
		json.Unmarshal(data, &users)
		for _, u := range users {
			if u.ID >= nextUserID {
				nextUserID = u.ID + 1
			}
		}
	}
}

func loadProducts() {
	if data, err := ioutil.ReadFile(productsFile); err == nil {
		json.Unmarshal(data, &products)
		for _, p := range products {
			if p.ID >= nextProductID {
				nextProductID = p.ID + 1
			}
		}
	}
}

func loadOrders() {
	if data, err := ioutil.ReadFile(ordersFile); err == nil {
		json.Unmarshal(data, &orders)
		for _, o := range orders {
			if o.ID >= nextOrderID {
				nextOrderID = o.ID + 1
			}

			// Kunlik counter ni qayta tiklash
			if o.OrderID != "" {
				parts := strings.Split(o.OrderID, "-")
				if len(parts) == 4 {
					dateStr := strings.Join(parts[:3], "-")
					orderNum, _ := strconv.Atoi(parts[3])
					if uint(orderNum) > dailyOrderCounter[dateStr] {
						dailyOrderCounter[dateStr] = uint(orderNum)
					}
				}
			}
		}
	}
}

func saveData() {
	saveFilials()
	saveCategories()
	saveUsers()
	saveProducts()
	saveOrders()
}

func saveFilials() {
	data, _ := json.MarshalIndent(filials, "", "  ")
	ioutil.WriteFile(filialsFile, data, 0644)
}

func saveCategories() {
	data, _ := json.MarshalIndent(categories, "", "  ")
	ioutil.WriteFile(categoriesFile, data, 0644)
}

func saveUsers() {
	data, _ := json.MarshalIndent(users, "", "  ")
	ioutil.WriteFile(usersFile, data, 0644)
}

func saveProducts() {
	data, _ := json.MarshalIndent(products, "", "  ")
	ioutil.WriteFile(productsFile, data, 0644)
}

func saveOrders() {
	data, _ := json.MarshalIndent(orders, "", "  ")
	ioutil.WriteFile(ordersFile, data, 0644)
}

// Order ID generator
func generateOrderID() string {
	now := time.Now()
	dateStr := now.Format("06-01-02") // YY-MM-DD format

	if _, exists := dailyOrderCounter[dateStr]; !exists {
		dailyOrderCounter[dateStr] = 0
	}
	dailyOrderCounter[dateStr]++

	return fmt.Sprintf("%s-%d", dateStr, dailyOrderCounter[dateStr])
}

// Helper functions
func findUserByPhone(phone string) *User {
	for i, u := range users {
		if u.Phone == phone {
			return &users[i]
		}
	}
	return nil
}

func findUserByID(id uint) *User {
	for i, u := range users {
		if u.ID == id {
			return &users[i]
		}
	}
	return nil
}

func findFilialByID(id uint) *Filial {
	for i, f := range filials {
		if f.ID == id {
			return &filials[i]
		}
	}
	return nil
}

func findCategoryByID(id uint) *Category {
	for i, c := range categories {
		if c.ID == id {
			return &categories[i]
		}
	}
	return nil
}

func findProductByID(id uint) *Product {
	for i, p := range products {
		if p.ID == id {
			return &products[i]
		}
	}
	return nil
}

func findOrderByID(id uint) *Order {
	for i, o := range orders {
		if o.ID == id {
			return &orders[i]
		}
	}
	return nil
}

// CRUD Operations

// ============= FILIALS =============
func CreateFilial(req AddFilialRequest) Filial {
	filial := Filial{
		ID:       nextFilialID,
		Name:     req.Name,
		Location: req.Location,
	}
	filials = append(filials, filial)
	nextFilialID++
	saveFilials()
	return filial
}

func GetAllFilials() []Filial {
	return filials
}

func GetFilialByID(id uint) *Filial {
	return findFilialByID(id)
}

func UpdateFilial(id uint, req UpdateFilialRequest) *Filial {
	filial := findFilialByID(id)
	if filial == nil {
		return nil
	}
	filial.Name = req.Name
	filial.Location = req.Location
	saveFilials()
	return filial
}

func DeleteFilial(id uint) bool {
	for i, f := range filials {
		if f.ID == id {
			filials = append(filials[:i], filials[i+1:]...)
			saveFilials()
			return true
		}
	}
	return false
}

// ============= CATEGORIES =============
func CreateCategory(req AddCategoryRequest) Category {
	category := Category{
		ID:       nextCategoryID,
		Name:     req.Name,
		Printer:  req.Printer,
		ImageUrl: req.ImageUrl,
	}
	categories = append(categories, category)
	nextCategoryID++
	saveCategories()
	return category
}

func GetAllCategories() []Category {
	return categories
}

//	func GetProductsByCategoryID(categoryID uint) []Product {
//		var categoryProducts []Product
//		for _, p := range products {
//			if p.CategoryID == categoryID {
//				categoryProducts = append(categoryProducts, p)
//			}
//		}
//		return categoryProducts
//	}
func GetCategoryByID(id uint) *Category {
	return findCategoryByID(id)
}

func UpdateCategory(id uint, req UpdateCategoryRequest) *Category {
	category := findCategoryByID(id)
	if category == nil {
		return nil
	}

	// agar name kelgan bo‘lsa o‘zgartiramiz
	if req.Name != nil {
		category.Name = *req.Name
	}

	// agar printer kelgan bo‘lsa o‘zgartiramiz
	if req.Printer != nil {
		category.Printer = *req.Printer
	}
	if req.ImageUrl != nil {
		category.ImageUrl = *req.ImageUrl
	}

	saveCategories()
	return category
}

func DeleteCategory(id uint) bool {
	for i, c := range categories {
		if c.ID == id {
			categories = append(categories[:i], categories[i+1:]...)
			saveCategories()
			return true
		}
	}
	return false
}
func DeleteCategoryWithProducts(categoryID uint) bool {
	// 1. Kategoriyaga tegishli mahsulotlarni o'chirish
	var remainingProducts []Product
	for _, p := range products {
		if p.CategoryID != categoryID {
			remainingProducts = append(remainingProducts, p)
		}
	}
	products = remainingProducts
	saveProducts()

	// 2. Kategoriyani o'chirish
	for i, c := range categories {
		if c.ID == categoryID {
			categories = append(categories[:i], categories[i+1:]...)
			saveCategories()
			return true
		}
	}
	return false
}

// ============= PRODUCTS =============
func CreateProduct(req AddProductRequest) Product {
	product := Product{
		ID:          nextProductID,
		Name:        req.Name,
		Type:        req.Type,
		CategoryID:  req.CategoryID,
		ImageUrl:    req.ImageUrl,
		Ingredients: req.Ingredients,
		Filials:     req.Filials,
	}
	products = append(products, product)
	nextProductID++
	saveProducts()
	return product
}

func GetAllProducts() []Product {
	return products
}

func GetProductByID(id uint) *Product {
	return findProductByID(id)
}

func UpdateProduct(id uint, req UpdateProductRequest) *Product {
	product := findProductByID(id)
	if product == nil {
		return nil
	}
	product.Name = req.Name
	product.Type = req.Type
	product.CategoryID = req.CategoryID
	product.Ingredients = req.Ingredients
	product.ImageUrl = req.ImageUrl
	product.Filials = req.Filials
	saveProducts()
	return product
}

func DeleteProduct(id uint) bool {
	for i, p := range products {
		if p.ID == id {
			products = append(products[:i], products[i+1:]...)
			saveProducts()
			return true
		}
	}
	return false
}

// ================= CATEGORY ITEMS =================
func loadCategoryItems() {
	if data, err := ioutil.ReadFile(categoryItemsFile); err == nil {
		json.Unmarshal(data, &categoryItems)
		for _, ci := range categoryItems {
			if ci.ID >= nextCategoryItemID {
				nextCategoryItemID = ci.ID + 1
			}
		}
	}
}

func saveCategoryItems() {
	data, _ := json.MarshalIndent(categoryItems, "", "  ")
	ioutil.WriteFile(categoryItemsFile, data, 0644)
}

// --- Helpers ---
func findCategoryItemByID(id uint) *CategoryItem {
	for i, ci := range categoryItems {
		if ci.ID == id {
			return &categoryItems[i]
		}
	}
	return nil
}

// --- CRUD ---
// Create
func CreateCategoryItem(categoryID uint, name string) *CategoryItem {
	// category mavjudligini tekshiramiz
	if findCategoryByID(categoryID) == nil {
		fmt.Println("❌ Bunday category mavjud emas")
		return nil
	}

	item := CategoryItem{
		ID:         nextCategoryItemID,
		CategoryID: categoryID,
		Name:       name,
	}
	categoryItems = append(categoryItems, item)
	nextCategoryItemID++
	saveCategoryItems()
	return &item
}

// Get all
func GetAllCategoryItems() []CategoryItem {
	return categoryItems
}

// Get by ID
func GetCategoryItemByID(id uint) *CategoryItem {
	return findCategoryItemByID(id)
}

// Get by CategoryID
func GetCategoryItemsByCategoryID(categoryID uint) []CategoryItem {
	var items []CategoryItem
	for _, ci := range categoryItems {
		if ci.CategoryID == categoryID {
			items = append(items, ci)
		}
	}
	return items
}

// Update
func UpdateCategoryItem(id uint, newName string) *CategoryItem {
	item := findCategoryItemByID(id)
	if item == nil {
		return nil
	}
	item.Name = newName
	saveCategoryItems()
	return item
}

// Delete
func DeleteCategoryItem(id uint) bool {
	for i, ci := range categoryItems {
		if ci.ID == id {
			categoryItems = append(categoryItems[:i], categoryItems[i+1:]...)
			saveCategoryItems()
			return true
		}
	}
	return false
}

// ============= USERS =============
func CreateUser(req RegisterUserRequest) User {
	hashedPassword, _ := hashPassword(req.Password)
	user := User{
		ID:       nextUserID,
		Name:     req.Name,
		Phone:    req.Phone,
		Password: hashedPassword,
		IsAdmin:  false,
		FilialID: uint(req.FilialID),
	}
	users = append(users, user)
	nextUserID++
	saveUsers()
	return user
}

func GetAllUsers() []User {
	return users
}

func GetUserByID(id uint) *User {
	return findUserByID(id)
}

func UpdateUser(id uint, req UpdateUserRequest) *User {
	user := findUserByID(id)
	if user == nil {
		return nil
	}

	// Faqat kelgan fieldlarni yangilaymiz
	if req.Name != nil {
		user.Name = *req.Name
	}
	if req.Phone != nil {
		user.Phone = *req.Phone
	}
	if req.CategoryID != nil {
		user.CategoryID = *req.CategoryID
	}
	if req.Password != nil {
		hashedPassword, _ := hashPassword(*req.Password)
		user.Password = hashedPassword
	}
	if req.IsAdmin != nil {
		user.IsAdmin = *req.IsAdmin
	}
	if req.FilialID != nil {
		user.FilialID = *req.FilialID
	}

	saveUsers() // saqlash
	return user
}

func DeleteUser(id uint) bool {
	for i, u := range users {
		if u.ID == id {
			users = append(users[:i], users[i+1:]...)
			saveUsers()
			return true
		}
	}
	return false
}

func AssignUserFilial(userID uint, filialID uint) *User {
	user := findUserByID(userID)
	if user == nil {
		return nil
	}
	user.FilialID = filialID
	saveUsers()
	return user
}

// ============= ORDERS =============
func CreateOrder(userID uint, req CreateOrderRequest) (*Order, error) {
	user := findUserByID(userID)
	if user == nil {
		return nil, fmt.Errorf("user topilmadi")
	}

	if user.FilialID == 0 {
		return nil, fmt.Errorf("sizga filial belgilanmagan")
	}

	filial := findFilialByID(user.FilialID)
	if filial == nil {
		return nil, fmt.Errorf("filial topilmadi")
	}

	order := Order{
		ID:         nextOrderID,
		OrderID:    generateOrderID(),
		Comment:    req.Comment,
		SentDataTime: req.SentDataTime,
		UserID:     userID,
		Username:   user.Name,
		FilialID:   user.FilialID,
		FilialName: filial.Name,
		Items:      []OrderItem{},
		Total:      0,
		Status:     "pending",
		Created:    time.Now(),
		Updated:    time.Now(),
	}

	for _, reqItem := range req.Items {
		product := findProductByID(reqItem.ProductID)
		if product == nil {
			return nil, fmt.Errorf("mahsulot topilmadi: ID %d", reqItem.ProductID)
		}

		// Mahsulot bu filialda mavjudligini tekshirish
		productAvailable := false
		for _, fId := range product.Filials {
			if fId == user.FilialID {
				productAvailable = true
				break
			}
		}

		if !productAvailable {
			return nil, fmt.Errorf("mahsulot %s bu filialda mavjud emas", product.Name)
		}

		if reqItem.Count <= 0 {
			return nil, fmt.Errorf("mahsulot soni 0 dan katta bo'lishi kerak")
		}

		orderItem := OrderItem{
			ProductID: reqItem.ProductID,
			Name:      product.Name,
			Type:      product.Type,
			Count:     reqItem.Count,
		}

		order.Items = append(order.Items, orderItem)
	}

	orders = append(orders, order)
	nextOrderID++
	saveOrders()

	return &order, nil
}

func GetAllOrders() []Order {
	return orders
}

func GetOrderByID(id uint) *Order {
	return findOrderByID(id)
}

func GetOrdersByUserID(userID uint) []Order {
	var userOrders []Order
	for _, order := range orders {
		if order.UserID == userID {
			userOrders = append(userOrders, order)
		}
	}
	return userOrders
}

func UpdateOrder(id uint, req UpdateOrderRequest) *Order {
	order := findOrderByID(id)
	if order == nil {
		return nil
	}
	order.Status = req.Status
	order.Updated = time.Now()
	saveOrders()
	return order
}

func DeleteOrder(id uint) bool {
	for i, o := range orders {
		if o.ID == id {
			orders = append(orders[:i], orders[i+1:]...)
			saveOrders()
			return true
		}
	}
	return false
}

func GetFilteredOrders(filialID string, status string, date string) []Order {
	var filteredOrders []Order

	for _, order := range orders {
		// Filial bo'yicha filter
		if filialID != "" {
			fID, err := strconv.Atoi(filialID)
			if err == nil && order.FilialID != uint(fID) {
				continue
			}
		}

		// Status bo'yicha filter
		if status != "" && order.Status != status {
			continue
		}

		// Sana bo'yicha filter
		if date != "" {
			orderDate := order.Created.Format("2006-01-02")
			if orderDate != date {
				continue
			}
		}

		filteredOrders = append(filteredOrders, order)
	}

	// Eng yangi buyurtmalar birinchi
	for i := 0; i < len(filteredOrders)-1; i++ {
		for j := 0; j < len(filteredOrders)-i-1; j++ {
			if filteredOrders[j].Created.Before(filteredOrders[j+1].Created) {
				filteredOrders[j], filteredOrders[j+1] = filteredOrders[j+1], filteredOrders[j]
			}
		}
	}

	return filteredOrders
}
