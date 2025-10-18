package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// Telegram message structure
type TelegramMessage struct {
	ChatID    string `json:"chat_id"`
	Text      string `json:"text"`
	ParseMode string `json:"parse_mode"`
}

// Send formatted message to Telegram
func sendToTelegram(order *Order, categoryItems map[uint][]PrinterItem, printerSuccess bool) error {
	user := findUserByID(order.UserID)
	if user == nil {
		return fmt.Errorf("user topilmadi")
	}

	// Format the message
	var message strings.Builder
	message.WriteString("🧾 *НОВЫЙ ПОРЯДОК*\n\n")
	message.WriteString(fmt.Sprintf("📋 *Заказ ID:* `%s`\n", order.OrderID))
	message.WriteString(fmt.Sprintf("👤 *Клиент:* %s\n", order.Username))
	message.WriteString(fmt.Sprintf("🏢 *Ветвь:* %s\n", order.FilialName))
	loc := time.FixedZone("UTC+5", 5*60*60)
	tashkentTime := time.Now().In(loc)
	message.WriteString(fmt.Sprintf("⏰ *Время:* %s\n\n", tashkentTime.Format("2006-01-02 15:04:05")))

	// Printer status at the top
	printerStatusText := "❌ *Невозможно отправить на принтер* @Baxtiyor0055"
	if printerSuccess {
		printerStatusText = "✅ *Отправлено в типографию*"
	}
	message.WriteString(fmt.Sprintf("🖨️ *СТАТУС:* %s\n\n", printerStatusText))

	message.WriteString("📦 *ТОВАРЫ:*\n")

	// Display items grouped by category
	for categoryID, items := range categoryItems {
		category := GetCategoryByID(categoryID)
		if category != nil {
			message.WriteString(fmt.Sprintf("\n🔸 *%s:*\n", category.Name))
			for _, item := range items {
				count := float64(item.Count)
				var formattedCount string

				// Agar butun son bo‘lsa
				if count == float64(int64(count)) {
					formattedCount = fmt.Sprintf("%d", int64(count))
				} else {
					// 3 ta kasr raqamgacha
					formattedCount = fmt.Sprintf("%.3f", count)
					// ortiqcha nol va nuqtani olib tashlash
					formattedCount = strings.TrimRight(strings.TrimRight(formattedCount, "0"), ".")
				}

				message.WriteString(fmt.Sprintf("   • %s - %s %s\n", item.Product, formattedCount, item.Type))
			}
		}
	}

	telegramMsg := TelegramMessage{
		ChatID:    "-4985547344",
		Text:      message.String(),
		ParseMode: "Markdown",
	}

	jsonData, err := json.Marshal(telegramMsg)
	if err != nil {
		log.Printf("Telegram JSON marshal xato: %v", err)
		return err
	}

	telegramURL := "https://api.telegram.org/bot8157743798:AAELzxyyFLSMxbT-XL4l-3ZVmxVBXYOY0Ro/sendMessage"

	resp, err := http.Post(telegramURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Telegram ga yuborishda xato: %v", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		log.Printf("✅ Telegram ga yuborildi: %s", order.OrderID)
	} else {
		log.Printf("❌ Telegram ga yuborishda xato - Status: %d", resp.StatusCode)
		return fmt.Errorf("telegram yuborishda xato: status %d", resp.StatusCode)
	}

	return nil
}

func sendToPrinter(order *Order) error {
	user := findUserByID(order.UserID)
	if user == nil {
		return fmt.Errorf("user topilmadi")
	}

	filial := findFilialByID(order.FilialID)
	if filial == nil {
		return fmt.Errorf("filial topilmadi")
	}

	// Mahsulotlarni kategoriya bo'yicha guruhlash
	categoryItems := make(map[uint][]PrinterItem)

	for _, item := range order.Items {
		product := findProductByID(item.ProductID)
		if product != nil {
			categoryItems[product.CategoryID] = append(categoryItems[product.CategoryID], PrinterItem{
				Product: item.Name,
				Count:   item.Count,
				Type:    item.Type,
			})
		}
	}

	allSuccess := true

	// Har bir printer uchun mahsulotlar va kategoriyalar
	printerItems := make(map[uint][]PrinterItem)
	printerCategories := make(map[uint]map[string]bool) // printerID -> kategoriya nomlari

	for categoryID, items := range categoryItems {
		category := GetCategoryByID(categoryID)
		if category == nil {
			log.Printf("Kategoriya topilmadi: %d", categoryID)
			allSuccess = false
			continue
		}

		printerID := category.Printer
		printerItems[printerID] = append(printerItems[printerID], items...)

		// Kategoriyani printerga bog'lab qo'shamiz
		if printerCategories[printerID] == nil {
			printerCategories[printerID] = make(map[string]bool)
		}
		printerCategories[printerID][category.Name] = true
	}

	// Endi printerID bo'yicha chek yuboramiz
	for printerID, items := range printerItems {
		// Kategoriyalarni ro'yxatga aylantiramiz
		var categoryNames []string
		for name := range printerCategories[printerID] {
			categoryNames = append(categoryNames, name)
		}
		categoryList := strings.Join(categoryNames, ", ")

		printRequest := PrinterRequest{
			Printer:  printerID,
			OrderID:  order.OrderID,
			Category: categoryList, // shu printerga tegishli barcha kategoriyalar
			Username: order.Username,
			Comment:  order.Comment,
			Filial:   order.FilialName,
			Items:    items,
		}

		jsonData, err := json.Marshal(printRequest)
		if err != nil {
			log.Printf("JSON marshal xato: %v", err)
			allSuccess = false
			continue
		}

		resp, err := http.Post("https://marxabo1.javohir-jasmina.uz/print", "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			log.Printf("Printerga yuborishda xato (PrinterID %d): %v", printerID, err)
			allSuccess = false
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			log.Printf("✅ Chek yuborildi: PrinterID %d - %s (%s) | Kategoriyalar: %s",
				printerID, order.Username, order.FilialName, categoryList)
		} else {
			log.Printf("❌ Chek yuborishda xato: PrinterID %d - Status: %d", printerID, resp.StatusCode)
			allSuccess = false
		}
	}

	// Send to Telegram after processing all printers (eski versiya kabi)
	if len(categoryItems) > 0 {
		err := sendToTelegram(order, categoryItems, allSuccess)
		if err != nil {
			log.Printf("Telegram ga yuborishda xato: %v", err)
			// Don't mark as failure since printer might have worked
		}
	}

	if !allSuccess {
		return fmt.Errorf("ba'zi printerlarga yuborishda xatolik bo'ldi")
	}
	return nil
}
