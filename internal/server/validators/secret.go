package validators

import (
	"fmt"
	"github.com/Evlushin/GophKeeper/internal/server/models"
	utils "github.com/Evlushin/GophKeeper/internal/server/utils/strings"
	"io"
	"net/http"
)

type StoreSecretWrapper struct {
	*models.StoreSecret
}

func (o *StoreSecretWrapper) Valid(r *http.Request) (map[string]map[string]string, error) {
	problems := make(map[string]map[string]string)

	// 1. Чтение тела запроса
	body, err := readRequestBody(r)
	if err != nil {
		return nil, fmt.Errorf("reading request body: %w", err)
	}

	// 2. Очистка и проверка номера
	number := utils.RemoveWhitespaces(string(body))
	numberProblems := validateNumberOrder(number)

	// 3. Добавление проблем, если есть
	if len(numberProblems) > 0 {
		problems["number"] = numberProblems
	}

	// 4. Установка значения, если валидно
	if len(problems) == 0 {
		o.Number = number
	}

	return problems, nil
}

func readRequestBody(r *http.Request) ([]byte, error) {
	defer func() {
		_ = r.Body.Close() // Гарантированное закрытие, игнорируем ошибку
	}()

	body, err := io.ReadAll(io.LimitReader(r.Body, 1024))
	if err != nil {
		return nil, fmt.Errorf("reading request body: %w", err)
	}
	return body, nil
}

func validateNumberOrder(number string) map[string]string {
	problems := make(map[string]string)

	if number == "" {
		problems["required"] = "number is required"
		return problems
	}

	if !validator.IsNumericRegex(number) {
		problems["is_numeric"] = "number must contain only digits"
	}

	if !validator.IsValidLuhn(number) {
		problems["is_valid"] = "the number is not valid according to the Luhn algorithm"
	}

	return problems
}
