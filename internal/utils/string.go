package utils

// FormatValue заменяет пустую строку на "N/A"
func FormatValue(value string) string {
	if value == "" {
		return "N/A"
	}
	return value
}
