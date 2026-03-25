package strings

import (
	"strings"
	"unicode"
)

func RemoveWhitespaces(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
}
