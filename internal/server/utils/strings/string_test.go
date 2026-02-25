package strings

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRemoveWhitespaces_TableDriven(t *testing.T) {
	testCases := map[string]struct {
		input    string
		expected string
	}{
		"empty string":                   {"", ""},
		"no whitespaces":                 {"HelloWorld", "HelloWorld"},
		"spaces only":                    {"   ", ""},
		"spaces in between":              {"Hello World", "HelloWorld"},
		"multiple spaces":                {"Hello    World", "HelloWorld"},
		"tabs":                           {"Hello\tWorld", "HelloWorld"},
		"newlines":                       {"Hello\nWorld", "HelloWorld"},
		"carriage return":                {"Hello\rWorld", "HelloWorld"},
		"mixed whitespaces":              {"Hello \t\n\r World", "HelloWorld"},
		"whitespaces at start and end":   {"  Hello World  ", "HelloWorld"},
		"with numbers and special chars": {"Hello 123 !@# World", "Hello123!@#World"},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			result := RemoveWhitespaces(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}
