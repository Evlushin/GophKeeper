package validators

import (
	"fmt"
	"net/http"
	"strings"
)

type Validator interface {
	Valid(r *http.Request) (map[string]map[string]string, error)
}

func Decode(r *http.Request, v Validator) (map[string]map[string]string, error) {
	problems, err := v.Valid(r)
	if err != nil {
		return nil, fmt.Errorf("check valid on request: %w", err)
	}

	if len(problems) > 0 {
		return problems, nil
	}

	return nil, nil
}

func ValidErrToStr(errors map[string]map[string]string) string {
	result := ""
	for property, e := range errors {
		for key, value := range e {
			result += fmt.Sprintf("%s: %s: %s\n", property, key, value)
		}
	}
	return strings.TrimSuffix(result, "\n")
}
