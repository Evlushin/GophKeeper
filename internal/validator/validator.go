package validator

import (
	"errors"
	"fmt"
)

var ErrTypeInvalid = errors.New("invalid type")

// Validator is an object that can be validated.
type Validator interface {
	// Valid checks the object and returns any
	// problems. If len(problems) == 0 then
	// the object is valid.
	Valid() (problems Problems)
}

type Problems map[string]string

func IsValid[T Validator](v T) (Problems, error) {
	problems := v.Valid()
	if len(problems) > 0 {
		err := fmt.Errorf("%w: type %T has %d problems", ErrTypeInvalid, v, len(problems))
		return problems, err
	}
	return problems, nil
}
