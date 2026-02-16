package models

import "github.com/Evlushin/GophKeeper/internal/client/validator"

type LoginRequest struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

func (r LoginRequest) Valid() validator.Problems {
	problems := make(validator.Problems)

	if r.Login == "" {
		problems["login"] = "login is required"
	}

	if r.Password == "" {
		problems["password"] = "password is required"
	}

	return problems
}

type RegisterRequest struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

func (r RegisterRequest) Valid() validator.Problems {
	problems := make(validator.Problems)

	if r.Login == "" {
		problems["login"] = "login is required"
	}

	if r.Password == "" {
		problems["password"] = "password is required"
	}

	return problems
}
