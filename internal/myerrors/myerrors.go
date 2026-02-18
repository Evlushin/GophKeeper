package myerrors

import "errors"

var (
	ErrGetSecretNotFound    = errors.New("no secret")
	ErrInvalidRequest       = errors.New("error request")
	ErrConfigIsNil          = errors.New("config is nil")
	ErrNoFilePath           = errors.New("secret file path is empty")
	ErrSecretAlreadyDeleted = errors.New("secret already deleted")
	ErrNoReader             = errors.New("reader is nil")
	ErrUserAlreadyExists    = errors.New("user already exists")
	ErrInvalidCredentials   = errors.New("invalid credentials")
	ErrUserNotFound         = errors.New("user not found")
)
