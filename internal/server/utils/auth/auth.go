package auth

import (
	"context"
	"errors"
	"fmt"
	"github.com/Evlushin/GophKeeper/internal/server/handler/config"
	"github.com/Evlushin/GophKeeper/internal/server/models"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"time"
)

var (
	ErrUserNotFoundInContext       = errors.New("user not found in context")
	ErrUnexpectedUserTypeInContext = errors.New("unexpected user type in context")
)

type userCtxKey struct{}

func WithUser(ctx context.Context, userID models.UserID) context.Context {
	return context.WithValue(ctx, userCtxKey{}, userID)
}

func GetCtxUserID(ctx context.Context) (models.UserID, error) {
	value := ctx.Value(userCtxKey{})
	if value == nil {
		return 0, ErrUserNotFoundInContext
	}

	if userID, ok := value.(models.UserID); ok {
		return userID, nil
	}
	return 0, fmt.Errorf("%w: %T", ErrUnexpectedUserTypeInContext, value)
}

func SetAuthCookie(cfg *config.Config, w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.AuthCookieName,
		Value:    token,
		Expires:  time.Now().Add(cfg.AuthExpireDuration),
		HttpOnly: true,
	})
}

func HashPassword(password string) (string, error) {
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(hashedBytes), nil
}

func VerifyPassword(hashedPassword, password string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		return fmt.Errorf("compare hash and password: %w", err)
	}
	return nil
}
