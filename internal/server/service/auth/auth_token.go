package auth

import (
	"errors"
	"fmt"
	"github.com/Evlushin/GophKeeper/internal/server/handler/config"
	"github.com/Evlushin/GophKeeper/internal/server/models"
	"github.com/golang-jwt/jwt/v4"
	"time"
)

var (
	ErrInvalidToken            = errors.New("invalid token")
	ErrUnexpectedSigningMethod = errors.New("unexpected signing method")
)

type claims struct {
	jwt.RegisteredClaims
	UserID models.UserID `json:"user_id"`
}

type AuthToken struct {
	secret []byte
	ttl    time.Duration
}

func NewAuthToken(cfg *config.Config) *AuthToken {
	return &AuthToken{
		secret: []byte(cfg.AuthSecretKey),
		ttl:    cfg.AuthExpireDuration,
	}
}

func (s *AuthToken) Generate(userID models.UserID) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.ttl)),
		},
	})

	tokenString, err := token.SignedString(s.secret)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}

	return tokenString, nil
}

func (s *AuthToken) Parse(tokenString string) (models.UserID, error) {
	token, err := jwt.ParseWithClaims(tokenString, &claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("%w: %v", ErrUnexpectedSigningMethod, t.Header["alg"])
		}
		return s.secret, nil
	})

	if err != nil {
		return 0, ErrInvalidToken
	}

	claims, ok := token.Claims.(*claims)
	if !ok || !token.Valid {
		return 0, ErrInvalidToken
	}

	return claims.UserID, nil
}
