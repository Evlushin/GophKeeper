package auth

import (
	"github.com/Evlushin/GophKeeper/internal/server/handler/config"
	"github.com/Evlushin/GophKeeper/internal/server/models"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const testSecret = "test-secret"

func newAuthToken(secret string, ttl time.Duration) *AuthToken {
	cfg := &config.Config{
		AuthConfig: config.AuthConfig{
			AuthSecretKey:      secret,
			AuthExpireDuration: ttl,
		},
	}
	return NewAuthToken(cfg)
}

func TestAuthToken_GenerateAndParse_Success(t *testing.T) {
	ttl := time.Hour
	auth := newAuthToken(testSecret, ttl)

	userID := models.UserID(42)

	token, err := auth.Generate(userID)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	gotUserID, err := auth.Parse(token)
	require.NoError(t, err)
	require.Equal(t, userID, gotUserID)
}

func TestAuthToken_Parse_InvalidSecret(t *testing.T) {
	secret1 := "secret-1"
	secret2 := "secret-2"

	auth1 := newAuthToken(secret1, time.Hour)
	auth2 := newAuthToken(secret2, time.Hour)

	userID := models.UserID(7)
	token, err := auth1.Generate(userID)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	_, err = auth2.Parse(token)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidToken)
}

func TestAuthToken_Parse_Expired(t *testing.T) {
	auth := newAuthToken(testSecret, -1*time.Second)

	userID := models.UserID(100)
	token, err := auth.Generate(userID)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	_, err = auth.Parse(token)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidToken)
}

func TestAuthToken_Parse_MalformedToken(t *testing.T) {
	auth := newAuthToken(testSecret, time.Hour)

	badJWT := "not-a-jwt"

	_, err := auth.Parse(badJWT)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidToken)
}
