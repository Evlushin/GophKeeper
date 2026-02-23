package handlerauth

import (
	"context"
	"errors"
	"github.com/Evlushin/GophKeeper/internal/myerrors"
	"github.com/Evlushin/GophKeeper/internal/server/codec"
	"github.com/Evlushin/GophKeeper/internal/server/handler/config"
	"github.com/Evlushin/GophKeeper/internal/server/models"
	utils "github.com/Evlushin/GophKeeper/internal/server/utils/auth"
	"github.com/Evlushin/GophKeeper/internal/validator"
	"go.uber.org/zap"
	"log"
	"net/http"
)

type UserLoginer interface {
	Login(ctx context.Context, login string, password string) (*models.User, string, error)
}

// HandleLogin handles the HTTP request for user authentication.
// Endpoint: POST /api/user/login
// Request Body: JSON encoded models.AuthRequest
//
//	{
//	  "login": "string, required, email or username",
//	  "password": "string, required, min 8 characters"
//	}
//
// Behavior:
//   - Validates request JSON structure and field constraints
//   - Authenticates user credentials against the database
//   - Generates JWT token on successful authentication
//   - Sets HTTP-only secure cookie with the token (if cfg.UseCookieAuth)
//
// Returns:
//   - HTTP 200 OK with JSON models.AuthResponse {UserID, Login, Token}
//   - HTTP 400 Bad Request on JSON decode error or validation failure
//   - HTTP 401 Unauthorized on invalid login/password combination
//   - HTTP 500 Internal Server Error on database or token generation failure
//
// Security:
//   - Passwords are never logged or returned in responses
//   - Uses constant-time comparison for credential validation
//   - Token cookie configured with HttpOnly, Secure, SameSite flags
func HandleLogin(cfg *config.Config, l *zap.Logger, auth UserLoginer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		creds, err := codec.Decode[models.AuthRequest](r)
		if err != nil {
			l.Debug("decode json request", zap.Error(err))
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		_, err = validator.IsValid(creds)
		if err != nil {
			l.Debug("check validity", zap.Error(err))
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		user, token, err := auth.Login(context.Background(), creds.Login, creds.Password)
		if err != nil {
			if errors.Is(err, myerrors.ErrInvalidCredentials) {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			l.Error("login user via service", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		utils.SetAuthCookie(cfg, w, token)

		if err = codec.Encode(w, http.StatusOK, models.AuthResponse{
			UserID: uint(user.ID),
			Login:  user.Login,
			Token:  token,
		}); err != nil {
			log.Printf("Error encoding response: %v", err)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
	}
}
