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
	"net/http"
)

type UserRegisterer interface {
	Register(ctx context.Context, login, password string) (*models.User, string, error)
}

// HandleRegister handles the HTTP request for new user registration.
// Endpoint: POST /api/user/register
// Request Body: JSON encoded models.AuthRequest
//
//	{
//	  "login": "string, required, unique, valid email format",
//	  "password": "string, required, min 8 characters with complexity"
//	}
//
// Behavior:
//   - Validates request JSON structure and field constraints
//   - Checks for existing user with the same login (unique constraint)
//   - Hashes password using bcrypt before storage
//   - Generates JWT token for immediate authentication after registration
//   - Sets HTTP-only secure cookie with the token (if cfg.UseCookieAuth)
//
// Returns:
//   - HTTP 200 OK with JSON models.AuthResponse {UserID, Login, Token}
//   - HTTP 400 Bad Request on JSON decode error or validation failure
//   - HTTP 409 Conflict if user with given login already exists
//   - HTTP 500 Internal Server Error on database or hashing failure
//
// Security:
//   - Passwords are hashed with bcrypt (cost factor from config) before storage
//   - Registration rate limiting recommended at middleware level
//   - Consider adding email verification flow for production use
func HandleRegister(cfg *config.Config, l *zap.Logger, reg UserRegisterer) http.HandlerFunc {
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

		user, token, err := reg.Register(r.Context(), creds.Login, creds.Password)
		if err != nil {
			if errors.Is(err, myerrors.ErrUserAlreadyExists) {
				w.WriteHeader(http.StatusConflict)
				return
			}

			l.Error("register user via service", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		utils.SetAuthCookie(cfg, w, token)

		if err = codec.Encode(w, http.StatusOK, models.AuthResponse{
			UserID: uint(user.ID),
			Login:  user.Login,
			Token:  token,
		}); err != nil {
			l.Error("encoding response", zap.Error(err))
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
	}
}
