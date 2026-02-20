package middleware

import (
	"context"
	"github.com/Evlushin/GophKeeper/internal/server/handler/config"
	"github.com/Evlushin/GophKeeper/internal/server/models"
	utils "github.com/Evlushin/GophKeeper/internal/server/utils/auth"
	"go.uber.org/zap"
	"net/http"
)

type AuthUserValidator interface {
	ValidateUser(ctx context.Context, userID models.UserID) (*models.User, error)
	ValidateToken(token string) (models.UserID, error)
}

func NewAuth(
	cfg *config.Config,
	logger *zap.Logger,
	auth AuthUserValidator,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := r.Header.Get("X-API-Token")

			if token == "" {
				cookie, err := r.Cookie(cfg.AuthCookieName)
				if err != nil {
					logger.Debug("no auth cookie", zap.Error(err))
					w.WriteHeader(http.StatusUnauthorized)
					return
				}

				token = cookie.Value
				if token == "" {
					logger.Debug("empty auth cookie", zap.Error(err))
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
			}

			userID, err := auth.ValidateToken(token)
			if err != nil {
				logger.Debug("invalid auth token", zap.Error(err))
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			user, err := auth.ValidateUser(context.Background(), userID)
			if err != nil {
				logger.Debug("invalid user", zap.Error(err))
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			ctx := utils.WithUser(r.Context(), user.ID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
