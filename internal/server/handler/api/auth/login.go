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

//nolint:dupl // register and login are different business processes with possible same structure
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
