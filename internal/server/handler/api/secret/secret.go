package secret

import (
	"context"
	"encoding/json"
	"github.com/Evlushin/GophKeeper/internal/server/codec"
	"github.com/Evlushin/GophKeeper/internal/server/models"
	utils "github.com/Evlushin/GophKeeper/internal/server/utils/auth"
	"github.com/Evlushin/GophKeeper/internal/validator"
	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
	"log"
	"net/http"
	"time"
)

const defaultCtxTimeout = 60 * time.Second

type Secret interface {
	CountSecret(ctx context.Context, indexSecret models.IndexSecret) (int64, error)
	IndexSecret(ctx context.Context, indexSecret models.IndexSecret) ([]models.SecretData, error)
	StoreSecret(ctx context.Context, storeSecret models.StoreSecret) error
	GetSecret(ctx context.Context, getSecret models.ShowSecret) (*models.SecretData, error)
	UpdateSecret(ctx context.Context, updateSecret models.UpdateSecret) error
	DeleteSecret(ctx context.Context, deleteSecret models.DeleteSecret) error
}

func Index(logger *zap.Logger, secret Secret) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		userID, err := utils.GetCtxUserID(r.Context())
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		queryParams := r.URL.Query()
		t := queryParams.Get("type")
		indexSecret := models.IndexSecret{
			UserID: userID,
			Type:   models.DataType(t),
		}

		ctx, cancel := context.WithTimeout(r.Context(), defaultCtxTimeout)
		defer cancel()

		count, err := secret.CountSecret(ctx, indexSecret)
		if err != nil {
			logger.Error("count secret", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if count < 1 {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		secrets, err := secret.IndexSecret(ctx, indexSecret)
		if err != nil {
			logger.Error("index secret", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		response, err := json.Marshal(secrets)
		if err != nil {
			logger.Error("marshal secrets to json", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		_, err = w.Write(response)
		if err != nil {
			logger.Error("write response", zap.Error(err))
		}
	}
}

func Store(logger *zap.Logger, secret Secret) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, err := utils.GetCtxUserID(r.Context())
		if err != nil {
			writeUnauthorized(w, logger)
			return
		}

		storeSecret, err := codec.Decode[models.StoreSecret](r)
		if err != nil {
			logger.Debug("decode json request", zap.Error(err))
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		_, err = validator.IsValid(storeSecret)
		if err != nil {
			logger.Debug("check validity", zap.Error(err))
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		storeSecret.UserID = userID
		err = secret.StoreSecret(r.Context(), storeSecret)
		if err != nil {
			writeInternalError(w, logger, "error storing secret", err)
			return
		}

		w.WriteHeader(http.StatusCreated)
	}
}

func writeUnauthorized(w http.ResponseWriter, logger *zap.Logger) {
	logger.Debug("unauthorized request")
	w.WriteHeader(http.StatusUnauthorized)
}

func writeInternalError(w http.ResponseWriter, logger *zap.Logger, msg string, err error) {
	logger.Error(msg, zap.Error(err))
	w.WriteHeader(http.StatusInternalServerError)
}

func Show(logger *zap.Logger, secret Secret) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, err := utils.GetCtxUserID(r.Context())
		if err != nil {
			writeUnauthorized(w, logger)
			return
		}

		id := chi.URLParam(r, "id")

		showSecret := models.ShowSecret{
			ID:     id,
			UserID: userID,
		}

		secretData, err := secret.GetSecret(r.Context(), showSecret)
		if err != nil {
			writeInternalError(w, logger, "error show secret", err)
			return
		}

		if err = codec.Encode(w, http.StatusOK, secretData); err != nil {
			log.Printf("Error encoding response: %v", err)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
	}
}

func Update(logger *zap.Logger, secret Secret) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, err := utils.GetCtxUserID(r.Context())
		if err != nil {
			writeUnauthorized(w, logger)
			return
		}

		updateSecret, err := codec.Decode[models.UpdateSecret](r)
		if err != nil {
			logger.Debug("decode json request", zap.Error(err))
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		updateSecret.UserID = userID
		err = secret.UpdateSecret(r.Context(), updateSecret)
		if err != nil {
			writeInternalError(w, logger, "error update secret", err)
			return
		}

		w.WriteHeader(http.StatusCreated)
	}
}

func Delete(logger *zap.Logger, secret Secret) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, err := utils.GetCtxUserID(r.Context())
		if err != nil {
			writeUnauthorized(w, logger)
			return
		}

		id := chi.URLParam(r, "id")

		deleteSecret := models.DeleteSecret{
			ID:     id,
			UserID: userID,
		}

		err = secret.DeleteSecret(r.Context(), deleteSecret)
		if err != nil {
			writeInternalError(w, logger, "error delete secret", err)
			return
		}

		w.WriteHeader(http.StatusCreated)
	}
}
