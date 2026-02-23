package secret

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/Evlushin/GophKeeper/internal/mycrypto"
	"github.com/Evlushin/GophKeeper/internal/server/codec"
	"github.com/Evlushin/GophKeeper/internal/server/handler/config"
	"github.com/Evlushin/GophKeeper/internal/server/models"
	utils "github.com/Evlushin/GophKeeper/internal/server/utils/auth"
	"github.com/Evlushin/GophKeeper/internal/validator"
	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	copyBufferSize    = 32 * 1024 // 32KB
	defaultCtxTimeout = 60 * time.Second
)

type Secret interface {
	CountSecret(ctx context.Context, indexSecret models.IndexSecret) (int64, error)
	IndexSecret(ctx context.Context, indexSecret models.IndexSecret) ([]models.SecretData, error)
	StoreSecret(ctx context.Context, storeSecret models.StoreSecret) error
	GetSecret(ctx context.Context, getSecret models.ShowSecret) (*models.SecretData, error)
	UpdateSecret(ctx context.Context, updateSecret models.UpdateSecret) error
	DeleteSecret(ctx context.Context, deleteSecret models.DeleteSecret) error
}

// Index handles the HTTP request to retrieve a list of secrets for the current user.
// Endpoint: GET /api/secret?type=<dataType>
// Query Parameters:
//   - type: optional filter by secret type (card, login, text, file)
//
// Returns:
//   - HTTP 200 OK with JSON array of SecretData if secrets exist
//   - HTTP 204 No Content if no secrets found for the given type
//   - HTTP 401 Unauthorized if user authentication fails
//   - HTTP 500 Internal Server Error on database or processing failure
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

// Store handles the HTTP request to create a new secret.
// Endpoint: POST /api/secret
// Request Body: JSON encoded models.StoreSecret
//   - Data field is automatically encrypted using AES-GCM before storage
//
// Returns:
//   - HTTP 201 Created on successful secret creation
//   - HTTP 400 Bad Request on JSON decode error or validation failure
//   - HTTP 401 Unauthorized if user authentication fails
//   - HTTP 500 Internal Server Error on encryption or database failure
func Store(cfg *config.Config, logger *zap.Logger, secret Secret) http.HandlerFunc {
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

		if len(storeSecret.Data) > 0 {
			storeSecret.Data, err = mycrypto.EncryptTextToHex(storeSecret.Data, []byte(cfg.AuthSecretKey), []byte(storeSecret.ID))
			if err != nil {
				writeInternalError(w, logger, "encrypt secret data", err)
				return
			}
		}

		err = secret.StoreSecret(r.Context(), storeSecret)
		if err != nil {
			writeInternalError(w, logger, "error storing secret", err)
			return
		}

		w.WriteHeader(http.StatusCreated)
	}
}

// writeUnauthorized logs a debug message and writes HTTP 401 Unauthorized response.
func writeUnauthorized(w http.ResponseWriter, logger *zap.Logger) {
	logger.Debug("unauthorized request")
	w.WriteHeader(http.StatusUnauthorized)
}

// writeInternalError logs an error message with context and writes HTTP 500 response.
func writeInternalError(w http.ResponseWriter, logger *zap.Logger, msg string, err error) {
	logger.Error(msg, zap.Error(err))
	w.WriteHeader(http.StatusInternalServerError)
}

// Show handles the HTTP request to retrieve a specific secret by ID.
// Endpoint: GET /api/secret/{id}
// Path Parameters:
//   - id: unique identifier of the secret to retrieve
//
// Returns:
//   - HTTP 200 OK with JSON encoded SecretData (Data field decrypted)
//   - HTTP 401 Unauthorized if user authentication fails
//   - HTTP 404 Not Found if secret does not exist (handled by repository)
//   - HTTP 500 Internal Server Error on decryption or database failure
func Show(cfg *config.Config, logger *zap.Logger, secret Secret) http.HandlerFunc {
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

		if len(secretData.Data) > 0 {
			secretData.Data, err = mycrypto.DecryptTextFromHex(string(secretData.Data), []byte(cfg.AuthSecretKey), []byte(secretData.ID))
			if err != nil {
				writeInternalError(w, logger, "decrypting secret data", err)
				return
			}
		}

		if err = codec.Encode(w, http.StatusOK, secretData); err != nil {
			writeInternalError(w, logger, "encoding response", err)
			return
		}
	}
}

// Update handles the HTTP request to modify an existing secret.
// Endpoint: PUT /api/secret
// Path Parameters:
//   - id: unique identifier of the secret to update
//
// Request Body: JSON encoded models.UpdateSecret
//   - Data field is automatically re-encrypted before saving
//
// Returns:
//   - HTTP 200 OK on successful update
//   - HTTP 400 Bad Request on JSON decode error
//   - HTTP 401 Unauthorized if user authentication fails
//   - HTTP 500 Internal Server Error on encryption or database failure
func Update(cfg *config.Config, logger *zap.Logger, secret Secret) http.HandlerFunc {
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

		if len(updateSecret.Data) > 0 {
			updateSecret.Data, err = mycrypto.EncryptTextToHex(updateSecret.Data, []byte(cfg.AuthSecretKey), []byte(updateSecret.ID))
			if err != nil {
				writeInternalError(w, logger, "encrypt secret data", err)
				return
			}
		}

		err = secret.UpdateSecret(r.Context(), updateSecret)
		if err != nil {
			writeInternalError(w, logger, "error update secret", err)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

// Delete handles the HTTP request to permanently remove a secret.
// Endpoint: DELETE /api/secret/{id}
// Path Parameters:
//   - id: unique identifier of the secret to delete
//
// Returns:
//   - HTTP 200 OK on successful deletion
//   - HTTP 401 Unauthorized if user authentication fails
//   - HTTP 500 Internal Server Error on database failure
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

		w.WriteHeader(http.StatusOK)
	}
}

// UploadFile handles the HTTP request to upload and encrypt a binary file.
// Endpoint: POST /api/secret/file/upload/{id}
// Path Parameters:
//   - id: unique identifier of the secret (must have FileStore path configured)
//
// Request Body: raw binary file content (streamed)
// Behavior:
//   - File is encrypted on-the-fly using AES-GCM with chunked nonce rotation
//   - Temporary file is used to ensure atomic write operation
//
// Returns:
//   - HTTP 200 OK on successful upload and encryption
//   - HTTP 400 Bad Request if secret has no FileStore configured or invalid salt
//   - HTTP 401 Unauthorized if user authentication fails
//   - HTTP 404 Not Found if secret does not exist
//   - HTTP 500 Internal Server Error on file I/O or encryption failure
func UploadFile(cfg *config.Config, logger *zap.Logger, secret Secret) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, err := utils.GetCtxUserID(r.Context())
		if err != nil {
			writeUnauthorized(w, logger)
			return
		}

		id := chi.URLParam(r, "id")
		secretData, err := secret.GetSecret(r.Context(), models.ShowSecret{
			ID:     id,
			UserID: userID,
		})
		if err != nil {
			writeInternalError(w, logger, "error show secret", err)
			return
		}

		if secretData.FileStore == "" {
			http.Error(w, "no file name", http.StatusBadRequest)
			return
		}

		fileName := filepath.Join(cfg.DirFile, secretData.FileStore)

		key := []byte(cfg.AuthSecretKey)
		salt, err := mycrypto.ParseHexSalt(secretData.FileStore)
		if err != nil {
			http.Error(w, "invalid salt", http.StatusBadRequest)
			return
		}

		tmpFile := fileName + ".tmp"
		file, err := os.Create(tmpFile)
		if err != nil {
			http.Error(w, "create file", http.StatusInternalServerError)
			return
		}

		encWriter, err := mycrypto.NewEncryptedWriter(file, key, salt)
		if err != nil {
			file.Close()
			os.Remove(tmpFile)
			http.Error(w, "init encryption", http.StatusInternalServerError)
			return
		}

		_, err = copyWithContext(r.Context(), encWriter, r.Body, copyBufferSize)
		if err != nil {
			encWriter.Close()
			file.Close()
			os.Remove(tmpFile)
			http.Error(w, "copy/encrypt file", http.StatusInternalServerError)
			return
		}

		if err = encWriter.Close(); err != nil {
			file.Close()
			os.Remove(tmpFile)
			http.Error(w, "close encrypted file", http.StatusInternalServerError)
			return
		}

		if err = os.Rename(tmpFile, fileName); err != nil {
			os.Remove(tmpFile)
			http.Error(w, "rename file", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

// copyWithContext копирует данные с поддержкой контекста
func copyWithContext(ctx context.Context, dst io.Writer, src io.Reader, chunkSize int) (int64, error) {
	if chunkSize <= 0 {
		chunkSize = 32 * 1024 // 32KB по умолчанию
	}

	buf := make([]byte, chunkSize)
	var total int64

	for {
		select {
		case <-ctx.Done():
			return total, ctx.Err()
		default:
		}

		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				total += int64(nw)
			}
			if ew != nil {
				return total, ew
			}
			if nr != nw {
				return total, io.ErrShortWrite
			}
		}
		if er != nil {
			if er == io.EOF {
				break
			}
			return total, er
		}
	}
	return total, nil
}

// DownloadFile handles the HTTP request to download and decrypt a stored file.
// Endpoint: GET /api/secrets/file/download/{id}
// Path Parameters:
//   - id: unique identifier of the secret containing file metadata
//
// Response Headers:
//   - Content-Type: application/octet-stream
//   - Content-Disposition: attachment; filename=<original_filename>
//
// Behavior:
//   - File is decrypted on-the-fly using AES-GCM during streaming
//   - Nonce is read from file header, salt is derived from secret metadata
//
// Returns:
//   - HTTP 200 OK with decrypted file stream
//   - HTTP 400 Bad Request if secret has no FileStore or invalid salt format
//   - HTTP 401 Unauthorized if user authentication fails
//   - HTTP 404 Not Found if file does not exist on disk
//   - HTTP 500 Internal Server Error on decryption or I/O failure
func DownloadFile(cfg *config.Config, logger *zap.Logger, secret Secret) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, err := utils.GetCtxUserID(r.Context())
		if err != nil {
			writeUnauthorized(w, logger)
			return
		}

		id := chi.URLParam(r, "id")

		secretData, err := secret.GetSecret(r.Context(), models.ShowSecret{
			ID:     id,
			UserID: userID,
		})
		if err != nil {
			writeInternalError(w, logger, "error show secret", err)
			return
		}

		if secretData.FileStore == "" {
			http.Error(w, "no file name", http.StatusBadRequest)
			return
		}

		fileName := filepath.Join(cfg.DirFile, secretData.FileStore)

		if _, err = os.Stat(fileName); os.IsNotExist(err) {
			http.Error(w, "file not found", http.StatusNotFound)
			return
		}

		file, err := os.Open(fileName)
		if err != nil {
			writeInternalError(w, logger, "error opening file", err)
			return
		}
		defer file.Close()

		// --- НАЧАЛО РАСШИФРОВКИ ---
		salt, err := hex.DecodeString(secretData.FileStore)
		if err != nil {
			writeInternalError(w, logger, "invalid salt format", err)
			return
		}

		key := []byte(cfg.AuthSecretKey)
		if key == nil {
			writeInternalError(w, logger, "encryption key not found", nil)
			return
		}

		decReader, err := mycrypto.NewDecryptedReader(file, key, salt)
		if err != nil {
			writeInternalError(w, logger, "init decryption", err)
			return
		}
		// --- КОНЕЦ РАСШИФРОВКИ ---

		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", secretData.FileStore))

		_, err = copyWithContext(r.Context(), w, decReader, copyBufferSize)
		if err != nil {
			if r.Context().Err() == context.Canceled {
				logger.Info("client disconnected during download")
				return
			}
			logger.Error("error sending file", zap.Error(err))
			return
		}
	}
}
