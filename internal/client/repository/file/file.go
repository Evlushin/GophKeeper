package file

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/Evlushin/GophKeeper/internal/client/config"
	"github.com/Evlushin/GophKeeper/internal/client/models"
	"github.com/Evlushin/GophKeeper/internal/client/myerrors"
	"github.com/google/uuid"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Store struct {
	mux *sync.RWMutex
	s   map[string]models.SaveData
	cfg *config.Config
}

func NewStore(cfg *config.Config) (*Store, error) {
	if cfg == nil {
		return nil, myerrors.ErrConfigIsNil
	}
	if cfg.Secret.File == "" {
		return nil, myerrors.ErrNoFilePath
	}

	store := &Store{
		mux: &sync.RWMutex{},
		s:   make(map[string]models.SaveData),
		cfg: cfg,
	}

	if err := store.load(); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to load store: %w", err)
	}

	return store, nil
}

// load загружает данные из файла в память.
func (st *Store) load() error {
	data, err := os.ReadFile(st.cfg.Secret.File)
	if err != nil {
		return fmt.Errorf("read db file: %w", err)
	}

	if len(data) == 0 {
		st.s = make(map[string]models.SaveData)
		return nil
	}

	if err = json.Unmarshal(data, &st.s); err != nil {
		return fmt.Errorf("unmarshal json: %w", err)
	}

	return nil
}

// Save сохраняет данные из памяти в файл.
func (st *Store) Save() error {
	data, err := json.MarshalIndent(st.s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}

	tmpFile := st.cfg.Secret.File + ".tmp"
	if err = os.WriteFile(tmpFile, data, 0644); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}

	if err = os.Rename(tmpFile, st.cfg.Secret.File); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}

	return nil
}

// ListSecret список секретов.
func (st *Store) ListSecret(ctx context.Context, req models.ListRequest) (map[string]models.SaveData, error) {
	st.mux.Lock()
	defer st.mux.Unlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	var (
		res   map[string]models.SaveData
		isAdd bool
	)
	for id, secret := range st.s {
		isAdd = true
		if req.Type != "" && models.DataType(req.Type) != secret.DataType {
			isAdd = false
		}
		if secret.IsDelete {
			isAdd = false
		}

		if isAdd {
			res[id] = secret
		}
	}

	return res, nil
}

// DeleteSecret помечает секрет как удаленный.
func (st *Store) DeleteSecret(ctx context.Context, req models.DeleteRequest) error {
	if req.ID == "" {
		return myerrors.ErrInvalidRequest
	}

	st.mux.Lock()
	defer st.mux.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	secret, exists := st.s[req.ID]
	if !exists {
		return myerrors.ErrGetSecretNotFound
	}

	if secret.IsDelete {
		return myerrors.ErrSecretAlreadyDeleted
	}

	secret.IsDelete = true
	secret.DeletedAt = time.Now()
	st.s[req.ID] = secret

	if err := st.Save(); err != nil {
		return fmt.Errorf("save after delete: %w", err)
	}

	return nil
}

// ShowSecret возвращает секрет по ID.
func (st *Store) ShowSecret(ctx context.Context, req models.ShowRequest) (*models.ShowResponse, error) {
	if req.ID == "" {
		return nil, myerrors.ErrInvalidRequest
	}

	st.mux.RLock()
	defer st.mux.RUnlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	secret, exists := st.s[req.ID]
	if !exists {
		return nil, myerrors.ErrGetSecretNotFound
	}

	if secret.IsDelete {
		return nil, myerrors.ErrSecretAlreadyDeleted
	}

	//var file
	//if secret.FileStore != "" {
	//	file, err := os.Open(secret.FileStore)
	//	if err != nil {
	//		return nil, fmt.Errorf("open file: %w", err)
	//	}
	//}

	return &models.ShowResponse{
		SecretData: secret.SecretData,
	}, nil
}

// StoreSecret сохраняет новый секрет.
func (st *Store) StoreSecret(ctx context.Context, req models.StoreRequest) error {
	id := uuid.New().String()
	st.mux.Lock()
	defer st.mux.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	if req.Reader != nil {
		file, err := st.StoreFile(ctx, models.StoreFileRequest{
			ID:        id,
			Reader:    req.Reader,
			ChunkSize: req.ChunkSize,
		})
		if err != nil {
			return fmt.Errorf("save file: %w", err)
		}
		req.SecretData.FileStore = file.FileStore
	}

	req.SecretData.CreatedAt = time.Now()
	req.SecretData.UpdatedAt = time.Now()
	st.s[id] = models.SaveData{
		SecretData: req.SecretData,
		IsDelete:   false,
	}

	if err := st.Save(); err != nil {
		return fmt.Errorf("save after update: %w", err)
	}

	return nil
}

// UpdateSecret обновить секрет.
func (st *Store) UpdateSecret(ctx context.Context, req models.UpdateRequest) error {
	_, err := st.ShowSecret(ctx, models.ShowRequest{ID: req.ID})
	if err != nil {
		return fmt.Errorf("get secret: %w", err)
	}

	st.mux.Lock()
	defer st.mux.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	if req.Reader != nil {
		file, err := st.StoreFile(ctx, models.StoreFileRequest{
			ID:        req.ID,
			Reader:    req.Reader,
			ChunkSize: req.ChunkSize,
		})
		if err != nil {
			return fmt.Errorf("save file: %w", err)
		}
		req.SecretData.FileStore = file.FileStore
	}

	req.SecretData.UpdatedAt = time.Now()
	st.s[req.ID] = models.SaveData{
		SecretData: req.SecretData,
		IsDelete:   false,
	}

	if err = st.Save(); err != nil {
		return fmt.Errorf("save after update: %w", err)
	}

	return nil
}

// generateFilePath создает уникальный путь для файла
func (st *Store) generateFilePath(secretID string) string {
	hash := sha256.Sum256([]byte(secretID + time.Now().String()))
	return filepath.Join(st.cfg.Secret.Dir, hex.EncodeToString(hash[:]))
}

// StoreFile сохраняет файл с потоковой записью
func (st *Store) StoreFile(ctx context.Context, req models.StoreFileRequest) (*models.StoreFileResponse, error) {
	if req.Reader == nil {
		return nil, myerrors.ErrNoReader
	}

	filePath := st.generateFilePath(req.ID)

	st.mux.Lock()
	defer st.mux.Unlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Создаем временный файл
	tmpFile := filePath + ".tmp"
	file, err := os.Create(tmpFile)
	if err != nil {
		return nil, fmt.Errorf("create temp file: %v", err)
	}
	defer file.Close()

	_, err = st.copyWithContext(ctx, file, req.Reader, req.ChunkSize)
	if err != nil {
		os.Remove(tmpFile)
		return nil, fmt.Errorf("copy file data: %w", err)
	}

	if err = os.Rename(tmpFile, filePath); err != nil {
		os.Remove(tmpFile)
		return nil, fmt.Errorf("rename file: %w", err)
	}

	return &models.StoreFileResponse{
		FileStore: filePath,
	}, nil
}

// copyWithContext копирует данные с поддержкой контекста
func (st *Store) copyWithContext(ctx context.Context, dst io.Writer, src io.Reader, chunkSize int) (int64, error) {
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
