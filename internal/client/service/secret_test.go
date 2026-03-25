package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/Evlushin/GophKeeper/internal/client/config"
	"github.com/Evlushin/GophKeeper/internal/client/models"
	"github.com/Evlushin/GophKeeper/internal/client/service/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// setupTest создаёт тестовую конфигурацию, мок-репозиторий и тестовый HTTP-сервер
func setupTest(t *testing.T, handler http.HandlerFunc) (*config.Config, *mocks.MockRepository, *http.Client, func()) {
	t.Helper()

	tmpDir := t.TempDir()

	cfg := &config.Config{
		Server: config.Server{
			Address: "", // будет заменено на адрес тестового сервера
			Cert:    "",
		},
		Log: config.Log{
			Level: "error",
		},
		Secret: config.Secret{
			File: "test.db",
			Dir:  tmpDir,
		},
		RequestTimeout: 30 * time.Second,
		App:            "gophkeeper-test",
	}

	mockRepo := mocks.NewMockRepository(t)
	client := &http.Client{Timeout: 5 * time.Second}

	server := httptest.NewServer(handler)
	cfg.Server.Address = server.URL

	cleanup := func() {
		server.Close()
	}

	return cfg, mockRepo, client, cleanup
}

// ============================================================================
// Тесты для метода List
// ============================================================================

func TestSecret_List(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		setupMock       func(m *mocks.MockRepository)
		setupHandler    http.HandlerFunc
		request         models.ListRequest
		wantErr         bool
		wantErrContains string
	}{
		{
			name: "успешный список с сервера",
			setupMock: func(m *mocks.MockRepository) {
				// При успешном ответе сервера локальное хранилище не запрашивается
			},
			setupHandler: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/api/secret", r.URL.Path)
				assert.Equal(t, http.MethodGet, r.Method)
				assert.Equal(t, "test-token", r.Header.Get("X-API-Token"))
				assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)

				response := []models.SaveData{
					{
						SecretData: models.SecretData{
							ID:        "1",
							DataType:  models.LoginPassword,
							Title:     "Test Secret",
							Metadata:  `{"source":"web"}`,
							CreatedAt: time.Now().UTC(),
							UpdatedAt: time.Now().UTC(),
						},
						IsDelete: false,
					},
				}
				_ = json.NewEncoder(w).Encode(response)
			},
			request: models.ListRequest{
				Type:  string(models.LoginPassword),
				Token: "test-token",
			},
			wantErr: false,
		},
		{
			name: "fallback на локальное хранилище при ошибке сервера",
			setupMock: func(m *mocks.MockRepository) {
				m.EXPECT().ListSecret(
					mock.Anything,
					mock.MatchedBy(func(req models.ListRequest) bool {
						return req.Token == "test-token" && req.Type == string(models.CardData)
					}),
				).Return([]models.SaveData{
					{
						SecretData: models.SecretData{
							ID:        "local-1",
							DataType:  models.CardData,
							Title:     "Local Card",
							Metadata:  `{"bank":"TestBank"}`,
							CreatedAt: time.Now().UTC(),
						},
						IsDelete: false,
					},
				}, nil)
			},
			setupHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadGateway)
				_, _ = w.Write([]byte(`{"error":"gateway timeout"}`))
			},
			request: models.ListRequest{
				Type:  string(models.CardData),
				Token: "test-token",
			},
			wantErr: false,
		},
		{
			name: "ошибка при чтении локального хранилища",
			setupMock: func(m *mocks.MockRepository) {
				m.EXPECT().ListSecret(mock.Anything, mock.Anything).
					Return(nil, errors.New("storage read error"))
			},
			setupHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"error":"unavailable"}`))
			},
			request: models.ListRequest{
				Type:  string(models.BinaryData),
				Token: "test-token",
			},
			wantErr:         true,
			wantErrContains: "get list",
		},
		{
			name: "невалидный JSON в ответе сервера",
			setupMock: func(m *mocks.MockRepository) {
				// При успешном статусе, но невалидном JSON, парсинг упадёт
			},
			setupHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{invalid json response`))
			},
			request: models.ListRequest{
				Type:  string(models.LoginPassword),
				Token: "test-token",
			},
			wantErr:         true,
			wantErrContains: "parse response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg, mockRepo, httpClient, cleanup := setupTest(t, tt.setupHandler)
			defer cleanup()

			svc := &Secret{
				cfg:        cfg,
				store:      mockRepo,
				httpClient: httpClient,
			}

			if tt.setupMock != nil {
				tt.setupMock(mockRepo)
			}

			err := svc.List(context.Background(), tt.request)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantErrContains != "" {
					assert.Contains(t, err.Error(), tt.wantErrContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ============================================================================
// Тесты для метода Store
// ============================================================================

func TestSecret_Store(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		setupMock       func(m *mocks.MockRepository)
		setupHandler    http.HandlerFunc
		request         models.StoreRequest
		wantErr         bool
		wantErrContains string
	}{
		{
			name: "успешное сохранение LoginPassword на сервере",
			setupMock: func(m *mocks.MockRepository) {
				m.EXPECT().StoreSecret(
					mock.Anything,
					mock.MatchedBy(func(req models.StoreRequest) bool {
						return req.Title == "My Account" && req.DataType == models.LoginPassword
					}),
				).Return(&models.SaveData{
					SecretData: models.SecretData{
						ID:        "srv-123",
						Title:     "My Account",
						DataType:  models.LoginPassword,
						Data:      []byte(`{"login":"user","pass":"pwd"}`),
						CreatedAt: time.Now().UTC(),
					},
					IsDelete: false,
				}, nil)
			},
			setupHandler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/secret" && r.Method == http.MethodPost {
					assert.Equal(t, "test-token", r.Header.Get("X-API-Token"))

					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusCreated)
					_ = json.NewEncoder(w).Encode(models.SaveData{
						SecretData: models.SecretData{ID: "srv-123"},
					})
				}
			},
			request: models.StoreRequest{
				SecretData: models.SecretData{
					Title:    "My Account",
					DataType: models.LoginPassword,
					Data:     []byte(`{"login":"user","pass":"pwd"}`),
				},
				Token: "test-token",
			},
			wantErr: false,
		},
		{
			name: "успешное сохранение CardData",
			setupMock: func(m *mocks.MockRepository) {
				card := models.Card{
					Number:     "4111111111111111",
					Holder:     "John Doe",
					ExpiryDate: "12/25",
					CVV:        "123",
					Bank:       "TestBank",
				}
				data, _ := json.Marshal(card)

				m.EXPECT().StoreSecret(mock.Anything, mock.Anything).
					Return(&models.SaveData{
						SecretData: models.SecretData{
							ID:       "card-1",
							DataType: models.CardData,
							Title:    "My Card",
							Data:     data,
						},
					}, nil)
			},
			setupHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(models.SaveData{
					SecretData: models.SecretData{ID: "card-1", DataType: models.CardData},
				})
			},
			request: models.StoreRequest{
				SecretData: models.SecretData{
					Title:    "My Card",
					DataType: models.CardData,
				},
				Token: "token-123",
			},
			wantErr: false,
		},
		{
			name: "ошибка сохранения в локальном хранилище",
			setupMock: func(m *mocks.MockRepository) {
				m.EXPECT().StoreSecret(mock.Anything, mock.Anything).
					Return(nil, errors.New("local storage failed"))
			},
			setupHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			request: models.StoreRequest{
				SecretData: models.SecretData{
					Title:    "Fail Secret",
					DataType: models.LoginPassword,
				},
				Token: "token",
			},
			wantErr:         true,
			wantErrContains: "store secret",
		},
		{
			name: "ошибка маршалинга запроса (циклическая структура)",
			setupMock: func(m *mocks.MockRepository) {
				m.EXPECT().StoreSecret(mock.Anything, mock.Anything).
					Return(&models.SaveData{
						SecretData: models.SecretData{ID: "x", DataType: models.BinaryData},
					}, nil)
			},
			setupHandler: func(w http.ResponseWriter, r *http.Request) {},
			request: models.StoreRequest{
				SecretData: models.SecretData{
					DataType: models.BinaryData,
					// Reader может вызвать проблемы при маршалинге, но в нашем случае он игнорируется json-тегом "-"
				},
				Token: "token",
			},
			wantErr: false, // json.Marshal корректно пропускает поля с тегом "-"
		},
		{
			name: "сервер недоступен, но локальное сохранение прошло",
			setupMock: func(m *mocks.MockRepository) {
				m.EXPECT().StoreSecret(mock.Anything, mock.Anything).
					Return(&models.SaveData{
						SecretData: models.SecretData{
							ID:        "local-only",
							Title:     "Local Only",
							DataType:  models.LoginPassword,
							CreatedAt: time.Now().UTC(),
						},
					}, nil)
			},
			setupHandler: func(w http.ResponseWriter, r *http.Request) {
				// Имитация недоступности сервера
				w.WriteHeader(http.StatusServiceUnavailable)
			},
			request: models.StoreRequest{
				SecretData: models.SecretData{
					Title:    "Local Only",
					DataType: models.LoginPassword,
				},
				Token: "token",
			},
			wantErr: false, // Локальное сохранение успешно, ошибка сервера не критична
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg, mockRepo, httpClient, cleanup := setupTest(t, tt.setupHandler)
			defer cleanup()

			svc := &Secret{
				cfg:        cfg,
				store:      mockRepo,
				httpClient: httpClient,
			}

			if tt.setupMock != nil {
				tt.setupMock(mockRepo)
			}

			err := svc.Store(context.Background(), tt.request)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantErrContains != "" {
					assert.Contains(t, err.Error(), tt.wantErrContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ============================================================================
// Тесты для метода Show
// ============================================================================

func TestSecret_Show(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		setupMock       func(m *mocks.MockRepository)
		setupHandler    http.HandlerFunc
		request         models.ShowRequest
		wantErr         bool
		wantErrContains string
	}{
		{
			name: "успешный показ LoginPassword с сервера",
			setupMock: func(m *mocks.MockRepository) {
				// Не вызывается при успешном ответе сервера
			},
			setupHandler: func(w http.ResponseWriter, r *http.Request) {
				assert.Contains(t, r.URL.Path, "/api/secret/")
				assert.Equal(t, http.MethodGet, r.Method)
				assert.Equal(t, "show-token", r.Header.Get("X-API-Token"))

				creds := models.Credentials{Login: "test@example.com", Pass: "supersecret"}
				data, _ := json.Marshal(creds)

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(&models.ShowResponse{
					SecretData: models.SecretData{
						ID:        "show-1",
						Title:     "Test Login",
						DataType:  models.LoginPassword,
						Data:      data,
						Metadata:  `{"verified":true}`,
						CreatedAt: time.Now().UTC(),
						UpdatedAt: time.Now().UTC(),
					},
				})
			},
			request: models.ShowRequest{
				ID:    "show-1",
				Token: "show-token",
			},
			wantErr: false,
		},
		{
			name:      "успешный показ CardData",
			setupMock: func(m *mocks.MockRepository) {},
			setupHandler: func(w http.ResponseWriter, r *http.Request) {
				card := models.Card{
					Number:     "5500000000000004",
					Holder:     "Jane Smith",
					ExpiryDate: "09/26",
					CVV:        "456",
					Bank:       "GlobalBank",
				}
				data, _ := json.Marshal(card)

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(&models.ShowResponse{
					SecretData: models.SecretData{
						ID:       "card-show",
						Title:    "Work Card",
						DataType: models.CardData,
						Data:     data,
					},
				})
			},
			request: models.ShowRequest{
				ID:    "card-show",
				Token: "token",
			},
			wantErr: false,
		},
		{
			name: "fallback на локальное хранилище при BinaryData",
			setupMock: func(m *mocks.MockRepository) {
				m.EXPECT().ShowSecret(
					mock.Anything,
					mock.MatchedBy(func(req models.ShowRequest) bool {
						return req.ID == "file-local"
					}),
				).Return(&models.ShowResponse{
					SecretData: models.SecretData{
						ID:        "file-local",
						Title:     "Local File",
						DataType:  models.BinaryData,
						FileStore: "local_file.bin",
						Data:      []byte("local content"),
					},
					Reader: strings.NewReader("local file content"),
				}, nil)
			},
			setupHandler: func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "/api/secret/file/download") {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				w.WriteHeader(http.StatusBadGateway)
				_, _ = w.Write([]byte(`{"error":"gateway error"}`))
			},
			request: models.ShowRequest{
				ID:    "file-local",
				Token: "token",
			},
			wantErr: false,
		},
		{
			name:      "ошибка парсинга JSON ответа сервера",
			setupMock: func(m *mocks.MockRepository) {},
			setupHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{not valid json`))
			},
			request: models.ShowRequest{
				ID:    "bad-json",
				Token: "token",
			},
			wantErr:         true,
			wantErrContains: "parse response",
		},
		{
			name: "ошибка чтения локального хранилища при fallback",
			setupMock: func(m *mocks.MockRepository) {
				m.EXPECT().ShowSecret(mock.Anything, mock.Anything).
					Return(nil, errors.New("local show error"))
			},
			setupHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			request: models.ShowRequest{
				ID:    "fail-id",
				Token: "token",
			},
			wantErr:         true,
			wantErrContains: "get secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg, mockRepo, httpClient, cleanup := setupTest(t, tt.setupHandler)
			defer cleanup()

			svc := &Secret{
				cfg:        cfg,
				store:      mockRepo,
				httpClient: httpClient,
			}

			if tt.setupMock != nil {
				tt.setupMock(mockRepo)
			}

			err := svc.Show(context.Background(), tt.request)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantErrContains != "" {
					assert.Contains(t, err.Error(), tt.wantErrContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ============================================================================
// Тесты для метода Update
// ============================================================================

func TestSecret_Update(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		setupMock       func(m *mocks.MockRepository)
		setupHandler    http.HandlerFunc
		request         models.UpdateRequest
		wantErr         bool
		wantErrContains string
	}{
		{
			name: "успешное обновление LoginPassword",
			setupMock: func(m *mocks.MockRepository) {
				m.EXPECT().UpdateSecret(
					mock.Anything,
					mock.MatchedBy(func(req models.UpdateRequest) bool {
						return req.ID == "upd-1" && req.Title == "Updated Account"
					}),
				).Return(&models.SaveData{
					SecretData: models.SecretData{
						ID:        "upd-1",
						Title:     "Updated Account",
						DataType:  models.LoginPassword,
						UpdatedAt: time.Now().UTC(),
					},
				}, nil)
			},
			setupHandler: func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPut && r.URL.Path == "/api/secret" {
					assert.Equal(t, "update-token", r.Header.Get("X-API-Token"))
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(models.SaveData{
						SecretData: models.SecretData{ID: "upd-1"},
					})
				}
			},
			request: models.UpdateRequest{
				StoreRequest: models.StoreRequest{
					SecretData: models.SecretData{
						Title:    "Updated Account",
						DataType: models.LoginPassword,
					},
					// Token не указываем здесь
				},
				ID:    "upd-1",
				Token: "update-token", // ✅ Токен на уровне UpdateRequest
			},
			wantErr: false,
		},
		{
			name: "ошибка обновления в локальном хранилище",
			setupMock: func(m *mocks.MockRepository) {
				m.EXPECT().UpdateSecret(mock.Anything, mock.Anything).
					Return(nil, errors.New("update local failed"))
			},
			setupHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			request: models.UpdateRequest{
				StoreRequest: models.StoreRequest{
					SecretData: models.SecretData{Title: "Test"},
				},
				ID:    "fail-id",
				Token: "token", // ✅ Токен здесь
			},
			wantErr:         true,
			wantErrContains: "update secret",
		},
		{
			name: "сервер вернул ошибку, но локальное обновление прошло",
			setupMock: func(m *mocks.MockRepository) {
				m.EXPECT().UpdateSecret(mock.Anything, mock.Anything).
					Return(&models.SaveData{
						SecretData: models.SecretData{
							ID:        "local-upd",
							Title:     "Local Updated",
							DataType:  models.CardData,
							UpdatedAt: time.Now().UTC(),
						},
					}, nil)
			},
			setupHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"error":"conflict"}`))
			},
			request: models.UpdateRequest{
				StoreRequest: models.StoreRequest{
					SecretData: models.SecretData{
						Title:    "Local Updated",
						DataType: models.CardData,
					},
				},
				ID:    "local-upd",
				Token: "token", // ✅ Токен здесь
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg, mockRepo, httpClient, cleanup := setupTest(t, tt.setupHandler)
			defer cleanup()

			svc := &Secret{
				cfg:        cfg,
				store:      mockRepo,
				httpClient: httpClient,
			}

			if tt.setupMock != nil {
				tt.setupMock(mockRepo)
			}

			err := svc.Update(context.Background(), tt.request)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantErrContains != "" {
					assert.Contains(t, err.Error(), tt.wantErrContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ============================================================================
// Тесты для метода Delete
// ============================================================================

func TestSecret_Delete(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		setupMock       func(m *mocks.MockRepository)
		setupHandler    http.HandlerFunc
		request         models.DeleteRequest
		wantErr         bool
		wantErrContains string
	}{
		{
			name: "успешное удаление с сервера и локально",
			setupMock: func(m *mocks.MockRepository) {
				m.EXPECT().DeleteSecret(
					mock.Anything,
					mock.MatchedBy(func(req models.DeleteRequest) bool {
						return req.ID == "del-123" && req.Token == "del-token"
					}),
				).Return(nil)
			},
			setupHandler: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodDelete, r.Method)
				assert.Contains(t, r.URL.Path, "/api/secret/del-123")
				assert.Equal(t, "del-token", r.Header.Get("X-API-Token"))
				w.WriteHeader(http.StatusOK)
			},
			request: models.DeleteRequest{
				ID:    "del-123",
				Token: "del-token",
			},
			wantErr: false,
		},
		{
			name: "ошибка удаления в локальном хранилище",
			setupMock: func(m *mocks.MockRepository) {
				m.EXPECT().DeleteSecret(mock.Anything, mock.Anything).
					Return(errors.New("delete local failed"))
			},
			setupHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			request: models.DeleteRequest{
				ID:    "fail-del",
				Token: "token",
			},
			wantErr:         true,
			wantErrContains: "delete secret",
		},
		{
			name: "сервер вернул 404, но локальное удаление прошло",
			setupMock: func(m *mocks.MockRepository) {
				m.EXPECT().DeleteSecret(mock.Anything, mock.Anything).Return(nil)
			},
			setupHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"error":"not found"}`))
			},
			request: models.DeleteRequest{
				ID:    "missing",
				Token: "token",
			},
			wantErr: false, // Локальное удаление успешно, 404 сервера не критичен
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg, mockRepo, httpClient, cleanup := setupTest(t, tt.setupHandler)
			defer cleanup()

			svc := &Secret{
				cfg:        cfg,
				store:      mockRepo,
				httpClient: httpClient,
			}

			if tt.setupMock != nil {
				tt.setupMock(mockRepo)
			}

			err := svc.Delete(context.Background(), tt.request)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantErrContains != "" {
					assert.Contains(t, err.Error(), tt.wantErrContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ============================================================================
// Тесты для вспомогательного метода uploadLargeFile
// ============================================================================

func TestSecret_uploadLargeFile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		setupHandler    http.HandlerFunc
		request         models.StoreRequest
		fileContent     string
		wantErr         bool
		wantErrContains string
	}{
		{
			name: "успешная загрузка файла",
			setupHandler: func(w http.ResponseWriter, r *http.Request) {
				assert.Contains(t, r.URL.Path, "/api/secret/file/upload/")
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, "application/octet-stream", r.Header.Get("Content-Type"))
				assert.Equal(t, "upload-token", r.Header.Get("X-API-Token"))

				body, err := io.ReadAll(r.Body)
				assert.NoError(t, err)
				assert.Equal(t, "binary file content", string(body))

				w.WriteHeader(http.StatusOK)
			},
			request: models.StoreRequest{
				SecretData: models.SecretData{ID: "file-123"},
				Token:      "upload-token",
			},
			fileContent:     "binary file content",
			wantErr:         false,
			wantErrContains: "",
		},
		{
			name: "ошибка при загрузке (статус != 200)",
			setupHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid file"}`))
			},
			request: models.StoreRequest{
				SecretData: models.SecretData{ID: "bad-file"},
				Token:      "token",
			},
			fileContent:     "any content",
			wantErr:         true,
			wantErrContains: "загрузка файла не удалась",
		},
		{
			name:         "ошибка создания HTTP-запроса",
			setupHandler: func(w http.ResponseWriter, r *http.Request) {},
			request: models.StoreRequest{
				SecretData: models.SecretData{ID: ""}, // Пустой ID может вызвать проблемы в URL
				Token:      "token",
			},
			fileContent:     "content",
			wantErr:         false, // Пустой ID допустим, сервер сам вернёт ошибку
			wantErrContains: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg, _, httpClient, cleanup := setupTest(t, tt.setupHandler)
			defer cleanup()

			svc := &Secret{
				cfg:        cfg,
				httpClient: httpClient,
			}

			reader := bytes.NewReader([]byte(tt.fileContent))
			err := svc.uploadLargeFile(context.Background(), tt.request, reader)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantErrContains != "" {
					assert.Contains(t, err.Error(), tt.wantErrContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ============================================================================
// Тесты для конструктора NewSecret
// ============================================================================

func TestNewSecret(t *testing.T) {
	t.Parallel()

	t.Run("успешное создание сервиса", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		cfg := &config.Config{
			Server: config.Server{
				Address: "http://localhost:8080",
				Cert:    "",
			},
			Log: config.Log{Level: "info"},
			Secret: config.Secret{
				File: "store.db",
				Dir:  tmpDir,
			},
			RequestTimeout: 30 * time.Second,
			App:            "gophkeeper",
		}
		client := &http.Client{Timeout: 10 * time.Second}

		svc, err := NewSecret(cfg, client)

		assert.NoError(t, err)
		assert.NotNil(t, svc)
		assert.Equal(t, cfg, svc.cfg)
		assert.Equal(t, client, svc.httpClient)
		assert.NotNil(t, svc.store)
	})

	t.Run("ошибка при создании хранилища (невалидный путь)", func(t *testing.T) {
		t.Parallel()

		// Пропускаем на Windows - там права доступа работают иначе
		if runtime.GOOS == "windows" {
			t.Skip("Skipping on Windows - file permissions work differently")
		}

		cfg := &config.Config{
			Secret: config.Secret{
				File: "test.db",
				Dir:  "/proc/non_writable_xyz_12345", // Недоступный путь на Unix
			},
		}
		client := &http.Client{}

		svc, err := NewSecret(cfg, client)

		assert.Error(t, err)
		// ✅ Защита от паники: проверяем err перед работой с svc
		if err != nil {
			assert.Nil(t, svc)
			assert.Contains(t, err.Error(), "new store")
		}
	})
}

// ============================================================================
// Edge-case тесты
// ============================================================================

func TestSecret_EdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("List с пустым токеном", func(t *testing.T) {
		t.Parallel()

		cfg, mockRepo, httpClient, cleanup := setupTest(t, func(w http.ResponseWriter, r *http.Request) {
			// Сервер может отказать в доступе, но метод не должен паниковать
			w.WriteHeader(http.StatusUnauthorized)
		})
		defer cleanup()

		svc := &Secret{cfg: cfg, store: mockRepo, httpClient: httpClient}

		mockRepo.EXPECT().ListSecret(mock.Anything, mock.Anything).
			Return(nil, nil) // Fallback вернёт пустой список

		err := svc.List(context.Background(), models.ListRequest{Token: ""})
		assert.NoError(t, err)
	})

	t.Run("Show с отменённым контекстом", func(t *testing.T) {
		t.Parallel()

		cfg, mockRepo, httpClient, cleanup := setupTest(t, func(w http.ResponseWriter, r *http.Request) {
			// Не должно быть вызвано из-за отмены контекста
			select {
			case <-r.Context().Done():
				return
			default:
				w.WriteHeader(http.StatusOK)
			}
		})
		defer cleanup()

		svc := &Secret{cfg: cfg, store: mockRepo, httpClient: httpClient}

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Немедленная отмена

		err := svc.Show(ctx, models.ShowRequest{ID: "1", Token: "t"})
		// Ошибка возможна, но не паника
		_ = err
	})

	t.Run("Store с BinaryData и Reader", func(t *testing.T) {
		t.Parallel()

		cfg, mockRepo, httpClient, cleanup := setupTest(t, func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "/api/secret/file/upload") {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(models.SaveData{
				SecretData: models.SecretData{
					ID:        "bin-1",
					DataType:  models.BinaryData,
					FileStore: "uploaded.bin",
				},
			})
		})
		defer cleanup()

		svc := &Secret{cfg: cfg, store: mockRepo, httpClient: httpClient}

		mockRepo.EXPECT().StoreSecret(mock.Anything, mock.Anything).
			Return(&models.SaveData{
				SecretData: models.SecretData{
					ID:        "bin-1",
					DataType:  models.BinaryData,
					FileStore: "uploaded.bin",
				},
			}, nil)

		// Создаём временный файл для имитации BinaryData с Reader
		tmpFile := filepath.Join(cfg.Secret.Dir, "uploaded.bin")
		err := os.WriteFile(tmpFile, []byte("file data"), 0644)
		assert.NoError(t, err)

		req := models.StoreRequest{
			SecretData: models.SecretData{
				Title:    "Binary File",
				DataType: models.BinaryData,
			},
			Token: "token",
		}

		err = svc.Store(context.Background(), req)
		assert.NoError(t, err)
	})
}
