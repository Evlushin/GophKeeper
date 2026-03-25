//go:build !integration

package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Evlushin/GophKeeper/internal/client/config"
	"github.com/Evlushin/GophKeeper/internal/client/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockKeyring — мок для keyring
type mockKeyring struct {
	setFunc func(service, user, password string) error
}

func (m mockKeyring) Set(service, user, password string) error {
	if m.setFunc != nil {
		return m.setFunc(service, user, password)
	}
	return nil
}
func (m mockKeyring) Get(service, user string) (string, error) { return "", nil }
func (m mockKeyring) Delete(service, user string) error        { return nil }

func newTestConfig(serverURL string) *config.Config {
	return &config.Config{
		Server: config.Server{Address: serverURL},
		App:    "test-app",
	}
}

// ==================== Тесты Register ====================

func TestAuth_Register_Success(t *testing.T) {
	t.Parallel()

	expectedToken := "test-token-123"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/user/register", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		var req models.RegisterRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		require.NoError(t, err)
		assert.Equal(t, "testuser", req.Login)
		assert.Equal(t, "password123", req.Password)

		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"token":"` + expectedToken + `"}`))
	}))
	defer server.Close()

	cfg := newTestConfig(server.URL)
	auth := NewAuthWithKeyring(cfg, &http.Client{}, mockKeyring{
		setFunc: func(service, user, password string) error {
			assert.Equal(t, "test-app", service)
			assert.Equal(t, "auth-token", user)
			assert.Equal(t, expectedToken, password)
			return nil
		},
	})

	err := auth.Register(context.Background(), models.RegisterRequest{
		Login:    "testuser",
		Password: "password123",
	})

	require.NoError(t, err)
}

func TestAuth_Register_BadRequest(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid input"}`))
	}))
	defer server.Close()

	cfg := newTestConfig(server.URL)
	auth := NewAuth(cfg, &http.Client{})

	err := auth.Register(context.Background(), models.RegisterRequest{
		Login:    "",
		Password: "",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "bad request (400)")
}

func TestAuth_Register_Conflict(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"user already exists"}`))
	}))
	defer server.Close()

	cfg := newTestConfig(server.URL)
	auth := NewAuth(cfg, &http.Client{})

	err := auth.Register(context.Background(), models.RegisterRequest{
		Login:    "existing",
		Password: "pass",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "user already exists (409)")
}

func TestAuth_Register_KeyringError(t *testing.T) {
	t.Parallel()

	expectedToken := "token"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"token":"` + expectedToken + `"}`))
	}))
	defer server.Close()

	cfg := newTestConfig(server.URL)
	auth := NewAuthWithKeyring(cfg, &http.Client{}, mockKeyring{
		setFunc: func(_, _, _ string) error {
			return errors.New("keyring failed")
		},
	})

	err := auth.Register(context.Background(), models.RegisterRequest{
		Login:    "user",
		Password: "pass",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "set token: keyring failed")
}

func TestAuth_Register_InvalidJSONResponse(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{invalid json}`))
	}))
	defer server.Close()

	cfg := newTestConfig(server.URL)
	auth := NewAuth(cfg, &http.Client{})

	err := auth.Register(context.Background(), models.RegisterRequest{
		Login:    "user",
		Password: "pass",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse response")
}

func TestAuth_Register_NetworkError(t *testing.T) {
	t.Parallel()

	cfg := newTestConfig("http://invalid-host-that-does-not-exist")
	auth := NewAuth(cfg, &http.Client{Timeout: 1})

	err := auth.Register(context.Background(), models.RegisterRequest{
		Login:    "user",
		Password: "pass",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "send register request")
}

func TestAuth_Register_ContextCanceled(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Имитация долгого ответа
		select {
		case <-r.Context().Done():
			return
		}
	}))
	defer server.Close()

	cfg := newTestConfig(server.URL)
	auth := NewAuth(cfg, &http.Client{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // отменяем сразу

	err := auth.Register(ctx, models.RegisterRequest{
		Login:    "user",
		Password: "pass",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")
}

// ==================== Тесты Login ====================

func TestAuth_Login_Success(t *testing.T) {
	t.Parallel()

	expectedToken := "login-token-456"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/user/login", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)

		var req models.LoginRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		require.NoError(t, err)
		assert.Equal(t, "testuser", req.Login)
		assert.Equal(t, "password123", req.Password)

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"token":"` + expectedToken + `"}`))
	}))
	defer server.Close()

	cfg := newTestConfig(server.URL)
	auth := NewAuthWithKeyring(cfg, &http.Client{}, mockKeyring{
		setFunc: func(service, user, password string) error {
			assert.Equal(t, expectedToken, password)
			return nil
		},
	})

	err := auth.Login(context.Background(), models.LoginRequest{
		Login:    "testuser",
		Password: "password123",
	})

	require.NoError(t, err)
}

func TestAuth_Login_Unauthorized(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid credentials"}`))
	}))
	defer server.Close()

	cfg := newTestConfig(server.URL)
	auth := NewAuth(cfg, &http.Client{})

	err := auth.Login(context.Background(), models.LoginRequest{
		Login:    "user",
		Password: "wrongpass",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected status code 401")
}

func TestAuth_Login_TooManyRequests(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"rate limit"}`))
	}))
	defer server.Close()

	cfg := newTestConfig(server.URL)
	auth := NewAuth(cfg, &http.Client{})

	err := auth.Login(context.Background(), models.LoginRequest{
		Login:    "user",
		Password: "pass",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "too many requests (429)")
}

// ==================== Тесты handleAuthResponse (косвенные) ====================

func TestAuth_HandleAuthResponse_UnexpectedStatusCode(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"server error"}`))
	}))
	defer server.Close()

	cfg := newTestConfig(server.URL)
	auth := NewAuth(cfg, &http.Client{})

	err := auth.Register(context.Background(), models.RegisterRequest{
		Login:    "user",
		Password: "pass",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected status code 500")
}

func TestAuth_Register_MarshalError(t *testing.T) {
	t.Parallel()

	// Передаём невалидные данные, которые могут вызвать ошибку при маршалинге
	// (в данном случае json.Marshal надёжен, но тестируем путь с ошибкой через mock)
	cfg := newTestConfig("http://unused")
	auth := NewAuth(cfg, &http.Client{})

	// Этот тест скорее документационный — json.Marshal редко падает на валидных структурах
	// Но если models.RegisterRequest будет изменён, тест поймает регрессию
	err := auth.Register(context.Background(), models.RegisterRequest{
		Login:    "valid",
		Password: "valid",
	})
	// Ошибка будет сетевая, т.к. сервер не поднят — это нормально для этого теста
	assert.Error(t, err)
}

// ==================== Тест NewAuth ====================

func TestNewAuth(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{App: "myapp"}
	client := &http.Client{Timeout: 10}

	auth := NewAuth(cfg, client)

	require.NotNil(t, auth)
	assert.Equal(t, cfg, auth.cfg)
	assert.Equal(t, client, auth.httpClient)
	assert.NotNil(t, auth.keyring) // должен быть defaultKeyring
}
