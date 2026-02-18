package middleware

import (
	"github.com/Evlushin/GophKeeper/internal/server/handler/config"
	"github.com/Evlushin/GophKeeper/internal/server/handler/middleware/mocks"
	"github.com/Evlushin/GophKeeper/internal/server/models"
	utils "github.com/Evlushin/GophKeeper/internal/server/utils/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewAuth(t *testing.T) {
	logger := zap.NewNop()
	cfg := &config.Config{
		AuthConfig: config.AuthConfig{
			AuthCookieName:     config.DefaultAuthCookieName,
			AuthExpireDuration: config.DefaultAuthExpireDuration,
		},
	}

	createTestOkHandler := func(handlerCalled *bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			*handlerCalled = true
			w.WriteHeader(http.StatusOK)
		}
	}

	t.Run("successful authentication", func(t *testing.T) {
		// Setup
		mockAuth := mocks.NewMockAuthUserValidator(t)
		authMiddleware := NewAuth(cfg, logger, mockAuth)

		expectedUserID := models.UserID(123)
		expectedUser := &models.User{
			ID:    expectedUserID,
			Login: "testuser",
		}

		token := "valid-token"

		mockAuth.EXPECT().
			ValidateToken(token).
			Return(expectedUserID, nil).
			Once()
		mockAuth.EXPECT().
			ValidateUser(mock.Anything, expectedUserID).
			Return(expectedUser, nil).
			Once()

		handlerCalled := false
		testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			userID, err := utils.GetCtxUserID(r.Context())
			assert.NoError(t, err)
			assert.Equal(t, expectedUserID, userID)
			w.WriteHeader(http.StatusOK)
		})

		// Execute
		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{
			Name:  cfg.AuthCookieName,
			Value: token,
		})
		rr := httptest.NewRecorder()

		authMiddleware(testHandler).ServeHTTP(rr, req)

		// Assert
		assert.True(t, handlerCalled)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("no auth cookie", func(t *testing.T) {
		// Setup
		mockAuth := mocks.NewMockAuthUserValidator(t)
		authMiddleware := NewAuth(cfg, logger, mockAuth)

		handlerCalled := false
		testHandler := createTestOkHandler(&handlerCalled)

		// Execute
		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()

		authMiddleware(testHandler).ServeHTTP(rr, req)

		// Assert
		assert.False(t, handlerCalled)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("empty auth cookie", func(t *testing.T) {
		// Setup
		mockAuth := mocks.NewMockAuthUserValidator(t)
		authMiddleware := NewAuth(cfg, logger, mockAuth)

		handlerCalled := false
		testHandler := createTestOkHandler(&handlerCalled)

		// Execute
		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{
			Name:  cfg.AuthCookieName,
			Value: "",
		})
		rr := httptest.NewRecorder()

		authMiddleware(testHandler).ServeHTTP(rr, req)

		// Assert
		assert.False(t, handlerCalled)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		mockAuth.AssertExpectations(t)
	})

	t.Run("invalid token", func(t *testing.T) {
		// Setup
		mockAuth := mocks.NewMockAuthUserValidator(t)
		authMiddleware := NewAuth(cfg, logger, mockAuth)

		token := "invalid-token"

		mockAuth.EXPECT().
			ValidateToken(token).
			Return(models.UserID(0), assert.AnError).
			Once()

		handlerCalled := false
		testHandler := createTestOkHandler(&handlerCalled)

		// Execute
		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{
			Name:  cfg.AuthCookieName,
			Value: token,
		})

		rr := httptest.NewRecorder()

		authMiddleware(testHandler).ServeHTTP(rr, req)

		// Assert
		assert.False(t, handlerCalled)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("invalid user", func(t *testing.T) {
		// Setup
		mockAuth := mocks.NewMockAuthUserValidator(t)
		authMiddleware := NewAuth(cfg, logger, mockAuth)

		expectedUserID := models.UserID(123)
		token := "valid-token"

		mockAuth.EXPECT().
			ValidateToken(token).
			Return(expectedUserID, nil).
			Once()
		mockAuth.EXPECT().
			ValidateUser(mock.Anything, expectedUserID).
			Return((*models.User)(nil), assert.AnError).
			Once()

		handlerCalled := false
		testHandler := createTestOkHandler(&handlerCalled)

		// Execute
		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{
			Name:  cfg.AuthCookieName,
			Value: token,
		})

		rr := httptest.NewRecorder()

		authMiddleware(testHandler).ServeHTTP(rr, req)

		// Assert
		assert.False(t, handlerCalled)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})
}
