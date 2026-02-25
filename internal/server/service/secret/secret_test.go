package secret

import (
	"context"
	"errors"
	"github.com/Evlushin/GophKeeper/internal/server/service/secret/mocks"
	"github.com/stretchr/testify/mock"
	"testing"
	"time"

	"github.com/Evlushin/GophKeeper/internal/server/models"
	"github.com/stretchr/testify/assert"
)

func TestSecret_Ping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		mockSetup   func(*mocks.MockRepository)
		expectedErr bool
	}{
		{
			name: "success",
			mockSetup: func(m *mocks.MockRepository) {
				m.EXPECT().Ping(mock.Anything).Return(nil)
			},
			expectedErr: false,
		},
		{
			name: "repository error",
			mockSetup: func(m *mocks.MockRepository) {
				m.EXPECT().Ping(mock.Anything).Return(errors.New("db connection failed"))
			},
			expectedErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockRepo := mocks.NewMockRepository(t)
			tt.mockSetup(mockRepo)

			svc := &Secret{store: mockRepo}
			err := svc.Ping(context.Background())

			if tt.expectedErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSecret_CountSecret(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	indexSecret := models.IndexSecret{
		UserID: 1,
		Type:   models.LoginPassword,
	}

	tests := []struct {
		name           string
		mockSetup      func(*mocks.MockRepository)
		expectedCount  int64
		expectedErr    bool
		expectedErrMsg string
	}{
		{
			name: "success with count",
			mockSetup: func(m *mocks.MockRepository) {
				m.EXPECT().CountSecret(ctx, indexSecret).Return(int64(5), nil)
			},
			expectedCount: 5,
			expectedErr:   false,
		},
		{
			name: "success with zero count",
			mockSetup: func(m *mocks.MockRepository) {
				m.EXPECT().CountSecret(ctx, indexSecret).Return(int64(0), nil)
			},
			expectedCount: 0,
			expectedErr:   false,
		},
		{
			name: "repository error",
			mockSetup: func(m *mocks.MockRepository) {
				m.EXPECT().CountSecret(ctx, indexSecret).Return(int64(0), errors.New("query failed"))
			},
			expectedCount:  0,
			expectedErr:    true,
			expectedErrMsg: "count secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockRepo := mocks.NewMockRepository(t)
			tt.mockSetup(mockRepo)

			svc := &Secret{store: mockRepo}
			count, err := svc.CountSecret(ctx, indexSecret)

			assert.Equal(t, tt.expectedCount, count)
			if tt.expectedErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErrMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSecret_IndexSecret(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	indexSecret := models.IndexSecret{
		UserID: 1,
		Type:   models.CardData,
	}

	expectedSecrets := []models.SecretData{
		{
			ID:        "secret-1",
			DataType:  models.CardData,
			Title:     "Bank Card",
			CreatedAt: time.Now(),
		},
		{
			ID:        "secret-2",
			DataType:  models.CardData,
			Title:     "Credit Card",
			CreatedAt: time.Now(),
		},
	}

	tests := []struct {
		name           string
		mockSetup      func(*mocks.MockRepository)
		expectedData   []models.SecretData
		expectedErr    bool
		expectedErrMsg string
	}{
		{
			name: "success with results",
			mockSetup: func(m *mocks.MockRepository) {
				m.EXPECT().IndexSecret(ctx, indexSecret).Return(expectedSecrets, nil)
			},
			expectedData: expectedSecrets,
			expectedErr:  false,
		},
		{
			name: "success with empty results",
			mockSetup: func(m *mocks.MockRepository) {
				m.EXPECT().IndexSecret(ctx, indexSecret).Return([]models.SecretData{}, nil)
			},
			expectedData: []models.SecretData{},
			expectedErr:  false,
		},
		{
			name: "repository error",
			mockSetup: func(m *mocks.MockRepository) {
				m.EXPECT().IndexSecret(ctx, indexSecret).Return(nil, errors.New("index query failed"))
			},
			expectedData:   nil,
			expectedErr:    true,
			expectedErrMsg: "index secrets",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockRepo := mocks.NewMockRepository(t)
			tt.mockSetup(mockRepo)

			svc := &Secret{store: mockRepo}
			result, err := svc.IndexSecret(ctx, indexSecret)

			assert.Equal(t, tt.expectedData, result)
			if tt.expectedErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErrMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSecret_StoreSecret(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	storeSecret := models.StoreSecret{
		SecretData: models.SecretData{
			ID:       "secret-123",
			DataType: models.LoginPassword,
			Title:    "My Login",
			Metadata: `{"login":"user","url":"example.com"}`,
		},
		UserID: 1,
	}

	tests := []struct {
		name           string
		mockSetup      func(*mocks.MockRepository)
		expectedErr    bool
		expectedErrMsg string
	}{
		{
			name: "success",
			mockSetup: func(m *mocks.MockRepository) {
				m.EXPECT().StoreSecret(ctx, storeSecret).Return(nil)
			},
			expectedErr: false,
		},
		{
			name: "repository error - duplicate",
			mockSetup: func(m *mocks.MockRepository) {
				m.EXPECT().StoreSecret(ctx, storeSecret).Return(errors.New("duplicate key"))
			},
			expectedErr:    true,
			expectedErrMsg: "store secret",
		},
		{
			name: "repository error - validation",
			mockSetup: func(m *mocks.MockRepository) {
				m.EXPECT().StoreSecret(ctx, storeSecret).Return(errors.New("invalid data"))
			},
			expectedErr:    true,
			expectedErrMsg: "store secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockRepo := mocks.NewMockRepository(t)
			tt.mockSetup(mockRepo)

			svc := &Secret{store: mockRepo}
			err := svc.StoreSecret(ctx, storeSecret)

			if tt.expectedErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErrMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSecret_GetSecret(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	showSecret := models.ShowSecret{
		ID:     "secret-123",
		UserID: 1,
	}

	expectedData := &models.SecretData{
		ID:        "secret-123",
		DataType:  models.LoginPassword,
		Title:     "My Login",
		Metadata:  `{"login":"user","url":"example.com"}`,
		Data:      []byte("encrypted_data"),
		CreatedAt: time.Now(),
	}

	tests := []struct {
		name           string
		mockSetup      func(*mocks.MockRepository)
		expectedData   *models.SecretData
		expectedErr    bool
		expectedErrMsg string
	}{
		{
			name: "success",
			mockSetup: func(m *mocks.MockRepository) {
				m.EXPECT().GetSecret(ctx, showSecret).Return(expectedData, nil)
			},
			expectedData: expectedData,
			expectedErr:  false,
		},
		{
			name: "not found",
			mockSetup: func(m *mocks.MockRepository) {
				m.EXPECT().GetSecret(ctx, showSecret).Return(nil, errors.New("not found"))
			},
			expectedData:   nil,
			expectedErr:    true,
			expectedErrMsg: "get secret",
		},
		{
			name: "database error",
			mockSetup: func(m *mocks.MockRepository) {
				m.EXPECT().GetSecret(ctx, showSecret).Return(nil, errors.New("query failed"))
			},
			expectedData:   nil,
			expectedErr:    true,
			expectedErrMsg: "get secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockRepo := mocks.NewMockRepository(t)
			tt.mockSetup(mockRepo)

			svc := &Secret{store: mockRepo}
			result, err := svc.GetSecret(ctx, showSecret)

			assert.Equal(t, tt.expectedData, result)
			if tt.expectedErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErrMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSecret_UpdateSecret(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	updateSecret := models.UpdateSecret{
		SecretData: models.SecretData{
			ID:        "secret-123",
			DataType:  models.LoginPassword,
			Title:     "Updated Login",
			Metadata:  `{"login":"newuser","url":"newexample.com"}`,
			UpdatedAt: time.Now(),
		},
		UserID: 1,
	}

	tests := []struct {
		name           string
		mockSetup      func(*mocks.MockRepository)
		expectedErr    bool
		expectedErrMsg string
	}{
		{
			name: "success",
			mockSetup: func(m *mocks.MockRepository) {
				m.EXPECT().UpdateSecret(ctx, updateSecret).Return(nil)
			},
			expectedErr: false,
		},
		{
			name: "not found",
			mockSetup: func(m *mocks.MockRepository) {
				m.EXPECT().UpdateSecret(ctx, updateSecret).Return(errors.New("record not found"))
			},
			expectedErr:    true,
			expectedErrMsg: "update secret",
		},
		{
			name: "validation error",
			mockSetup: func(m *mocks.MockRepository) {
				m.EXPECT().UpdateSecret(ctx, updateSecret).Return(errors.New("invalid update"))
			},
			expectedErr:    true,
			expectedErrMsg: "update secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockRepo := mocks.NewMockRepository(t)
			tt.mockSetup(mockRepo)

			svc := &Secret{store: mockRepo}
			err := svc.UpdateSecret(ctx, updateSecret)

			if tt.expectedErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErrMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSecret_DeleteSecret(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	deleteSecret := models.DeleteSecret{
		ID:     "secret-123",
		UserID: 1,
	}

	tests := []struct {
		name           string
		mockSetup      func(*mocks.MockRepository)
		expectedErr    bool
		expectedErrMsg string
	}{
		{
			name: "success",
			mockSetup: func(m *mocks.MockRepository) {
				m.EXPECT().DeleteSecret(ctx, deleteSecret).Return(nil)
			},
			expectedErr: false,
		},
		{
			name: "not found",
			mockSetup: func(m *mocks.MockRepository) {
				m.EXPECT().DeleteSecret(ctx, deleteSecret).Return(errors.New("not found"))
			},
			expectedErr:    true,
			expectedErrMsg: "delete secret",
		},
		{
			name: "permission denied",
			mockSetup: func(m *mocks.MockRepository) {
				m.EXPECT().DeleteSecret(ctx, deleteSecret).Return(errors.New("permission denied"))
			},
			expectedErr:    true,
			expectedErrMsg: "delete secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockRepo := mocks.NewMockRepository(t)
			tt.mockSetup(mockRepo)

			svc := &Secret{store: mockRepo}
			err := svc.DeleteSecret(ctx, deleteSecret)

			if tt.expectedErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErrMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Тесты для валидации моделей
func TestStoreSecret_Valid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		input        models.StoreSecret
		expectErrors bool
	}{
		{
			name: "valid store secret",
			input: models.StoreSecret{
				SecretData: models.SecretData{
					ID:       "secret-123",
					DataType: models.LoginPassword,
				},
				UserID: 1,
			},
			expectErrors: false,
		},
		{
			name: "missing id",
			input: models.StoreSecret{
				SecretData: models.SecretData{
					DataType: models.LoginPassword,
				},
				UserID: 1,
			},
			expectErrors: true,
		},
		{
			name: "missing datatype",
			input: models.StoreSecret{
				SecretData: models.SecretData{
					ID: "secret-123",
				},
				UserID: 1,
			},
			expectErrors: true,
		},
		{
			name: "missing both id and datatype",
			input: models.StoreSecret{
				SecretData: models.SecretData{},
				UserID:     1,
			},
			expectErrors: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			problems := tt.input.Valid()
			if tt.expectErrors {
				assert.NotEmpty(t, problems)
			} else {
				assert.Empty(t, problems)
			}
		})
	}
}

func TestUpdateSecret_Valid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		input        models.UpdateSecret
		expectErrors bool
	}{
		{
			name: "valid update secret",
			input: models.UpdateSecret{
				SecretData: models.SecretData{
					ID:       "secret-123",
					DataType: models.CardData,
				},
				UserID: 1,
			},
			expectErrors: false,
		},
		{
			name: "missing id",
			input: models.UpdateSecret{
				SecretData: models.SecretData{
					DataType: models.CardData,
				},
				UserID: 1,
			},
			expectErrors: true,
		},
		{
			name: "missing datatype",
			input: models.UpdateSecret{
				SecretData: models.SecretData{
					ID: "secret-123",
				},
				UserID: 1,
			},
			expectErrors: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			problems := tt.input.Valid()
			if tt.expectErrors {
				assert.NotEmpty(t, problems)
			} else {
				assert.Empty(t, problems)
			}
		})
	}
}
