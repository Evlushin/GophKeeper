package auth

import (
	"github.com/Evlushin/GophKeeper/internal/server/models"
	"github.com/Evlushin/GophKeeper/internal/server/service/auth/mocks"
	"github.com/Evlushin/GophKeeper/internal/server/utils/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"testing"
	"time"
)

const testLogin = "testuser"

func TestAuthUser_Create(t *testing.T) {
	login := testLogin
	password := "testpassword"

	tests := []struct {
		name        string
		setupMock   func(*mocks.MockUserRepository)
		expectedErr error
	}{
		{
			name: "successful user creation",
			setupMock: func(m *mocks.MockUserRepository) {
				m.EXPECT().
					ExistsByLogin(mock.Anything, login).
					Return(false, nil).
					Once()
				m.EXPECT().
					Create(mock.Anything, mock.MatchedBy(func(user *models.User) bool {
						return user.Login == login && user.PasswordHash != ""
					})).
					Return(nil).
					Once()
			},
			expectedErr: nil,
		},
		{
			name: "user already exists",
			setupMock: func(m *mocks.MockUserRepository) {
				m.EXPECT().
					ExistsByLogin(mock.Anything, login).
					Return(true, nil).
					Once()
			},
			expectedErr: ErrUserAlreadyExists,
		},
		{
			name: "error checking user existence",
			setupMock: func(m *mocks.MockUserRepository) {
				m.EXPECT().
					ExistsByLogin(mock.Anything, login).
					Return(false, assert.AnError).
					Once()
			},
			expectedErr: assert.AnError,
		},
		{
			name: "error creating user",
			setupMock: func(m *mocks.MockUserRepository) {
				m.EXPECT().
					ExistsByLogin(mock.Anything, login).
					Return(false, nil).
					Once()
				m.EXPECT().
					Create(mock.Anything, mock.AnythingOfType("*models.User")).
					Return(assert.AnError).
					Once()
			},
			expectedErr: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := mocks.NewMockUserRepository(t)
			tt.setupMock(mockRepo)

			authUser := NewAuthUser(mockRepo)

			user, err := authUser.Create(t.Context(), login, password)

			if tt.expectedErr != nil {
				assert.ErrorIs(t, err, tt.expectedErr)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, user)
				assert.Equal(t, login, user.Login)
				assert.NotEmpty(t, user.PasswordHash)
			}
		})
	}
}

func TestAuthUser_Authenticate(t *testing.T) {
	login := testLogin
	password := "testpassword"
	correctPassword := "correctpassword"
	hashedPwd, err := auth.HashPassword(correctPassword)
	require.NoError(t, err)

	existingUser := &models.User{
		ID:           models.UserID(1),
		Login:        login,
		PasswordHash: hashedPwd,
		CreatedAt:    time.Now(),
	}

	tests := []struct {
		name         string
		setupMock    func(*mocks.MockUserRepository)
		password     string
		expectedUser *models.User
		expectedErr  error
	}{
		{
			name: "successful authentication",
			setupMock: func(m *mocks.MockUserRepository) {
				m.EXPECT().
					FindByLogin(mock.Anything, login).
					Return(existingUser, nil).
					Once()
			},
			password:     correctPassword,
			expectedUser: existingUser,
			expectedErr:  nil,
		},
		{
			name: "user not found",
			setupMock: func(m *mocks.MockUserRepository) {
				m.EXPECT().
					FindByLogin(mock.Anything, login).
					Return(nil, gorm.ErrRecordNotFound).
					Once()
			},
			password:     password,
			expectedUser: nil,
			expectedErr:  ErrInvalidCredentials,
		},
		{
			name: "repository error",
			setupMock: func(m *mocks.MockUserRepository) {
				m.EXPECT().
					FindByLogin(mock.Anything, login).
					Return(nil, assert.AnError).
					Once()
			},
			password:     password,
			expectedUser: nil,
			expectedErr:  assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := mocks.NewMockUserRepository(t)
			tt.setupMock(mockRepo)

			authUser := NewAuthUser(mockRepo)

			user, err := authUser.Authenticate(t.Context(), login, tt.password)

			if tt.expectedErr != nil {
				assert.ErrorIs(t, err, tt.expectedErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedUser, user)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

func TestAuthUser_GetByID(t *testing.T) {
	userID := models.UserID(1)

	expectedUser := &models.User{
		ID:        userID,
		Login:     "testuser",
		CreatedAt: time.Now(),
	}

	//nolint:dupl // GetByLogin and GetById are different function with possible same structure
	tests := []struct {
		name         string
		setupMock    func(*mocks.MockUserRepository)
		expectedUser *models.User
		expectedErr  error
	}{
		{
			name: "successful get by ID",
			setupMock: func(m *mocks.MockUserRepository) {
				m.EXPECT().
					FindByID(mock.Anything, userID).
					Return(expectedUser, nil).
					Once()
			},
			expectedUser: expectedUser,
			expectedErr:  nil,
		},
		{
			name: "user not found",
			setupMock: func(m *mocks.MockUserRepository) {
				m.EXPECT().
					FindByID(mock.Anything, userID).
					Return(nil, gorm.ErrRecordNotFound).
					Once()
			},
			expectedUser: nil,
			expectedErr:  ErrUserNotFound,
		},
		{
			name: "repository error",
			setupMock: func(m *mocks.MockUserRepository) {
				m.EXPECT().
					FindByID(mock.Anything, userID).
					Return(nil, assert.AnError).
					Once()
			},
			expectedUser: nil,
			expectedErr:  assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := mocks.NewMockUserRepository(t)
			tt.setupMock(mockRepo)

			authUser := NewAuthUser(mockRepo)

			user, err := authUser.GetByID(t.Context(), userID)

			if tt.expectedErr != nil {
				assert.ErrorIs(t, err, tt.expectedErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedUser, user)
			}
		})
	}
}

func TestAuthUser_GetByLogin(t *testing.T) {
	login := testLogin

	expectedUser := &models.User{
		ID:        models.UserID(1),
		Login:     login,
		CreatedAt: time.Now(),
	}

	//nolint:dupl // GetByLogin and GetById are different function with possible same structure
	tests := []struct {
		name         string
		setupMock    func(*mocks.MockUserRepository)
		expectedUser *models.User
		expectedErr  error
	}{
		{
			name: "successful get by login",
			setupMock: func(m *mocks.MockUserRepository) {
				m.EXPECT().
					FindByLogin(mock.Anything, login).
					Return(expectedUser, nil).
					Once()
			},
			expectedUser: expectedUser,
			expectedErr:  nil,
		},
		{
			name: "user not found",
			setupMock: func(m *mocks.MockUserRepository) {
				m.EXPECT().
					FindByLogin(mock.Anything, login).
					Return(nil, gorm.ErrRecordNotFound).
					Once()
			},
			expectedUser: nil,
			expectedErr:  ErrUserNotFound,
		},
		{
			name: "repository error",
			setupMock: func(m *mocks.MockUserRepository) {
				m.EXPECT().
					FindByLogin(mock.Anything, login).
					Return(nil, assert.AnError).
					Once()
			},
			expectedUser: nil,
			expectedErr:  assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := mocks.NewMockUserRepository(t)
			tt.setupMock(mockRepo)

			authUser := NewAuthUser(mockRepo)

			user, err := authUser.GetByLogin(t.Context(), login)

			if tt.expectedErr != nil {
				assert.ErrorIs(t, err, tt.expectedErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedUser, user)
			}
		})
	}
}

func TestAuthUser_ValidateCredentials(t *testing.T) {
	login := testLogin
	correctPassword := "correctpassword"
	wrongPassword := "wrongpassword"

	hashedPwd, err := auth.HashPassword(correctPassword)
	require.NoError(t, err)

	existingUser := &models.User{
		ID:           models.UserID(1),
		Login:        login,
		PasswordHash: hashedPwd,
		CreatedAt:    time.Now(),
	}

	tests := []struct {
		name          string
		setupMock     func(*mocks.MockUserRepository)
		password      string
		expectedUser  *models.User
		expectedError error
	}{
		{
			name: "successful validation",
			setupMock: func(m *mocks.MockUserRepository) {
				m.EXPECT().
					FindByLogin(mock.Anything, login).
					Return(existingUser, nil).
					Once()
			},
			password:      correctPassword,
			expectedUser:  existingUser,
			expectedError: nil,
		},
		{
			name: "user not found",
			setupMock: func(m *mocks.MockUserRepository) {
				m.EXPECT().
					FindByLogin(mock.Anything, login).
					Return(nil, gorm.ErrRecordNotFound).
					Once()
			},
			password:      correctPassword,
			expectedUser:  nil,
			expectedError: ErrInvalidCredentials,
		},
		{
			name: "repository error",
			setupMock: func(m *mocks.MockUserRepository) {
				m.EXPECT().
					FindByLogin(mock.Anything, login).
					Return(nil, assert.AnError).
					Once()
			},
			password:      correctPassword,
			expectedUser:  nil,
			expectedError: assert.AnError,
		},
		{
			name: "invalid password",
			setupMock: func(m *mocks.MockUserRepository) {
				m.EXPECT().
					FindByLogin(mock.Anything, login).
					Return(existingUser, nil).
					Once()
			},
			password:      wrongPassword,
			expectedUser:  nil,
			expectedError: ErrInvalidCredentials,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := mocks.NewMockUserRepository(t)
			tt.setupMock(mockRepo)

			authUser := NewAuthUser(mockRepo)

			user, err := authUser.ValidateCredentials(t.Context(), login, tt.password)

			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedUser, user)
			}
		})
	}
}
