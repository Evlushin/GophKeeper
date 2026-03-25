package auth

import (
	"github.com/Evlushin/GophKeeper/internal/server/models"
	"github.com/Evlushin/GophKeeper/internal/server/service/auth/mocks"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

//nolint:dupl // register and login tests are similar
func TestAuth_Register(t *testing.T) {
	type args struct {
		login    string
		password string
	}
	tests := []struct {
		name       string
		args       args
		setupMocks func(um *mocks.MockAuthUserProvider, tm *mocks.MockAuthTokenProvider)
		wantUser   *models.User
		wantToken  string
		wantErr    error
	}{
		{
			name: "success",
			args: args{login: "test", password: "password"},
			setupMocks: func(um *mocks.MockAuthUserProvider, tm *mocks.MockAuthTokenProvider) {
				createdUser := &models.User{ID: 42, Login: "test"}
				um.EXPECT().
					Create(mock.Anything, "test", "password").
					Return(createdUser, nil).
					Once()
				tm.EXPECT().
					Generate(createdUser.ID).
					Return("jwt-token", nil).
					Once()
			},
			wantUser:  &models.User{ID: 42, Login: "test"},
			wantToken: "jwt-token",
			wantErr:   nil,
		},
		{
			name: "create error",
			args: args{login: "test", password: "password"},
			setupMocks: func(um *mocks.MockAuthUserProvider, _ *mocks.MockAuthTokenProvider) {
				um.EXPECT().
					Create(mock.Anything, "test", "password").
					Return((*models.User)(nil), assert.AnError).
					Once()
			},
			wantUser:  nil,
			wantToken: "",
			wantErr:   assert.AnError,
		},
		{
			name: "token generate error",
			args: args{login: "test", password: "password"},
			setupMocks: func(um *mocks.MockAuthUserProvider, tm *mocks.MockAuthTokenProvider) {
				createdUser := &models.User{ID: 7, Login: "test"}
				um.EXPECT().
					Create(mock.Anything, "test", "password").
					Return(createdUser, nil).
					Once()
				tm.EXPECT().
					Generate(createdUser.ID).
					Return("", assert.AnError).
					Once()
			},
			wantUser:  nil,
			wantToken: "",
			wantErr:   assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userMock := mocks.NewMockAuthUserProvider(t)
			tokenMock := mocks.NewMockAuthTokenProvider(t)

			if tt.setupMocks != nil {
				tt.setupMocks(userMock, tokenMock)
			}

			auth := NewAuth(userMock, tokenMock)
			u, tok, err := auth.Register(t.Context(), tt.args.login, tt.args.password)

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				require.Nil(t, u)
				require.Empty(t, tok)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.wantUser, u)
			require.Equal(t, tt.wantToken, tok)
		})
	}
}

//nolint:dupl // register and login tests are similar
func TestAuth_Login(t *testing.T) {
	type args struct {
		login    string
		password string
	}
	tests := []struct {
		name       string
		args       args
		setupMocks func(um *mocks.MockAuthUserProvider, tm *mocks.MockAuthTokenProvider)
		wantUser   *models.User
		wantToken  string
		wantErr    error
	}{
		{
			name: "success",
			args: args{login: "test", password: "password"},
			setupMocks: func(um *mocks.MockAuthUserProvider, tm *mocks.MockAuthTokenProvider) {
				authUser := &models.User{ID: 100, Login: "test"}
				um.EXPECT().
					Authenticate(mock.Anything, "test", "password").
					Return(authUser, nil).
					Once()
				tm.EXPECT().
					Generate(authUser.ID).
					Return("jwt-token", nil).
					Once()
			},
			wantUser:  &models.User{ID: 100, Login: "test"},
			wantToken: "jwt-token",
			wantErr:   nil,
		},
		{
			name: "authenticate error",
			args: args{login: "test", password: "bad"},
			setupMocks: func(um *mocks.MockAuthUserProvider, _ *mocks.MockAuthTokenProvider) {
				um.EXPECT().
					Authenticate(mock.Anything, "test", "bad").
					Return((*models.User)(nil), assert.AnError).
					Once()
			},
			wantUser:  nil,
			wantToken: "",
			wantErr:   assert.AnError,
		},
		{
			name: "token generate error",
			args: args{login: "test", password: "password"},
			setupMocks: func(um *mocks.MockAuthUserProvider, tm *mocks.MockAuthTokenProvider) {
				authUser := &models.User{ID: 11, Login: "test"}
				um.EXPECT().
					Authenticate(mock.Anything, "test", "password").
					Return(authUser, nil).
					Once()
				tm.EXPECT().
					Generate(authUser.ID).
					Return("", assert.AnError).
					Once()
			},
			wantUser:  nil,
			wantToken: "",
			wantErr:   assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userMock := mocks.NewMockAuthUserProvider(t)
			tokenMock := mocks.NewMockAuthTokenProvider(t)

			if tt.setupMocks != nil {
				tt.setupMocks(userMock, tokenMock)
			}

			auth := NewAuth(userMock, tokenMock)
			u, tok, err := auth.Login(t.Context(), tt.args.login, tt.args.password)

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				require.Nil(t, u)
				require.Empty(t, tok)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.wantUser, u)
			require.Equal(t, tt.wantToken, tok)
		})
	}
}

func TestAuth_ValidateUser(t *testing.T) {
	type args struct {
		userID models.UserID
	}
	tests := []struct {
		name      string
		args      args
		setupMock func(um *mocks.MockAuthUserProvider)
		wantUser  *models.User
		wantErr   error
	}{
		{
			name: "success",
			args: args{userID: 5},
			setupMock: func(um *mocks.MockAuthUserProvider) {
				user := &models.User{ID: 5, Login: "test"}
				um.EXPECT().
					GetByID(mock.Anything, models.UserID(5)).
					Return(user, nil).
					Once()
			},
			wantUser: &models.User{ID: 5, Login: "test"},
			wantErr:  nil,
		},
		{
			name: "get by id error",
			args: args{userID: 5},
			setupMock: func(um *mocks.MockAuthUserProvider) {
				um.EXPECT().
					GetByID(mock.Anything, models.UserID(5)).
					Return((*models.User)(nil), assert.AnError)
			},
			wantUser: nil,
			wantErr:  assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userMock := mocks.NewMockAuthUserProvider(t)
			tokenMock := mocks.NewMockAuthTokenProvider(t)

			if tt.setupMock != nil {
				tt.setupMock(userMock)
			}

			auth := NewAuth(userMock, tokenMock)
			got, err := auth.ValidateUser(t.Context(), tt.args.userID)

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				require.Nil(t, got)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.wantUser, got)
		})
	}
}

func TestAuth_ValidateToken(t *testing.T) {
	type args struct {
		token string
	}
	tests := []struct {
		name       string
		args       args
		setupMock  func(tm *mocks.MockAuthTokenProvider)
		wantUserID models.UserID
		wantErr    error
	}{
		{
			name: "success",
			args: args{token: "jwt-token"},
			setupMock: func(tm *mocks.MockAuthTokenProvider) {
				tm.EXPECT().
					Parse("jwt-token").
					Return(models.UserID(77), nil).
					Once()
			},
			wantUserID: 77,
			wantErr:    nil,
		},
		{
			name: "parse error",
			args: args{token: "bad"},
			setupMock: func(tm *mocks.MockAuthTokenProvider) {
				tm.EXPECT().
					Parse("bad").
					Return(models.UserID(0), assert.AnError)
			},
			wantUserID: 0,
			wantErr:    assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userMock := mocks.NewMockAuthUserProvider(t)
			tokenMock := mocks.NewMockAuthTokenProvider(t)

			if tt.setupMock != nil {
				tt.setupMock(tokenMock)
			}

			auth := NewAuth(userMock, tokenMock)
			gotUserID, err := auth.ValidateToken(tt.args.token)

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				require.Equal(t, models.UserID(0), gotUserID)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.wantUserID, gotUserID)
		})
	}
}
