package auth

import (
	"context"
	"fmt"
	"github.com/Evlushin/GophKeeper/internal/server/models"
)

type AuthTokenProvider interface {
	Generate(userID models.UserID) (string, error)
	Parse(tokenString string) (models.UserID, error)
}

type AuthUserProvider interface {
	Create(ctx context.Context, login, password string) (*models.User, error)
	Authenticate(ctx context.Context, login, password string) (*models.User, error)
	GetByID(ctx context.Context, userID models.UserID) (*models.User, error)
}

type Auth struct {
	user  AuthUserProvider
	token AuthTokenProvider
}

func NewAuth(u AuthUserProvider, t AuthTokenProvider) *Auth {
	return &Auth{
		user:  u,
		token: t,
	}
}

//nolint:dupl // register and login are different business processes with possible same structure
func (s *Auth) Register(ctx context.Context, login, password string) (*models.User, string, error) {
	user, err := s.user.Create(ctx, login, password)
	if err != nil {
		return nil, "", fmt.Errorf("create user: %w", err)
	}

	token, err := s.token.Generate(user.ID)
	if err != nil {
		return nil, "", fmt.Errorf("generate token: %w", err)
	}

	return user, token, nil
}

//nolint:dupl // register and login are different business processes with possible same structure
func (s *Auth) Login(ctx context.Context, login, password string) (*models.User, string, error) {
	user, err := s.user.Authenticate(ctx, login, password)
	if err != nil {
		return nil, "", fmt.Errorf("authenticate user: %w", err)
	}

	token, err := s.token.Generate(user.ID)
	if err != nil {
		return nil, "", fmt.Errorf("generate token: %w", err)
	}

	return user, token, nil
}

func (s *Auth) ValidateUser(ctx context.Context, userID models.UserID) (*models.User, error) {
	user, err := s.user.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("get user by ID: %w", err)
	}
	return user, nil
}

func (s *Auth) ValidateToken(tokenString string) (models.UserID, error) {
	userID, err := s.token.Parse(tokenString)
	if err != nil {
		return 0, fmt.Errorf("parse token: %w", err)
	}
	return userID, nil
}
