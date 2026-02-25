package auth

import (
	"context"
	"errors"
	"fmt"
	"github.com/Evlushin/GophKeeper/internal/server/models"
	"github.com/Evlushin/GophKeeper/internal/server/utils/auth"

	"gorm.io/gorm"
)

var (
	ErrUserAlreadyExists  = errors.New("user already exists")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserNotFound       = errors.New("user not found")
)

type UserRepository interface {
	Create(ctx context.Context, user *models.User) error
	FindByLogin(ctx context.Context, login string) (*models.User, error)
	FindByID(ctx context.Context, id models.UserID) (*models.User, error)
	ExistsByLogin(ctx context.Context, login string) (bool, error)
}

type AuthUser struct {
	repo UserRepository
}

func NewAuthUser(r UserRepository) *AuthUser {
	return &AuthUser{
		repo: r,
	}
}

func (s *AuthUser) Create(ctx context.Context, login, password string) (*models.User, error) {
	exists, err := s.repo.ExistsByLogin(ctx, login)
	if err != nil {
		return nil, fmt.Errorf("check user existence: %w", err)
	}
	if exists {
		return nil, ErrUserAlreadyExists
	}

	hashedPassword, err := auth.HashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	user := &models.User{
		Login:        login,
		PasswordHash: hashedPassword,
	}

	if err = s.repo.Create(ctx, user); err != nil {
		return nil, fmt.Errorf("create user %s: %w", user.Login, err)
	}

	return user, nil
}

func (s *AuthUser) Authenticate(ctx context.Context, login, password string) (*models.User, error) {
	user, err := s.ValidateCredentials(ctx, login, password)
	if err != nil {
		return nil, fmt.Errorf("validate credentials: %w", err)
	}
	return user, nil
}

func (s *AuthUser) GetByID(ctx context.Context, id models.UserID) (*models.User, error) {
	user, err := s.repo.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("get user by ID: %w", err)
	}
	return user, nil
}

func (s *AuthUser) GetByLogin(ctx context.Context, login string) (*models.User, error) {
	user, err := s.repo.FindByLogin(ctx, login)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("get user by login: %w", err)
	}
	return user, nil
}

func (s *AuthUser) ValidateCredentials(ctx context.Context, login, password string) (*models.User, error) {
	user, err := s.repo.FindByLogin(ctx, login)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("find by login: %w", ErrInvalidCredentials)
		}
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	if err = auth.VerifyPassword(user.PasswordHash, password); err != nil {
		return nil, fmt.Errorf("verify password: %w", ErrInvalidCredentials)
	}

	return user, nil
}
