package pg

import (
	"context"
	"fmt"
	"github.com/Evlushin/GophKeeper/internal/server/models"
	"gorm.io/gorm"
)

type PgUser struct {
	conn *gorm.DB
}

func NewPgUser(db *gorm.DB) *PgUser {
	return &PgUser{conn: db}
}

func (r *PgUser) Create(ctx context.Context, user *models.User) error {
	err := r.conn.WithContext(ctx).
		Create(user).Error
	if err != nil {
		return fmt.Errorf("create user in repo: %w", err)
	}
	return nil
}

func (r *PgUser) FindByLogin(ctx context.Context, login string) (*models.User, error) {
	var user models.User
	err := r.conn.WithContext(ctx).
		Where("login = ?", login).
		First(&user).Error
	if err != nil {
		return nil, fmt.Errorf("find user by login in repo: %w", err)
	}
	return &user, nil
}

func (r *PgUser) FindByID(ctx context.Context, id models.UserID) (*models.User, error) {
	var user models.User
	err := r.conn.WithContext(ctx).
		First(&user, id).Error
	if err != nil {
		return nil, fmt.Errorf("find user by id in repo: %w", err)
	}
	return &user, nil
}

func (r *PgUser) ExistsByLogin(ctx context.Context, login string) (bool, error) {
	var count int64
	err := r.conn.WithContext(ctx).
		Model(&models.User{}).
		Where("login = ?", login).
		Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("check if user exists by login in repo: %w", err)
	}
	return count > 0, nil
}
