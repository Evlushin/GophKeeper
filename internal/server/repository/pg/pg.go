package pg

import (
	"context"
	"errors"
	"fmt"
	"github.com/Evlushin/GophKeeper/internal/myerrors"
	"github.com/Evlushin/GophKeeper/internal/server/models"
	"github.com/Evlushin/GophKeeper/internal/server/repository/pg/migrator"
	_ "github.com/jackc/pgx/v5/stdlib"
	"gorm.io/gorm"
	"time"
)

type Store struct {
	conn *gorm.DB
}

func NewStore(conn *gorm.DB) (*Store, error) {
	err := migrator.ApplyMigrations(conn, "file://./migrations")
	if err != nil {
		return nil, fmt.Errorf("no migrations: %w", err)
	}

	return &Store{
		conn: conn,
	}, nil
}

func (st *Store) Ping(ctx context.Context) error {
	err := st.conn.WithContext(ctx).Exec("SELECT 1").Error
	if err != nil {
		return fmt.Errorf("no ping in repository: %w", err)
	}
	return nil
}

func newErrSecretNotFound(id string) error {
	return fmt.Errorf("%w for id = %s", myerrors.ErrGetSecretNotFound, id)
}

func (st *Store) CountSecret(ctx context.Context, indexSecret models.IndexSecret) (int64, error) {
	var count int64
	res := st.conn.
		WithContext(ctx).
		Table("secrets").
		Where("user_id = ?", indexSecret.UserID).
		Where("deleted_at IS NULL").
		Count(&count)
	if res.Error != nil {
		return 0, fmt.Errorf("count secrets: %w", res.Error)
	}

	return count, nil
}

func (st *Store) IndexSecret(ctx context.Context, indexSecret models.IndexSecret) ([]models.SecretData, error) {
	var secrets []models.SecretData

	query := st.conn.
		WithContext(ctx).
		Table("secrets").
		Where("user_id = ?", indexSecret.UserID).
		Where("deleted_at IS NULL")

	if indexSecret.Type != "" {
		query = query.Where("type = ?", indexSecret.Type)
	}

	err := query.Order("updated_at asc").
		Find(&secrets).
		Error

	if err != nil {
		return nil, fmt.Errorf("failed to query secrets: %w", err)
	}

	return secrets, nil
}

func (st *Store) StoreSecret(ctx context.Context, storeSecret models.StoreSecret) error {

	result := st.conn.WithContext(ctx).
		Table("secrets").
		Create(&storeSecret)

	if result.Error != nil {
		return fmt.Errorf("failed to save secret: %w", result.Error)
	}

	return nil
}

func (st *Store) GetSecret(ctx context.Context, getSecret models.ShowSecret) (*models.SecretData, error) {
	var secret models.SecretData

	result := st.conn.WithContext(ctx).
		Where("id = ?", getSecret.ID).
		Where("user_id = ?", getSecret.UserID).
		Where("deleted_at IS NULL").
		First(&secret)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, newErrSecretNotFound(getSecret.ID)
		}
		return nil, fmt.Errorf("failed to get order: %w", result.Error)
	}

	return &secret, nil
}

func (st *Store) UpdateSecret(ctx context.Context, updateSecret models.UpdateSecret) error {
	err := st.conn.
		WithContext(ctx).
		Table("withdrawals").
		Where("id = ? AND deleted_at IS NULL", updateSecret.ID).
		Where("user_id = ?", updateSecret.UserID).
		Updates(&updateSecret).
		Error

	if err != nil {
		return fmt.Errorf("failed to update secret: %w", err)
	}

	return nil
}

func (st *Store) DeleteSecret(ctx context.Context, deleteSecret models.DeleteSecret) error {
	result := st.conn.
		WithContext(ctx).
		Table("withdrawals").
		Where("id = ? AND user_id = ? AND deleted_at IS NULL", deleteSecret.ID, deleteSecret.UserID).
		Update("deleted_at", time.Now())

	if result.Error != nil {
		return fmt.Errorf("failed to delete secret: %w", result.Error)
	}

	// Проверяем, была ли найдена запись
	if result.RowsAffected == 0 {
		return fmt.Errorf("secret not found or already deleted")
	}

	return nil
}
