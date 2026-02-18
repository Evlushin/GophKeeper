package secret

import (
	"context"
	"fmt"
	"github.com/Evlushin/GophKeeper/internal/server/models"
	"github.com/Evlushin/GophKeeper/internal/server/repository/pg"
	"gorm.io/gorm"
)

type Repository interface {
	CountSecret(ctx context.Context, indexSecret models.IndexSecret) (int64, error)
	IndexSecret(ctx context.Context, indexSecret models.IndexSecret) ([]models.SecretData, error)
	StoreSecret(ctx context.Context, storeSecret models.StoreSecret) error
	GetSecret(ctx context.Context, getSecret models.ShowSecret) (*models.SecretData, error)
	UpdateSecret(ctx context.Context, updateSecret models.UpdateSecret) error
	DeleteSecret(ctx context.Context, deleteSecret models.DeleteSecret) error
	Ping(ctx context.Context) error
}

type Secret struct {
	store Repository
}

func NewSecret(conn *gorm.DB) (*Secret, error) {
	store, err := NewRepository(conn)
	if err != nil {
		return nil, fmt.Errorf("init repository: %w", err)
	}

	return &Secret{
		store: store,
	}, nil
}

func NewRepository(conn *gorm.DB) (Repository, error) {
	repo, err := pg.NewStore(conn)
	if err != nil {
		return nil, fmt.Errorf("create repository: %w", err)
	}
	return repo, nil
}

func (f *Secret) Ping(ctx context.Context) error {
	err := f.store.Ping(ctx)
	if err != nil {
		return fmt.Errorf("ping repository: %w", err)
	}
	return nil
}

func (f *Secret) CountSecret(ctx context.Context, indexSecret models.IndexSecret) (int64, error) {
	count, err := f.store.CountSecret(ctx, indexSecret)
	if err != nil {
		return 0, fmt.Errorf("count secret: %w", err)
	}
	return count, nil
}

func (f *Secret) IndexSecret(ctx context.Context, indexSecret models.IndexSecret) ([]models.SecretData, error) {
	res, err := f.store.IndexSecret(ctx, indexSecret)
	if err != nil {
		return nil, fmt.Errorf("index secrets: %w", err)
	}
	return res, nil
}

func (f *Secret) StoreSecret(ctx context.Context, storeSecret models.StoreSecret) error {
	err := f.store.StoreSecret(ctx, storeSecret)
	if err != nil {
		return fmt.Errorf("store secret: %w", err)
	}
	return nil
}

func (f *Secret) GetSecret(ctx context.Context, getSecret models.ShowSecret) (*models.SecretData, error) {
	res, err := f.store.GetSecret(ctx, getSecret)
	if err != nil {
		return nil, fmt.Errorf("get secret: %w", err)
	}
	return res, nil
}

func (f *Secret) UpdateSecret(ctx context.Context, updateSecret models.UpdateSecret) error {
	err := f.store.UpdateSecret(ctx, updateSecret)
	if err != nil {
		return fmt.Errorf("update secret: %w", err)
	}
	return nil
}

func (f *Secret) DeleteSecret(ctx context.Context, deleteSecret models.DeleteSecret) error {
	err := f.store.DeleteSecret(ctx, deleteSecret)
	if err != nil {
		return fmt.Errorf("delete secret: %w", err)
	}
	return nil
}
