package service

import (
	"context"
	"fmt"
	"github.com/Evlushin/GophKeeper/internal/client/config"
	"github.com/Evlushin/GophKeeper/internal/client/models"
	"github.com/Evlushin/GophKeeper/internal/client/repository/file"
)

type Repository interface {
	ListSecret(ctx context.Context, req models.ListRequest) (map[string]models.SaveData, error)
	StoreSecret(ctx context.Context, req models.StoreRequest) error
	ShowSecret(ctx context.Context, req models.ShowRequest) (*models.ShowResponse, error)
	UpdateSecret(ctx context.Context, req models.UpdateRequest) error
	DeleteSecret(ctx context.Context, req models.DeleteRequest) error
}

type Secret struct {
	cfg   *config.Config
	store Repository
}

func NewSecret(cfg *config.Config) (*Secret, error) {
	s, err := file.NewStore(cfg)
	if err != nil {
		return nil, fmt.Errorf("new store: %v", err)
	}

	return &Secret{
		cfg:   cfg,
		store: s,
	}, nil
}

func (s *Secret) List(ctx context.Context, request models.ListRequest) error {
	res, err := s.store.ListSecret(ctx, request)
	if err != nil {
		return fmt.Errorf("get list: %v", err)
	}

	fmt.Println("=== Список секретов ===")
	fmt.Printf("Количество: %d\n", len(res))

	for id, secret := range res {
		fmt.Printf("ID: %s\n", id)
		fmt.Printf("  Title: %s\n", secret.Title)
		fmt.Printf("  Type: %s\n", secret.DataType)
		fmt.Printf("  Metadata: %s\n", secret.Metadata)
		fmt.Printf("  Filepath: %s\n", secret.Filepath)
		fmt.Printf("  Filestore: %s\n", secret.Filestore)
		fmt.Printf("  Created: %v\n", secret.CreatedAt)
		fmt.Printf("  Update: %v\n", secret.UpdatedAt)
		fmt.Printf("  IsDelete: %v\n", secret.IsDelete)
		fmt.Println("---")
	}

	return nil
}

func (s *Secret) Store(ctx context.Context, request models.StoreRequest) error {
	err := s.store.StoreSecret(ctx, request)
	if err != nil {
		return fmt.Errorf("get list: %v", err)
	}

	fmt.Println("Секрет сохранен")

	return nil
}

func (s *Secret) Show(ctx context.Context, request models.ShowRequest) error {
	res, err := s.store.ShowSecret(ctx, request)

	return nil
}

func (s *Secret) Update(ctx context.Context, request models.UpdateRequest) error {
	fmt.Println(request)

	return nil
}

func (s *Secret) Delete(ctx context.Context, request models.DeleteRequest) error {
	fmt.Println(request)

	return nil
}
