package service

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Evlushin/GophKeeper/internal/client/config"
	"github.com/Evlushin/GophKeeper/internal/client/models"
	"github.com/Evlushin/GophKeeper/internal/client/repository/file"
	"io"
	"os"
)

type Repository interface {
	ListSecret(ctx context.Context, req models.ListRequest) ([]models.SaveData, error)
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

	for _, secret := range res {
		fmt.Printf("ID: %s\n", secret.ID)
		fmt.Printf("  Title: %s\n", secret.Title)
		fmt.Printf("  Type: %s\n", secret.DataType)
		fmt.Printf("  Metadata: %s\n", secret.Metadata)
		fmt.Printf("  Filepath: %s\n", secret.FilePath)
		fmt.Printf("  Filestore: %s\n", secret.FileStore)
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
		return fmt.Errorf("store secret: %v", err)
	}

	fmt.Println("Секрет сохранен")

	return nil
}

func (s *Secret) Show(ctx context.Context, request models.ShowRequest) error {
	res, err := s.store.ShowSecret(ctx, request)
	if err != nil {
		return fmt.Errorf("get secret: %v", err)
	}

	fmt.Printf("ID: %s\n", request.ID)
	fmt.Printf("  Title: %s\n", res.Title)
	fmt.Printf("  Type: %s\n", res.DataType)
	fmt.Printf("  Metadata: %s\n", res.Metadata)
	fmt.Printf("  Filepath: %s\n", res.FilePath)
	fmt.Printf("  Filestore: %s\n", res.FileStore)
	fmt.Printf("  Created: %v\n", res.CreatedAt)
	fmt.Printf("  Update: %v\n", res.UpdatedAt)
	fmt.Println("---")

	switch res.DataType {
	case models.BinaryData:
		fmt.Println("Data")
		fmt.Println("---")

		if len(res.Data) > 0 {
			fmt.Println(string(res.Data))
		}

		if res.Reader != nil {
			_, err = io.Copy(os.Stdout, res.Reader)
			if err != nil {
				return fmt.Errorf("copy to stdout: %v", err)
			}
		}

	case models.LoginPassword:
		fmt.Println("Login and password")
		fmt.Println("---")
		var loginData models.Credentials
		if err = json.Unmarshal(res.Data, &loginData); err == nil {
			fmt.Printf("  Login: %s\n", loginData.Login)
			fmt.Printf("  Password: %s\n", loginData.Pass)
		} else {
			return fmt.Errorf("parse json: %v", err)
		}

	case models.CardData:
		fmt.Println("Card")
		fmt.Println("---")
		var card models.Card
		if err = json.Unmarshal(res.Data, &card); err == nil {
			fmt.Printf("  Number: %s\n", card.Number)
			fmt.Printf("  Holder: %s\n", card.Holder)
			fmt.Printf("  Expiry: %s\n", card.ExpiryDate)
			fmt.Printf("  CVV: %s\n", card.CVV)
			fmt.Printf("  Bank: %s\n", card.Bank)

		} else {
			return fmt.Errorf("parse json: %v", err)
		}
	}
	fmt.Println("---")

	return nil
}

func (s *Secret) Update(ctx context.Context, request models.UpdateRequest) error {
	err := s.store.UpdateSecret(ctx, request)
	if err != nil {
		return fmt.Errorf("update secret: %v", err)
	}

	fmt.Println("Секрет обновлен")

	return nil
}

func (s *Secret) Delete(ctx context.Context, request models.DeleteRequest) error {
	err := s.store.DeleteSecret(ctx, request)
	if err != nil {
		return fmt.Errorf("delete secret: %v", err)
	}

	fmt.Println("Секрет удален")

	return nil
}
