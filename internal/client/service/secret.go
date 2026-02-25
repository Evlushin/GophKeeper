package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/Evlushin/GophKeeper/internal/client/config"
	"github.com/Evlushin/GophKeeper/internal/client/models"
	"github.com/Evlushin/GophKeeper/internal/client/repository/file"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type Repository interface {
	ListSecret(ctx context.Context, req models.ListRequest) ([]models.SaveData, error)
	StoreSecret(ctx context.Context, req models.StoreRequest) (*models.SaveData, error)
	ShowSecret(ctx context.Context, req models.ShowRequest) (*models.ShowResponse, error)
	UpdateSecret(ctx context.Context, req models.UpdateRequest) (*models.SaveData, error)
	DeleteSecret(ctx context.Context, req models.DeleteRequest) error
}

type Secret struct {
	cfg        *config.Config
	store      Repository
	httpClient *http.Client
}

func NewSecret(cfg *config.Config, cl *http.Client) (*Secret, error) {
	s, err := file.NewStore(cfg)
	if err != nil {
		return nil, fmt.Errorf("new store: %v", err)
	}

	return &Secret{
		cfg:        cfg,
		store:      s,
		httpClient: cl,
	}, nil
}

func (s *Secret) List(ctx context.Context, request models.ListRequest) error {
	jsonData, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		s.cfg.Server.Address+"/api/secret",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("X-API-Token", request.Token)

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	var res []models.SaveData
	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		if err = json.Unmarshal(body, &res); err != nil {
			return fmt.Errorf("parse response: %w, body: %s", err, string(body))
		}
	default:
		fmt.Printf("response status: %d, body: %s\n", resp.StatusCode, string(body))

		res, err = s.store.ListSecret(ctx, request)
		if err != nil {
			return fmt.Errorf("get list: %v", err)
		}

		fmt.Println("Локальное хранилище")
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

	sec, err := s.store.StoreSecret(ctx, request)
	if err != nil {
		return fmt.Errorf("store secret: %v", err)
	}

	fmt.Println("Секрет сохранен в локальное хранилище")

	jsonData, err := json.Marshal(sec)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		s.cfg.Server.Address+"/api/secret",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("X-API-Token", request.Token)

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		if request.Reader != nil {
			fmt.Println("Передача файла на сервер...")
			localFilePath := filepath.Join(s.cfg.Secret.Dir, sec.FileStore)
			fileReader, err := os.Open(localFilePath)
			if err != nil {
				return fmt.Errorf("ошибка открытия файла: %w", err)
			}
			defer fileReader.Close()
			err = s.uploadLargeFile(ctx, request, fileReader)
			if err != nil {
				return fmt.Errorf("sent file: %v", err)
			}
		}
		fmt.Println("Секрет сохранен на сервер")
	default:
		fmt.Printf("response status: %d, body: %s\n", resp.StatusCode, string(body))
	}

	return nil
}

func (s *Secret) uploadLargeFile(ctx context.Context, request models.StoreRequest, reader io.Reader) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		fmt.Sprintf("%s/api/secret/file/upload/%s", s.cfg.Server.Address, request.ID),
		reader,
	)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}

	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-API-Token", request.Token)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("загрузка файла не удалась, статус %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (s *Secret) Show(ctx context.Context, request models.ShowRequest) error {
	jsonData, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		fmt.Sprintf("%s/api/secret/%s", s.cfg.Server.Address, request.ID),
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("X-API-Token", request.Token)

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	var res *models.ShowResponse
	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		if err = json.Unmarshal(body, &res); err != nil {
			return fmt.Errorf("parse response: %w, body: %s", err, string(body))
		}
	default:
		fmt.Printf("response status: %d, body: %s\n", resp.StatusCode, string(body))
		res, err = s.store.ShowSecret(ctx, request)
		if err != nil {
			return fmt.Errorf("get secret: %v", err)
		}

		fmt.Println("Локальное хранилище")
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

		if res.FileStore != "" {

			ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
			defer cancel()

			req, err := http.NewRequestWithContext(
				ctx,
				http.MethodGet,
				fmt.Sprintf("%s/api/secret/file/download/%s", s.cfg.Server.Address, request.ID),
				nil,
			)
			if err != nil {
				return fmt.Errorf("new request: %w", err)
			}

			req.Header.Set("X-API-Token", request.Token)

			r, err := s.httpClient.Do(req)
			if err != nil {
				return fmt.Errorf("send request: %w", err)
			}
			defer r.Body.Close()

			if r.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(r.Body)
				fmt.Printf("загрузка файла не удалась, статус %d: %s", resp.StatusCode, string(body))

				_, err = io.Copy(os.Stdout, res.Reader)
				if err != nil {
					return fmt.Errorf("copy to stdout: %v", err)
				}
			} else {
				_, err = io.Copy(os.Stdout, r.Body)
				if err != nil {
					return fmt.Errorf("copy response to stdout: %v", err)
				}
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
	sec, err := s.store.UpdateSecret(ctx, request)
	if err != nil {
		return fmt.Errorf("update secret: %v", err)
	}

	jsonData, err := json.Marshal(sec)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(
		ctx,
		http.MethodPut,
		s.cfg.Server.Address+"/api/secret",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("X-API-Token", request.Token)

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		if request.Reader != nil {
			fmt.Println("Передача файла на сервер...")

			localFilePath := filepath.Join(s.cfg.Secret.Dir, sec.FileStore)
			fileReader, err := os.Open(localFilePath)
			if err != nil {
				return fmt.Errorf("ошибка открытия файла: %w", err)
			}
			defer fileReader.Close()

			err = s.uploadLargeFile(ctx, request.StoreRequest, fileReader)
			if err != nil {
				return fmt.Errorf("sent file: %v", err)
			}
		}
		fmt.Println("Секрет обновлен на сервере")
	default:
		fmt.Printf("response status: %d, body: %s\n", resp.StatusCode, string(body))
	}

	fmt.Println("Секрет обновлен в локальном хранилище")

	return nil
}

func (s *Secret) Delete(ctx context.Context, request models.DeleteRequest) error {
	jsonData, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(
		ctx,
		http.MethodDelete,
		fmt.Sprintf("%s/api/secret/%s", s.cfg.Server.Address, request.ID),
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("X-API-Token", request.Token)

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		fmt.Println("Секрет удален на сервере")
	default:
		fmt.Printf("response status: %d, body: %s\n", resp.StatusCode, string(body))
	}

	err = s.store.DeleteSecret(ctx, request)
	if err != nil {
		return fmt.Errorf("delete secret: %v", err)
	}

	fmt.Println("Секрет удален в локальном хранилище")

	return nil
}
