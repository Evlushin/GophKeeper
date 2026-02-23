package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/Evlushin/GophKeeper/internal/client/config"
	"github.com/Evlushin/GophKeeper/internal/client/models"
	"github.com/zalando/go-keyring"
	"io"
	"net/http"
)

type Auth struct {
	cfg        *config.Config
	httpClient *http.Client
}

func NewAuth(cfg *config.Config, cl *http.Client) *Auth {
	return &Auth{
		cfg:        cfg,
		httpClient: cl,
	}
}

func (a *Auth) Register(ctx context.Context, request models.RegisterRequest) error {
	jsonData, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("marshal register request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		a.cfg.Server.Address+"/api/user/register",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return fmt.Errorf("create register request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("send register request: %w", err)
	}
	defer resp.Body.Close()

	return a.handleAuthResponse(resp)
}

// handleAuthResponse обрабатывает ответ от сервера
func (a *Auth) handleAuthResponse(resp *http.Response) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		var authResp models.AuthResponse
		if err = json.Unmarshal(body, &authResp); err != nil {
			return fmt.Errorf("parse response: %w, body: %s", err, string(body))
		}

		err = keyring.Set(a.cfg.App, "auth-token", authResp.Token)
		if err != nil {
			return fmt.Errorf("set token: %w", err)
		}

		fmt.Println("Вход выполнен")

		return nil

	case http.StatusBadRequest:
		return fmt.Errorf("bad request (400): %s", string(body))

	case http.StatusConflict:
		return fmt.Errorf("user already exists (409): %s", string(body))

	case http.StatusTooManyRequests:
		return fmt.Errorf("too many requests (429): %s", string(body))

	default:
		return fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, string(body))
	}
}

func (a *Auth) Login(ctx context.Context, request models.LoginRequest) error {
	jsonData, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("marshal login request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		a.cfg.Server.Address+"/api/user/login",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return fmt.Errorf("create login request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("send login request: %w", err)
	}
	defer resp.Body.Close()

	return a.handleAuthResponse(resp)

	return nil
}
