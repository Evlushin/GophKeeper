package service

import (
	"context"
	"fmt"
	"github.com/Evlushin/GophKeeper/internal/client/config"
	"github.com/Evlushin/GophKeeper/internal/client/models"
)

type Auth struct {
	cfg *config.Config
}

func NewAuth(cfg *config.Config) *Auth {
	return &Auth{
		cfg: cfg,
	}
}

func (a *Auth) Register(ctx context.Context, request models.RegisterRequest) error {
	fmt.Println(request)

	return nil
}

func (a *Auth) Login(ctx context.Context, request models.LoginRequest) error {
	fmt.Println(request)

	return nil
}
