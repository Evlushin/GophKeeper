package service

import (
	"context"
	"fmt"
	"github.com/Evlushin/GophKeeper/internal/client/config"
)

// Container — реестр всех сервисов приложения
type Container struct {
	Config *config.Config
	Auth   *Auth
	Secret *Secret
}

type ctxKey struct{}

// NewContainer инициализирует все сервисы
func NewContainer(cfg *config.Config) (*Container, error) {
	authSvc := NewAuth(cfg)
	secretSvc, err := NewSecret(cfg)
	if err != nil {
		return nil, fmt.Errorf("new secret: %v", err)
	}

	return &Container{
		Config: cfg,
		Auth:   authSvc,
		Secret: secretSvc,
	}, nil
}

func FromContext(ctx context.Context) *Container {
	return ctx.Value(ctxKey{}).(*Container)
}

func SaveToContext(ctx context.Context, a *Container) context.Context {
	return context.WithValue(ctx, ctxKey{}, a)
}
