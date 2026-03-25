package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/Evlushin/GophKeeper/internal/client/config"
	"net"
	"net/http"
	"os"
	"time"
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
	caCert, err := os.ReadFile(cfg.Server.Cert)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12, // Безопасный минимум
			RootCAs:    caCertPool,       // Доверяем только нашему cert.pem
		},
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	client := &http.Client{
		Timeout:   cfg.RequestTimeout,
		Transport: transport,
	}

	authSvc := NewAuth(cfg, client)
	secretSvc, err := NewSecret(cfg, client)
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
