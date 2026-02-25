package handler

import (
	"context"
	"errors"
	"github.com/Evlushin/GophKeeper/internal/server/handler/config"
	"github.com/Evlushin/GophKeeper/internal/server/service/auth"
	"github.com/Evlushin/GophKeeper/internal/server/service/secret"
	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
	"net/http"
	"os"
	"sync"
	"time"
)

const defaultShutdownCtxTimeout = 10 * time.Second

func NewRouter(
	logger *zap.Logger,
	cfg *config.Config,
	s *secret.Secret,
	auth *auth.Auth,
) http.Handler {
	r := chi.NewRouter()
	addRoutes(r, logger, cfg, s, auth)
	return r
}

func Serve(
	ctx context.Context,
	logger *zap.Logger,
	cfg *config.Config,
	router http.Handler,
) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	httpServer := &http.Server{
		Addr:         cfg.ServerAddr,
		Handler:      router,
		ReadTimeout:  24 * time.Hour,
		WriteTimeout: 24 * time.Hour,
		IdleTimeout:  5 * time.Minute,
	}

	go func() {
		logger.Info("starting server", zap.String("addr", cfg.ServerAddr))

		if !certFilesExist(cfg.TLSCertFile, cfg.TLSKeyFile) {
			if err := GenerateSelfSignedCert(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil {
				logger.Error("generate certificates", zap.Error(err))
				cancel()
				return
			}
			logger.Debug("generate certificates")
		}

		// Запуск HTTPS-сервера
		err := httpServer.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("error serving HTTPS", zap.Error(err))
			cancel()
		}
	}()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		shutdownCtx := context.Background()
		shutdownCtx, cancel := context.WithTimeout(shutdownCtx, defaultShutdownCtxTimeout)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			logger.Error("error shutting down http server", zap.Error(err))
		}
		logger.Info("close server", zap.String("addr", cfg.ServerAddr))
	}()
	wg.Wait()
}

func certFilesExist(certFile, keyFile string) bool {
	_, errCert := os.Stat(certFile)
	_, errKey := os.Stat(keyFile)
	return errCert == nil || errKey == nil
}
