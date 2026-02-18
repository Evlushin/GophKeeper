package handler

import (
	handlerauth "github.com/Evlushin/GophKeeper/internal/server/handler/api/auth"
	handlersecret "github.com/Evlushin/GophKeeper/internal/server/handler/api/secret"
	"github.com/Evlushin/GophKeeper/internal/server/handler/config"
	mw "github.com/Evlushin/GophKeeper/internal/server/handler/middleware"
	"github.com/Evlushin/GophKeeper/internal/server/service/auth"
	"github.com/Evlushin/GophKeeper/internal/server/service/secret"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"go.uber.org/zap"
)

func addRoutes(
	mux *chi.Mux,
	logger *zap.Logger,
	cfg *config.Config,
	s *secret.Secret,
	auth *auth.Auth,
) {
	mux.Use(middleware.Logger)
	mux.Use(middleware.Compress(cfg.CompressLevel))

	mux.Route("/api", func(mux chi.Router) {
		mux.Route("/user", func(mux chi.Router) {
			mux.Post("/register", handlerauth.HandleRegister(cfg, logger, auth))
			mux.Post("/login", handlerauth.HandleLogin(cfg, logger, auth))

			// auth protected group
			mux.Group(func(mux chi.Router) {
				mux.Use(mw.NewAuth(cfg, logger, auth))

				mux.Route("/secret", func(mux chi.Router) {
					mux.Get("/", handlersecret.Index(logger, s))
					mux.Post("/", handlersecret.Store(logger, s))
					mux.Get("/{id}", handlersecret.Show(logger, s))
					mux.Put("/", handlersecret.Update(logger, s))
					mux.Delete("/{id}", handlersecret.Delete(logger, s))
				})
			})
		})
	})
}
