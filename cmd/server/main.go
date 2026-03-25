package main

import (
	"context"
	"fmt"
	"github.com/Evlushin/GophKeeper/internal/server/config"
	"github.com/Evlushin/GophKeeper/internal/server/db"
	"github.com/Evlushin/GophKeeper/internal/server/handler"
	"github.com/Evlushin/GophKeeper/internal/server/logging"
	"github.com/Evlushin/GophKeeper/internal/server/repository/pg"
	"github.com/Evlushin/GophKeeper/internal/server/service/auth"
	"github.com/Evlushin/GophKeeper/internal/server/service/secret"
	"github.com/Evlushin/GophKeeper/internal/utils"
	"go.uber.org/zap"
	"gorm.io/gorm"
	"log"
	"os"
	"os/signal"
	"syscall"
)

var (
	buildVersion string
	buildDate    string
	buildCommit  string
)

func run(ctx context.Context, args []string) error {
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
	defer cancel()

	printBuildInfo()

	cfg, err := config.GetConfig(args[1:])
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}
	if err = os.MkdirAll(cfg.Handlers.DirFile, 0755); err != nil {
		return fmt.Errorf("create dir: %w", err)
	}

	zl, err := logging.Initialize(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}
	defer func() {
		//nolint:errcheck // there isn't any good strategy to log error
		_ = zl.Sync()
	}()

	conn, err := db.InitGORMDB(cfg)
	if err != nil {
		return fmt.Errorf("init db error: %w", err)
	}
	defer func(conn *gorm.DB) {
		sqlDB, cErr := conn.DB()
		if cErr != nil {
			zl.Error("error getting underlying DB", zap.Error(cErr))
			return
		}

		cErr = sqlDB.Close()
		if cErr != nil {
			zl.Error("close db Error", zap.Error(cErr))
		}
	}(conn)

	s, err := secret.NewSecret(conn)
	if err != nil {
		return fmt.Errorf("failed to initialize service gophermart: %w", err)
	}

	userRepo := pg.NewPgUser(conn)
	userProvider := auth.NewAuthUser(userRepo)
	tokenProvider := auth.NewAuthToken(cfg.Handlers)
	a := auth.NewAuth(userProvider, tokenProvider)

	router := handler.NewRouter(zl, cfg.Handlers, s, a)

	handler.Serve(ctx, zl, cfg.Handlers, router)
	return nil
}

func main() {
	ctx := context.Background()
	if err := run(ctx, os.Args); err != nil {
		log.Fatalf("failed to run application: %v", err)
	}
}

// printBuildInfo выводит информацию о сборке
func printBuildInfo() {
	fmt.Printf("Build version: %s\n", utils.FormatValue(buildVersion))
	fmt.Printf("Build date: %s\n", utils.FormatValue(buildDate))
	fmt.Printf("Build commit: %s\n", utils.FormatValue(buildCommit))
}
