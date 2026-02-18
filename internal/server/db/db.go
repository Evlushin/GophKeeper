package db

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/Evlushin/GophKeeper/internal/server/config"
	_ "github.com/jackc/pgx/v5/stdlib"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"time"
)

const (
	DefaultMaxIdleConnections    = 10
	DefaultMaxOpenConnections    = 100
	DefaultConnectionMaxLifetime = 10 * time.Minute
)

// InitGORMDB инициализирует GORM DB с драйвером pgx
func InitGORMDB(c *config.Config) (*gorm.DB, error) {
	sqlDB, err := sql.Open("pgx", c.DatabaseDsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open pgx connection: %w", err)
	}

	sqlDB.SetMaxIdleConns(DefaultMaxIdleConnections)
	sqlDB.SetMaxOpenConns(DefaultMaxOpenConnections)
	sqlDB.SetConnMaxLifetime(DefaultConnectionMaxLifetime)

	db, err := gorm.Open(postgres.New(postgres.Config{
		Conn: sqlDB,
	}), &gorm.Config{
		Logger:                 logger.Default.LogMode(logger.Silent),
		SkipDefaultTransaction: true,
		TranslateError:         true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize GORM with pgx: %w", err)
	}

	if err := db.WithContext(context.Background()).Exec("SELECT 1").Error; err != nil {
		return nil, fmt.Errorf("database connection failed: %w", err)
	}

	return db, nil
}
