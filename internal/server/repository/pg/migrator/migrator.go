package migrator

import (
	"errors"
	"fmt"
	"gorm.io/gorm"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

func ApplyMigrations(db *gorm.DB, dirName string) error {
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}

	driver, err := postgres.WithInstance(sqlDB, &postgres.Config{
		MigrationsTable: "secret_schema_migrations",
	})
	if err != nil {
		return fmt.Errorf("unable to create db instance: %w", err)
	}

	migrator, err := migrate.NewWithDatabaseInstance(dirName, "pgx", driver)
	if err != nil {
		return fmt.Errorf("unable to create migration: %w", err)
	}

	if err = migrator.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("unable to apply migrations %w", err)
	}

	return nil
}
