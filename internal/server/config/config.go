package config

import (
	"flag"
	"fmt"
	"github.com/Evlushin/GophKeeper/internal/server/handler/config"
	"os"
)

type Config struct {
	Handlers    *config.Config
	LogLevel    string
	DatabaseDsn string
}

func GetConfig(args []string) (*Config, error) {
	cfg := Config{
		Handlers: &config.Config{
			ServerAddr:    config.DefaultServerAddr,
			CompressLevel: config.DefaultCompressLevel,
			AuthConfig: config.AuthConfig{
				AuthCookieName:     config.DefaultAuthCookieName,
				AuthSecretKey:      config.DefaultAuthSecretKey,
				AuthExpireDuration: config.DefaultAuthExpireDuration,
			},
		},
		DatabaseDsn: "host=127.127.126.41 port=5432 dbname=shorturl user=shorturl password=shorturl connect_timeout=10 sslmode=prefer",
		LogLevel:    "info",
	}

	if serverAddr := os.Getenv("RUN_ADDRESS"); serverAddr != "" {
		cfg.Handlers.ServerAddr = serverAddr
	}

	if envLogLevel := os.Getenv("LOG_LEVEL"); envLogLevel != "" {
		cfg.LogLevel = envLogLevel
	}

	if databaseDsn := os.Getenv("DATABASE_URI"); databaseDsn != "" {
		cfg.DatabaseDsn = databaseDsn
	}

	if secretKey := os.Getenv("AUTH_SECRET_KEY"); secretKey != "" {
		cfg.Handlers.AuthSecretKey = secretKey
	}

	fs := flag.NewFlagSet("myFlagSet", flag.ContinueOnError)
	fs.StringVar(&cfg.Handlers.ServerAddr, "a", cfg.Handlers.ServerAddr, "address of HTTP server")
	fs.StringVar(&cfg.LogLevel, "l", cfg.LogLevel, "log level")
	fs.StringVar(&cfg.DatabaseDsn, "d", cfg.DatabaseDsn, "connection string")
	fs.StringVar(&cfg.Handlers.AuthSecretKey, "s", cfg.Handlers.AuthSecretKey, "secret key")
	err := fs.Parse(args)
	if err != nil {
		return &Config{}, fmt.Errorf("parse arguments for flagset: %w", err)
	}

	return &cfg, nil
}
