package config

import (
	"flag"
	"fmt"
	"github.com/Evlushin/GophKeeper/internal/myerrors"
	"os"

	"github.com/Evlushin/GophKeeper/internal/server/handler/config"
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
			DirFile:       config.DefaultDirFile,
			TLSCertFile:   config.DefaultTLSCertFile,
			TLSKeyFile:    config.DefaultTLSKeyFile,
			//SecretKey:     "secret2",
			AuthConfig: config.AuthConfig{
				AuthCookieName:     config.DefaultAuthCookieName,
				AuthExpireDuration: config.DefaultAuthExpireDuration,
				//AuthSecretKey:      "secret",
			},
		},
		//DatabaseDsn: "host=127.127.126.41 port=5432 dbname=shorturl user=shorturl password=shorturl connect_timeout=10 sslmode=prefer",
		LogLevel: "info",
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

	if secretKeyData := os.Getenv("SECRET_KEY"); secretKeyData != "" {
		cfg.Handlers.SecretKey = secretKeyData
	}

	if dirFile := os.Getenv("DIR_FILE"); dirFile != "" {
		cfg.Handlers.DirFile = dirFile
	}

	fs := flag.NewFlagSet("myFlagSet", flag.ContinueOnError)
	fs.StringVar(&cfg.Handlers.ServerAddr, "a", cfg.Handlers.ServerAddr, "address of HTTP server")
	fs.StringVar(&cfg.LogLevel, "l", cfg.LogLevel, "log level")
	fs.StringVar(&cfg.DatabaseDsn, "d", cfg.DatabaseDsn, "connection string")
	fs.StringVar(&cfg.Handlers.AuthSecretKey, "s", cfg.Handlers.AuthSecretKey, "secret key auth")
	fs.StringVar(&cfg.Handlers.SecretKey, "sd", cfg.Handlers.SecretKey, "secret key data")
	fs.StringVar(&cfg.Handlers.DirFile, "dir", cfg.Handlers.DirFile, "dir file")
	err := fs.Parse(args)
	if err != nil {
		return &Config{}, fmt.Errorf("parse arguments for flagset: %w", err)
	}

	if cfg.DatabaseDsn == "" {
		return &Config{}, myerrors.ErrEnterConnectionString
	}

	if cfg.Handlers.SecretKey == "" {
		return &Config{}, myerrors.ErrEnterSecretKey
	}

	if cfg.Handlers.AuthSecretKey == "" {
		return &Config{}, myerrors.ErrEnterAuthSecretKey
	}

	return &cfg, nil
}
