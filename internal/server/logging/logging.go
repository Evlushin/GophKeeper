package logging

import (
	"fmt"
	"github.com/Evlushin/GophKeeper/internal/server/config"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func Initialize(c *config.Config) (*zap.Logger, error) {
	lvl, err := zap.ParseAtomicLevel(c.LogLevel)
	if err != nil {
		return nil, fmt.Errorf("parse log level: %w", err)
	}

	encoderConfig := zapcore.EncoderConfig{
		MessageKey:     "msg",
		LevelKey:       "level",
		TimeKey:        "ts",
		FunctionKey:    zapcore.OmitKey,
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeTime:     zapcore.TimeEncoderOfLayout("2006-01-02T15:04:05.000Z"), // Формат ISO 8601
		EncodeLevel:    zapcore.CapitalLevelEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
	}

	cfg := zap.NewProductionConfig()
	cfg.Level = lvl
	cfg.EncoderConfig = encoderConfig
	zl, err := cfg.Build()
	if err != nil {
		return nil, fmt.Errorf("build zap logger: %w", err)
	}

	return zl, nil
}
