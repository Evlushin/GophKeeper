package config

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	DefaultRequestTimeout = 30 * time.Second
)

type (
	Server struct {
		Address string `mapstructure:"address"`
		Cert    string `mapstructure:"cert"`
	}
	Log struct {
		Level string `mapstructure:"level"`
	}
	Secret struct {
		File string `mapstructure:"file"`
		Dir  string `mapstructure:"dir"`
	}
	Config struct {
		Server         Server `mapstructure:"server"`
		Log            Log    `mapstructure:"log"`
		Secret         Secret `mapstructure:"secret"`
		RequestTimeout time.Duration
		App            string
	}
)

// BindFlags регистрирует флаги. Вызывайте это в NewRootCmd
func BindFlags(cmd *cobra.Command) {
	cmd.Flags().StringP("address", "a", "https://localhost:8080", "Адрес сервера")
	cmd.Flags().StringP("level", "", "info", "Уровень логирования")
	cmd.Flags().StringP("storage-file", "f", "storage.txt", "Файл для хранения данных")
	cmd.Flags().StringP("dir-file", "s", "./file", "Папка для хранения файлов")
	cmd.Flags().StringP("cert", "c", "../../cert/cert.pem", "Публичный сертификат")
}

// Load инициализирует Viper и собирает Config
func Load(cmd *cobra.Command) (*Config, error) {
	v := viper.New()

	v.SetEnvPrefix("GK")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	err := v.BindPFlag("server.address", cmd.Flags().Lookup("address"))
	if err != nil {
		return nil, fmt.Errorf("привязка server.address: %v", err)
	}
	err = v.BindPFlag("log.level", cmd.Flags().Lookup("level"))
	if err != nil {
		return nil, fmt.Errorf("привязка log.level: %v", err)
	}
	err = v.BindPFlag("secret.file", cmd.Flags().Lookup("storage-file"))
	if err != nil {
		return nil, fmt.Errorf("привязка secret.file: %v", err)
	}
	err = v.BindPFlag("secret.dir", cmd.Flags().Lookup("dir-file"))
	if err != nil {
		return nil, fmt.Errorf("привязка secret.dir: %v", err)
	}
	err = v.BindPFlag("server.cert", cmd.Flags().Lookup("cert"))
	if err != nil {
		return nil, fmt.Errorf("привязка secret.cert: %v", err)
	}

	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath("./configs/client")

	if err = v.ReadInConfig(); err != nil {
		if !errors.As(err, &viper.ConfigFileNotFoundError{}) {
			return nil, fmt.Errorf("чтение конфига: %w", err)
		}
	}

	var cfg Config
	if err = v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("десериализация: %w", err)
	}

	cfg.RequestTimeout = DefaultRequestTimeout
	cfg.App = "GophKeeper"

	return &cfg, nil
}
