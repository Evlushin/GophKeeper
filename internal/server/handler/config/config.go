package config

import "time"

const (
	DefaultServerAddr         = "localhost:8080"
	DefaultCompressLevel      = 5
	DefaultAuthCookieName     = "auth"
	DefaultAuthSecretKey      = "secret"
	DefaultAuthExpireDuration = 24 * time.Hour
)

type Config struct {
	ServerAddr    string
	CompressLevel int
	AuthConfig
}

type AuthConfig struct {
	AuthCookieName     string        `env:"AUTH_COOKIE_NAME"`
	AuthSecretKey      string        `env:"AUTH_SECRET_KEY"`
	AuthExpireDuration time.Duration `env:"AUTH_EXPIRE_DURATION"`
}
