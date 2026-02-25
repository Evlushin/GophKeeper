package config

import "time"

const (
	DefaultServerAddr         = "localhost:8080"
	DefaultCompressLevel      = 5
	DefaultAuthCookieName     = "auth"
	DefaultAuthExpireDuration = 24 * time.Hour
	DefaultDirFile            = "./file"
	DefaultTLSCertFile        = "./cert/cert.pem"
	DefaultTLSKeyFile         = "./cert/key.pem"
)

type Config struct {
	ServerAddr    string
	CompressLevel int
	DirFile       string
	TLSCertFile   string
	TLSKeyFile    string
	SecretKey     string `env:"SECRET_KEY"`
	AuthConfig
}

type AuthConfig struct {
	AuthCookieName     string        `env:"AUTH_COOKIE_NAME"`
	AuthSecretKey      string        `env:"AUTH_SECRET_KEY"`
	AuthExpireDuration time.Duration `env:"AUTH_EXPIRE_DURATION"`
}
