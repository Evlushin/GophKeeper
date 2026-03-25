//go:build !integration

package mocks

import "github.com/zalando/go-keyring"

// KeyringInterface позволяет мокировать работу с keyring
type KeyringInterface interface {
	Set(service, user, password string) error
	Get(service, user string) (string, error)
	Delete(service, user string) error
}

// DefaultKeyring реализует интерфейс через реальный keyring
type DefaultKeyring struct{}

func (d DefaultKeyring) Set(service, user, password string) error {
	return keyring.Set(service, user, password)
}

func (d DefaultKeyring) Get(service, user string) (string, error) {
	return keyring.Get(service, user)
}

func (d DefaultKeyring) Delete(service, user string) error {
	return keyring.Delete(service, user)
}
