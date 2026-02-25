package models

import (
	"time"

	"github.com/Evlushin/GophKeeper/internal/validator"
)

type DataType string

const (
	LoginPassword DataType = "login_password"
	BinaryData    DataType = "binary"
	CardData      DataType = "card"
)

type IndexSecret struct {
	UserID UserID   `json:"user_id"`
	Type   DataType `json:"type"`
}

type SecretData struct {
	ID        string    `json:"id" gorm:"column:id;primaryKey"`
	DataType  DataType  `json:"type" gorm:"column:type"`
	Title     string    `json:"title"`
	Metadata  string    `json:"metadata"`
	Data      []byte    `json:"data"`
	FilePath  string    `json:"filepath" gorm:"column:filepath"`
	FileStore string    `json:"file_store"`
	CreatedAt time.Time `json:"created_at" gorm:"default:current_timestamp"`
	UpdatedAt time.Time `json:"updated_at" gorm:"default:current_timestamp"`
	DeletedAt time.Time `json:"deleted_at" gorm:"default:null"`
}

type StoreSecret struct {
	SecretData
	UserID UserID `json:"user_id"`
}

func (r StoreSecret) Valid() validator.Problems {
	problems := make(validator.Problems)

	if r.ID == "" {
		problems["id"] = "id is required"
	}

	if r.DataType == "" {
		problems["datatype"] = "datatype is required"
	}

	return problems
}

type ShowSecret struct {
	ID     string `json:"id"`
	UserID UserID `json:"user_id"`
}

type UpdateSecret struct {
	SecretData
	UserID UserID `json:"user_id"`
}

func (r UpdateSecret) Valid() validator.Problems {
	problems := make(validator.Problems)

	if r.ID == "" {
		problems["id"] = "id is required"
	}

	if r.DataType == "" {
		problems["datatype"] = "datatype is required"
	}

	return problems
}

type DeleteSecret struct {
	ID     string `json:"id"`
	UserID UserID `json:"user_id"`
}
