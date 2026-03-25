package models

import (
	"io"
	"time"
)

type DataType string

const (
	LoginPassword DataType = "login_password"
	BinaryData    DataType = "binary"
	CardData      DataType = "card"
)

type Card struct {
	Number     string `json:"number"`
	Holder     string `json:"holder"`
	ExpiryDate string `json:"expiry_date"`
	CVV        string `json:"cvv"`
	Bank       string `json:"bank"`
}

type Credentials struct {
	Login string `json:"login"`
	Pass  string `json:"pass"`
}

type ListRequest struct {
	Type  string `json:"type"`
	Token string `json:"-"`
}

type SecretData struct {
	ID        string    `json:"id"`
	DataType  DataType  `json:"type"`
	Title     string    `json:"title"`
	Metadata  string    `json:"metadata"`
	Data      []byte    `json:"data"`
	FilePath  string    `json:"filepath"`
	FileStore string    `json:"file_store"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	DeletedAt time.Time `json:"deleted_at"`
}

type SaveData struct {
	SecretData
	IsDelete bool
}

type StoreRequest struct {
	SecretData
	Reader    io.Reader `json:"-"`
	ChunkSize int       `json:"-"`
	Token     string    `json:"-"`
}

type StoreFileRequest struct {
	ID        string    `json:"id"`
	Reader    io.Reader `json:"-"`
	ChunkSize int       `json:"-"`
}

type StoreFileResponse struct {
	FileStore string `json:"file_store"`
}

type UpdateRequest struct {
	StoreRequest
	ID    string `json:"id"`
	Token string `json:"-"`
}

type ShowRequest struct {
	ID    string `json:"id"`
	Token string `json:"-"`
}

type ShowResponse struct {
	SecretData
	Reader io.Reader `json:"-"`
	Token  string    `json:"-"`
}

type DeleteRequest struct {
	ID    string `json:"id"`
	Token string `json:"-"`
}
