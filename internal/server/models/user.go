package models

import (
	"time"
)

type UserID uint

type User struct {
	ID           UserID    `json:"id" gorm:"primaryKey"`
	Login        string    `json:"login" gorm:"uniqueIndex;not null"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
}
