package models_test

import (
	"github.com/Evlushin/GophKeeper/internal/server/models"
	"github.com/Evlushin/GophKeeper/internal/validator"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthRequest_Valid(t *testing.T) {
	tests := []struct {
		name     string
		request  models.AuthRequest
		expected validator.Problems
	}{
		{
			name: "valid request",
			request: models.AuthRequest{
				Login:    "testuser",
				Password: "testpass",
			},
			expected: validator.Problems{},
		},
		{
			name: "empty login",
			request: models.AuthRequest{
				Login:    "",
				Password: "testpass",
			},
			expected: validator.Problems{
				"login": "login is required",
			},
		},
		{
			name: "empty password",
			request: models.AuthRequest{
				Login:    "testuser",
				Password: "",
			},
			expected: validator.Problems{
				"password": "password is required",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.request.Valid()
			assert.Equal(t, tt.expected, result)
		})
	}
}
