package mycrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

const (
	chunkSize   = 32 * 1024 // 32KB
	nonceSize   = 12        // Стандартный размер для GCM
	counterSize = 8         // Последние 8 байт nonce используем как счётчик
)

type EncryptedWriter struct {
	aesGCM       cipher.AEAD
	writer       io.Writer
	baseNonce    []byte // Первые 4 байта случайные, последние 8 — счётчик
	chunkCounter uint64
	buf          []byte
}

// DeriveKey генерирует 32-байтный ключ для AES-256.
func DeriveKey(password, salt []byte, iterations int) ([]byte, error) {
	if iterations == 0 {
		iterations = 100_000 // Рекомендуется для PBKDF2-SHA256
	}
	return pbkdf2.Key(password, salt, iterations, 32, sha256.New), nil
}

// ParseHexSalt преобразует hex-строку в байты.
func ParseHexSalt(saltHex string) ([]byte, error) {
	fmt.Println(saltHex)
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return nil, fmt.Errorf("invalid salt format: %w", err)
	}
	if len(salt) < 16 {
		return nil, fmt.Errorf("salt too short: must be at least 16 bytes")
	}
	return salt, nil
}

func NewEncryptedWriter(w io.Writer, password, salt []byte) (*EncryptedWriter, error) {
	// Деривация ключа
	aesKey, err := DeriveKey(password, salt, 100_000)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	// Генерация базового nonce (12 байт)
	baseNonce := make([]byte, nonceSize)
	if _, err := rand.Read(baseNonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Записываем базовый nonce в файл (нужен для расшифровки)
	if _, err := w.Write(baseNonce); err != nil {
		return nil, fmt.Errorf("write nonce: %w", err)
	}

	return &EncryptedWriter{
		aesGCM:       gcm,
		writer:       w,
		baseNonce:    baseNonce,
		chunkCounter: 0,
		buf:          make([]byte, chunkSize),
	}, nil
}

func (ew *EncryptedWriter) Write(p []byte) (int, error) {
	var total int
	for len(p) > 0 {
		chunk := p
		if len(p) > len(ew.buf) {
			chunk = p[:len(ew.buf)]
		}

		// Формируем уникальный nonce для этого чанка:
		// копируем базовый nonce и инкрементируем счётчик в последних 8 байтах
		chunkNonce := make([]byte, nonceSize)
		copy(chunkNonce, ew.baseNonce)
		binary.BigEndian.PutUint64(chunkNonce[nonceSize-counterSize:], ew.chunkCounter)
		ew.chunkCounter++

		// Шифрование: Seal добавляет auth tag в конец ciphertext
		ciphertext := ew.aesGCM.Seal(nil, chunkNonce, chunk, nil)

		if _, err := ew.writer.Write(ciphertext); err != nil {
			return total, fmt.Errorf("write encrypted chunk: %w", err)
		}

		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func (ew *EncryptedWriter) Close() error {
	if closer, ok := ew.writer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// EncryptTextToHex шифрует текст и возвращает HEX-строку (безопасно для БД).
func EncryptTextToHex(plaintext, password, salt []byte) ([]byte, error) {
	aesKey := pbkdf2.Key(password, salt, 100_000, 32, sha256.New)

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	result := append(nonce, ciphertext...)
	return []byte(hex.EncodeToString(result)), nil
}
