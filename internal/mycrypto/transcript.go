package mycrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

const (
	downloadChunkSize = 32 * 1024 // 32KB
)

// DecryptedReader читает зашифрованные данные и расшифровывает их на лету.
type DecryptedReader struct {
	aesGCM       cipher.AEAD
	reader       io.Reader
	baseNonce    []byte
	chunkCounter uint64
	buf          []byte
	pending      []byte
}

// NewDecryptedReader инициализирует потоковую расшифровку.
func NewDecryptedReader(r io.Reader, password, salt []byte) (*DecryptedReader, error) {
	baseNonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(r, baseNonce); err != nil {
		return nil, fmt.Errorf("read nonce: %w", err)
	}

	aesKey := pbkdf2.Key(password, salt, 100_000, 32, sha256.New)

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	return &DecryptedReader{
		aesGCM:       gcm,
		reader:       r,
		baseNonce:    baseNonce,
		chunkCounter: 0,
		buf:          make([]byte, downloadChunkSize+gcm.Overhead()),
		pending:      nil,
	}, nil
}

// Read реализует интерфейс.
func (dr *DecryptedReader) Read(p []byte) (int, error) {
	if len(dr.pending) > 0 {
		n := copy(p, dr.pending)
		dr.pending = dr.pending[n:]
		return n, nil
	}

	n, err := dr.reader.Read(dr.buf)
	if n == 0 {
		return 0, err
	}

	chunkNonce := make([]byte, nonceSize)
	copy(chunkNonce, dr.baseNonce)
	binary.BigEndian.PutUint64(chunkNonce[nonceSize-counterSize:], dr.chunkCounter)
	dr.chunkCounter++

	plaintext, err := dr.aesGCM.Open(nil, chunkNonce, dr.buf[:n], nil)
	if err != nil {
		return 0, fmt.Errorf("decrypt chunk %d: %w", dr.chunkCounter-1, err)
	}

	copied := copy(p, plaintext)

	if copied < len(plaintext) {
		dr.pending = plaintext[copied:]
	}

	return copied, nil
}

// DecryptTextFromHex принимает HEX-строку из БД и возвращает оригинальный текст.
func DecryptTextFromHex(encryptedHex string, password, salt []byte) ([]byte, error) {
	data, err := hex.DecodeString(encryptedHex)
	if err != nil {
		return nil, fmt.Errorf("decode hex: %w", err)
	}

	aesKey := pbkdf2.Key(password, salt, 100_000, 32, sha256.New)

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	size := gcm.NonceSize()
	if len(data) < size {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:size], data[size:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}
