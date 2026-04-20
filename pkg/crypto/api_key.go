// Package crypto provides encryption utilities for sensitive data like API keys.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

var (
	ErrInvalidKeySize   = errors.New("invalid key size: must be 16, 24, or 32 bytes for AES-128/192/256")
	ErrCiphertextShort  = errors.New("ciphertext too short: missing GCM nonce")
	ErrCiphertextTamper = errors.New("ciphertext authentication failed: data tampered")
)

// EncryptAPIKey encrypts plaintext using AES-256-GCM.
// Returns base64-encoded ciphertext.
func EncryptAPIKey(plaintext, key []byte) (string, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return "", ErrInvalidKeySize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptAPIKey decrypts base64-encoded ciphertext using AES-256-GCM.
// Returns plaintext.
func DecryptAPIKey(ciphertextBase64 string, key []byte) (string, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return "", ErrInvalidKeySize
	}

	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	nonceSize := 12 // GCM standard nonce size
	if len(ciphertext) < nonceSize {
		return "", ErrCiphertextShort
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := ciphertext[:nonceSize]
	ciphertext = ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", ErrCiphertextTamper
	}

	return string(plaintext), nil
}

// GenerateKey generates a random AES key of specified size (16, 24, or 32 bytes).
func GenerateKey(size int) ([]byte, error) {
	if size != 16 && size != 24 && size != 32 {
		return nil, ErrInvalidKeySize
	}
	key := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	return key, nil
}

// KeyToBase64 converts a key to base64 string for storage.
func KeyToBase64(key []byte) string {
	return base64.StdEncoding.EncodeToString(key)
}

// Base64ToKey converts a base64 string back to key bytes.
func Base64ToKey(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
