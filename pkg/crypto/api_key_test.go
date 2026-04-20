package crypto

import (
	"testing"
)

func TestEncryptDecryptAPIKey(t *testing.T) {
	plaintext := "sk-1234567890abcdef"
	key := []byte("1234567890abcdef1234567890abcdef") // 32 bytes for AES-256

	encrypted, err := EncryptAPIKey([]byte(plaintext), key)
	if err != nil {
		t.Fatalf("EncryptAPIKey failed: %v", err)
	}

	if encrypted == plaintext {
		t.Fatal("encrypted should differ from plaintext")
	}

	decrypted, err := DecryptAPIKey(encrypted, key)
	if err != nil {
		t.Fatalf("DecryptAPIKey failed: %v", err)
	}

	if decrypted != plaintext {
		t.Fatalf("decrypted != plaintext: got %q, want %q", decrypted, plaintext)
	}
}

func TestDecryptWithWrongKey(t *testing.T) {
	plaintext := "secret-api-key"
	key1 := []byte("1234567890abcdef1234567890abcdef") // 32 bytes
	key2 := []byte("abcdef1234567890abcdef1234567890") // different key

	encrypted, err := EncryptAPIKey([]byte(plaintext), key1)
	if err != nil {
		t.Fatalf("EncryptAPIKey failed: %v", err)
	}

	_, err = DecryptAPIKey(encrypted, key2)
	if err == nil {
		t.Fatal("expected error when decrypting with wrong key")
	}
}

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey(32)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	if len(key) != 32 {
		t.Fatalf("key length: got %d, want 32", len(key))
	}

	// Generate another key and verify they're different
	key2, err := GenerateKey(32)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	if string(key) == string(key2) {
		t.Fatal("two generated keys should be different")
	}
}

func TestKeyToBase64RoundTrip(t *testing.T) {
	key := []byte("1234567890abcdef1234567890abcdef")

	b64 := KeyToBase64(key)
	decoded, err := Base64ToKey(b64)
	if err != nil {
		t.Fatalf("Base64ToKey failed: %v", err)
	}

	if string(decoded) != string(key) {
		t.Fatal("round trip failed")
	}
}

func TestInvalidKeySize(t *testing.T) {
	_, err := EncryptAPIKey([]byte("test"), []byte("short"))
	if err != ErrInvalidKeySize {
		t.Fatalf("expected ErrInvalidKeySize, got %v", err)
	}

	_, err = DecryptAPIKey("dummy", []byte("short"))
	if err != ErrInvalidKeySize {
		t.Fatalf("expected ErrInvalidKeySize, got %v", err)
	}
}
