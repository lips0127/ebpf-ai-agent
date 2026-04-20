package config

import (
	"fmt"
	"os"
	"strings"

	"ebpf-ai-agent/pkg/crypto"

	"gopkg.in/yaml.v3"
)

type Config struct {
	MinimaxAPIKey   string `yaml:"minimax_api_key"`    // Plaintext API key (for backward compat)
	EncryptedAPIKey string `yaml:"encrypted_api_key"`   // AES-256-GCM encrypted API key
	EncryptionKey   string `yaml:"encryption_key"`     // Base64 encoded AES key (from env: ENCRYPTION_KEY)
}

// GetAPIKey returns the decrypted API key if encrypted, otherwise returns plaintext.
func (c *Config) GetAPIKey() (string, error) {
	if c.EncryptedAPIKey != "" {
		keyStr := os.Getenv("ENCRYPTION_KEY")
		if keyStr == "" {
			// Check config file as fallback
			keyStr = c.EncryptionKey
		}
		if keyStr == "" {
			return "", fmt.Errorf("encrypted API key configured but no encryption key found (set ENCRYPTION_KEY env var)")
		}

		key, err := crypto.Base64ToKey(keyStr)
		if err != nil {
			return "", fmt.Errorf("failed to decode encryption key: %w", err)
		}

		apiKey, err := crypto.DecryptAPIKey(c.EncryptedAPIKey, key)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt API key: %w", err)
		}
		return apiKey, nil
	}

	// Backward compat: return plaintext
	return c.MinimaxAPIKey, nil
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Expand environment variables in the config
	expanded := os.ExpandEnv(string(data))

	var cfg Config
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &cfg, nil
}

func (c *Config) Validate() []string {
	var warnings []string

	hasKey := c.MinimaxAPIKey != "" || c.EncryptedAPIKey != ""
	if !hasKey {
		warnings = append(warnings, "no API key configured, AI detection capability will be unavailable")
	}

	if c.EncryptedAPIKey != "" && c.EncryptionKey == "" && os.Getenv("ENCRYPTION_KEY") == "" {
		warnings = append(warnings, "encrypted API key configured but encryption key not found in ENCRYPTION_KEY env var")
	}

	return warnings
}

func DefaultConfigPath() string {
	paths := []string{
		"config.yaml",
		".ebpf-ai-agent.yaml",
		"/etc/ebpf-ai-agent/config.yaml",
	}

	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	return "config.yaml"
}

// EncryptAPIKey encrypts an API key for storage in config.
// Provided key must be 32 bytes (AES-256) or will error.
func EncryptAPIKey(plaintext, base64Key string) (string, error) {
	key, err := crypto.Base64ToKey(base64Key)
	if err != nil {
		return "", fmt.Errorf("invalid encryption key: %w", err)
	}

	if len(key) != 32 {
		return "", fmt.Errorf("encryption key must be 32 bytes for AES-256, got %d", len(key))
	}

	encrypted, err := crypto.EncryptAPIKey([]byte(plaintext), key)
	if err != nil {
		return "", fmt.Errorf("encryption failed: %w", err)
	}

	return encrypted, nil
}

// GenerateEncryptionKey generates a new random 32-byte key for AES-256.
// Returns base64-encoded key.
func GenerateEncryptionKey() (string, error) {
	key, err := crypto.GenerateKey(32)
	if err != nil {
		return "", err
	}
	return crypto.KeyToBase64(key), nil
}

// HasEncryptedAPIKey returns true if config has encrypted API key.
func (c *Config) HasEncryptedAPIKey() bool {
	return strings.TrimSpace(c.EncryptedAPIKey) != ""
}
