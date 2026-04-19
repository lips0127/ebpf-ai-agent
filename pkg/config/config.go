package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	MinimaxAPIKey string `yaml:"minimax_api_key"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &cfg, nil
}

func (c *Config) Validate() []string {
	var warnings []string

	if c.MinimaxAPIKey == "" {
		warnings = append(warnings, "minimax_api_key is not configured, AI detection capability may be unavailable")
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
