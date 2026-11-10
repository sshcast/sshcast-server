package config

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

type Config struct {
	ListenAddr            string   `toml:"listen_addr"`
	TLSCertFile           string   `toml:"tls_cert_file"`
	TLSKeyFile            string   `toml:"tls_key_file"`
	AllowAnyUser          bool     `toml:"allow_any_user"`
	AllowedUserPubkeys    []string `toml:"allowed_user_pubkeys"`
	SignAckTimeoutMs      uint64   `toml:"sign_ack_timeout_ms"`
	SignResponseTimeoutMs uint64   `toml:"sign_response_timeout_ms"`
	HeartbeatIntervalMs   uint64   `toml:"heartbeat_interval_ms"`
	MaxClockSkewMs        uint64   `toml:"max_clock_skew_ms"`
	WebDir                string   `toml:"web_dir"`

	parsedAllowedKeys [][]byte
}

func Default() *Config {
	return &Config{
		ListenAddr:            "127.0.0.1:8080",
		AllowAnyUser:          false,
		SignAckTimeoutMs:      1500,
		SignResponseTimeoutMs: 60000,
		HeartbeatIntervalMs:   25000,
		MaxClockSkewMs:        5 * 60 * 1000,
	}
}

func Load(path string) (*Config, error) {
	cfg := Default()
	if path == "" {
		if confDir := strings.TrimSpace(os.Getenv("CONFIGURATION_DIRECTORY")); confDir != "" {
			candidate := filepath.Join(strings.Split(confDir, ":")[0], "server.toml")
			if _, err := os.Stat(candidate); err == nil {
				path = candidate
			}
		}
	}
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config %q: %w", path, err)
		}
		if _, err := toml.Decode(string(data), cfg); err != nil {
			return nil, fmt.Errorf("parse config %q: %w", path, err)
		}
	}
	if err := cfg.CompileAllowedKeys(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func ParsePubkeyString(raw string) ([]byte, error) {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "sc_pub_")
	if b, err := hex.DecodeString(s); err == nil && len(b) == ed25519.PublicKeySize {
		return b, nil
	}
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == ed25519.PublicKeySize {
			return b, nil
		}
	}
	return nil, fmt.Errorf("invalid 32-byte Ed25519 public key encoding: %q", raw)
}

func (c *Config) CompileAllowedKeys() error {
	c.parsedAllowedKeys = nil
	for _, raw := range c.AllowedUserPubkeys {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		pub, err := ParsePubkeyString(raw)
		if err != nil {
			return err
		}
		c.parsedAllowedKeys = append(c.parsedAllowedKeys, pub)
	}
	return nil
}

func (c *Config) IsUserPubkeyAllowed(userPubkey []byte) bool {
	if c.AllowAnyUser {
		return true
	}
	for _, allowed := range c.parsedAllowedKeys {
		if bytes.Equal(allowed, userPubkey) {
			return true
		}
	}
	return false
}

func (c *Config) SignAckTimeout() time.Duration {
	if c.SignAckTimeoutMs == 0 {
		return 1500 * time.Millisecond
	}
	return time.Duration(c.SignAckTimeoutMs) * time.Millisecond
}

func (c *Config) SignResponseTimeout() time.Duration {
	if c.SignResponseTimeoutMs == 0 {
		return 60 * time.Second
	}
	return time.Duration(c.SignResponseTimeoutMs) * time.Millisecond
}

func (c *Config) HeartbeatInterval() time.Duration {
	if c.HeartbeatIntervalMs == 0 {
		return 25 * time.Second
	}
	return time.Duration(c.HeartbeatIntervalMs) * time.Millisecond
}
