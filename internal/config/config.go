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

	"github.com/pelletier/go-toml/v2"
	sshcastv1 "stingr.net/go/sshcast-proto/gen/go/sshcast/v1"
	"stingr.net/go/sshcast-proto/pkg/auth"
)

type Config struct {
	ListenAddr             string   `toml:"listen_addr" name:"listen_addr" aliases:"listen,listen-addr" default:"127.0.0.1:8080" help:"Listen address override when not socket-activated (e.g. unix:/run/sshcast-server/server.sock or 127.0.0.1:8080)."`
	TLSCertFile            string   `toml:"tls_cert_file" name:"tls_cert_file" aliases:"tls-cert,tls-cert-file" help:"Optional TLS certificate file (leave empty for h2c behind Nginx/Cloudflare)."`
	TLSKeyFile             string   `toml:"tls_key_file" name:"tls_key_file" aliases:"tls-key,tls-key-file" help:"Optional TLS private key file."`
	AllowAnyUser           bool     `toml:"allow_any_user" name:"allow_any_user" aliases:"allow-any-user" default:"false" help:"Allow any valid Ed25519 user root key without allowlist check."`
	AllowedUserPubkeys     []string `toml:"allowed_user_pubkeys" name:"allowed_user_pubkeys" aliases:"allow-user-pubkey,allowed-user-pubkeys" sep:"none" help:"Allowed user Ed25519 public key (hex or base64, repeatable)."`
	TrustedOperatorPubkeys []string `toml:"trusted_operator_pubkeys" name:"trusted_operator_pubkeys" aliases:"trusted-operator-pubkey,trusted-operator-pubkeys" sep:"none" help:"Trusted operator Ed25519 public key (sc_op_pub_<hex>, hex, or base64, repeatable)."`
	SignAckTimeoutMs       uint64   `toml:"sign_ack_timeout_ms" name:"sign_ack_timeout_ms" aliases:"sign-ack-timeout-ms" default:"1500" help:"Fast failover acknowledgment timeout in milliseconds."`
	SignResponseTimeoutMs  uint64   `toml:"sign_response_timeout_ms" name:"sign_response_timeout_ms" aliases:"sign-response-timeout-ms" default:"60000" help:"Human TouchID/FIDO2 approval timeout in milliseconds."`
	HeartbeatIntervalMs    uint64   `toml:"heartbeat_interval_ms" name:"heartbeat_interval_ms" aliases:"heartbeat-interval-ms" default:"25000" help:"Stream heartbeat interval in milliseconds."`
	MaxClockSkewMs         uint64   `toml:"max_clock_skew_ms" name:"max_clock_skew_ms" aliases:"max-clock-skew-ms" default:"300000" help:"Maximum allowed clock skew in milliseconds."`
	WebDir                 string   `toml:"web_dir" name:"web_dir" aliases:"web-dir" help:"Optional custom directory for /web/ static assets (e.g. custom sshcast_proto.wasm)."`
	DefaultDomain          string   `toml:"default_domain" name:"default_domain" aliases:"default-domain" help:"Optional default swarm domain returned by /web/coordinators when no domain query parameter is specified."`
	DefaultOperatorURL     string   `toml:"default_operator_url" name:"default_operator_url" aliases:"default-operator-url" help:"Optional default Operator URL fallback returned by /web/coordinators."`
	MaxWorkstationsPerUser int      `toml:"max_workstations_per_user" name:"max_workstations_per_user" aliases:"max-workstations-per-user" default:"16" help:"Maximum concurrent workstation connections per user (0 disables cap)."`
	MaxRelaysPerUser       int      `toml:"max_relays_per_user" name:"max_relays_per_user" aliases:"max-relays-per-user" default:"64" help:"Maximum concurrent relay connections per user (0 disables cap)."`
	MaxPendingSignsPerUser int      `toml:"max_pending_signs_per_user" name:"max_pending_signs_per_user" aliases:"max-pending-signs-per-user" default:"16" help:"Maximum concurrent pending sign requests per user (0 disables cap)."`
	MaxUsers               int      `toml:"max_users" name:"max_users" aliases:"max-users" default:"10000" help:"Maximum distinct active users in coordinator registry (0 disables cap)."`
	MaxGRPCMessageBytes    int      `toml:"max_grpc_message_bytes" name:"max_grpc_message_bytes" aliases:"max-grpc-message-bytes" default:"4194304" help:"Maximum gRPC send and receive message size in bytes."`

	parsedAllowedKeys  [][]byte `toml:"-" kong:"-"`
	parsedOperatorKeys [][]byte `toml:"-" kong:"-"`
}

func Default() *Config {
	return &Config{
		ListenAddr:             "127.0.0.1:8080",
		AllowAnyUser:           false,
		SignAckTimeoutMs:       1500,
		SignResponseTimeoutMs:  60000,
		HeartbeatIntervalMs:    25000,
		MaxClockSkewMs:         5 * 60 * 1000,
		MaxWorkstationsPerUser: 16,
		MaxRelaysPerUser:       64,
		MaxPendingSignsPerUser: 16,
		MaxUsers:               10000,
		MaxGRPCMessageBytes:    4194304,
	}
}

// DefaultPaths returns default server.toml search paths (such as $CONFIGURATION_DIRECTORY/server.toml).
func DefaultPaths() []string {
	var paths []string
	if confDir := strings.TrimSpace(os.Getenv("CONFIGURATION_DIRECTORY")); confDir != "" {
		paths = append(paths, filepath.Join(strings.Split(confDir, ":")[0], "server.toml"))
	}
	paths = append(paths, "/etc/sshcast/server.toml")
	return paths
}

// Validate implements kong's validation hook and compiles allowed user/operator public keys.
func (c *Config) Validate() error {
	return c.CompileAllowedKeys()
}

func Load(path string) (*Config, error) {
	cfg := Default()
	if path == "" {
		for _, candidate := range DefaultPaths() {
			if _, err := os.Stat(candidate); err == nil {
				path = candidate
				break
			}
		}
	}
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config %q: %w", path, err)
		}
		if err := toml.Unmarshal(data, cfg); err != nil {
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
	s = strings.TrimPrefix(s, "sc_op_pub_")
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
	c.parsedOperatorKeys = nil
	for _, raw := range c.TrustedOperatorPubkeys {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		pub, err := ParsePubkeyString(raw)
		if err != nil {
			return err
		}
		c.parsedOperatorKeys = append(c.parsedOperatorKeys, pub)
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

func (c *Config) IsOperatorPubkeyTrusted(operatorPubkey []byte) bool {
	for _, trusted := range c.parsedOperatorKeys {
		if bytes.Equal(trusted, operatorPubkey) {
			return true
		}
	}
	return false
}

// IsGrantAuthorized returns true if the user is allowed via:
// 1. allow_any_user = true, OR
// 2. grant.UserPubkey is in allowed_user_pubkeys, OR
// 3. grant.UserCert is present, signed by an operator key in trusted_operator_pubkeys, and valid at nowUnixSec.
func (c *Config) IsGrantAuthorized(grant *sshcastv1.NodeGrant, nowUnixSec uint64) bool {
	if grant == nil {
		return false
	}
	if c.IsUserPubkeyAllowed(grant.GetUserPubkey()) {
		return true
	}
	cert := grant.GetUserCert()
	if cert != nil && c.IsOperatorPubkeyTrusted(cert.GetOperatorPubkey()) {
		if err := auth.VerifyUserCert(cert, grant.GetUserPubkey(), nowUnixSec); err == nil {
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
