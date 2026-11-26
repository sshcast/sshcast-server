package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alecthomas/kong"
	kongtoml "github.com/alecthomas/kong-toml"
	"stingr.net/go/sshcast-server/internal/config"
)

func TestAcquireStandaloneListenerUnixAndTCP(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "run", "server.sock")

	unixLn, err := acquireStandaloneListener("unix:" + sockPath)
	if err != nil {
		t.Fatalf("acquireStandaloneListener unix failed: %v", err)
	}
	defer unixLn.Close()

	if unixLn.Addr().Network() != "unix" {
		t.Fatalf("expected unix network, got %q", unixLn.Addr().Network())
	}
	if _, err := os.Stat(sockPath); err != nil {
		t.Fatalf("expected socket file at %s: %v", sockPath, err)
	}

	tcpLn, err := acquireStandaloneListener("127.0.0.1:0")
	if err != nil {
		t.Fatalf("acquireStandaloneListener tcp failed: %v", err)
	}
	defer tcpLn.Close()

	if tcpLn.Addr().Network() != "tcp" {
		t.Fatalf("expected tcp network, got %q", tcpLn.Addr().Network())
	}
}

func TestKongTOMLAndCLIFlagOverrides(t *testing.T) {
	tmpDir := t.TempDir()
	tomlPath := filepath.Join(tmpDir, "server.toml")
	pubHex := strings.Repeat("ab", 32)
	opHex := strings.Repeat("cd", 32)

	tomlContent := `
listen_addr = "unix:/run/sshcast-server/server.sock"
sign_ack_timeout_ms = 2500
allowed_user_pubkeys = ["sc_pub_` + pubHex + `"]
trusted_operator_pubkeys = ["sc_op_pub_` + opHex + `"]
`
	if err := os.WriteFile(tomlPath, []byte(tomlContent), 0600); err != nil {
		t.Fatalf("WriteFile server.toml: %v", err)
	}

	var parsed cli
	parser, err := kong.New(&parsed, kong.Configuration(kongtoml.Loader))
	if err != nil {
		t.Fatalf("kong.New: %v", err)
	}
	_, err = parser.Parse([]string{
		"--config", tomlPath,
		"--listen", "127.0.0.1:9090",
		"--allow-any-user",
	})
	if err != nil {
		t.Fatalf("parser.Parse: %v", err)
	}

	if parsed.ListenAddr != "127.0.0.1:9090" {
		t.Fatalf("expected CLI --listen override 127.0.0.1:9090, got %q", parsed.ListenAddr)
	}
	if parsed.SignAckTimeoutMs != 2500 {
		t.Fatalf("expected TOML sign_ack_timeout_ms 2500, got %d", parsed.SignAckTimeoutMs)
	}
	if parsed.SignResponseTimeoutMs != 60000 {
		t.Fatalf("expected default sign_response_timeout_ms 60000, got %d", parsed.SignResponseTimeoutMs)
	}
	if !parsed.AllowAnyUser {
		t.Fatalf("expected AllowAnyUser=true from CLI flag")
	}
	if len(parsed.AllowedUserPubkeys) != 1 || len(parsed.TrustedOperatorPubkeys) != 1 {
		t.Fatalf("expected 1 allowed user pubkey and 1 trusted operator pubkey from TOML, got %v / %v",
			parsed.AllowedUserPubkeys, parsed.TrustedOperatorPubkeys)
	}
	if parsed.MaxWorkstationsPerUser != 16 || parsed.MaxRelaysPerUser != 64 ||
		parsed.MaxPendingSignsPerUser != 16 || parsed.MaxUsers != 10000 ||
		parsed.MaxGRPCMessageBytes != 4194304 {
		t.Fatalf("unexpected default coordinator safety caps via Kong: %+v", parsed.Config)
	}

	defCfg := config.Default()
	if defCfg.MaxWorkstationsPerUser != 16 || defCfg.MaxRelaysPerUser != 64 ||
		defCfg.MaxPendingSignsPerUser != 16 || defCfg.MaxUsers != 10000 ||
		defCfg.MaxGRPCMessageBytes != 4194304 {
		t.Fatalf("unexpected config.Default() safety caps: %+v", defCfg)
	}
}
