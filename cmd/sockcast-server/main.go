package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	sockcastv1 "github.com/theraphim/sockcast-proto/gen/go/sockcast/v1"
	"github.com/theraphim/sockcast-server/internal/config"
	"github.com/theraphim/sockcast-server/internal/hub"
	"github.com/theraphim/sockcast-server/internal/server"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

type stringSliceFlag []string

func (s *stringSliceFlag) String() string { return strings.Join(*s, ",") }
func (s *stringSliceFlag) Set(val string) error {
	*s = append(*s, val)
	return nil
}

func main() {
	var (
		configPath   = flag.String("config", "", "Path to server.toml configuration file")
		listenAddr   = flag.String("listen", "", "Listen address override (e.g. 127.0.0.1:8080 or :8443)")
		tlsCertFile  = flag.String("tls-cert", "", "Optional TLS certificate file (leave empty for h2c behind Nginx/Cloudflare)")
		tlsKeyFile   = flag.String("tls-key", "", "Optional TLS private key file")
		allowAnyUser = flag.Bool("allow-any-user", false, "Allow any valid Ed25519 user root key without allowlist check")
		allowedUsers stringSliceFlag
	)
	flag.Var(&allowedUsers, "allow-user-pubkey", "Allowed user Ed25519 public key (hex or base64, repeatable)")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	if *listenAddr != "" {
		cfg.ListenAddr = *listenAddr
	}
	if *tlsCertFile != "" {
		cfg.TLSCertFile = *tlsCertFile
	}
	if *tlsKeyFile != "" {
		cfg.TLSKeyFile = *tlsKeyFile
	}
	if *allowAnyUser {
		cfg.AllowAnyUser = true
	}
	if len(allowedUsers) > 0 {
		cfg.AllowedUserPubkeys = append(cfg.AllowedUserPubkeys, allowedUsers...)
		if err := cfg.CompileAllowedKeys(); err != nil {
			log.Fatalf("Invalid --allow-user-pubkey: %v", err)
		}
	}

	if !cfg.AllowAnyUser && len(cfg.AllowedUserPubkeys) == 0 {
		log.Printf("[warn] Neither allow_any_user nor allowed_user_pubkeys is configured; all requests will be denied until configured.")
	}

	registry := hub.NewRegistry(cfg.SignAckTimeout(), cfg.SignResponseTimeout())
	sockcastSrv := server.New(cfg, registry)

	grpcServer := grpc.NewServer(
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    30 * time.Second,
			Timeout: 10 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	)
	sockcastv1.RegisterSockcastServiceServer(grpcServer, sockcastSrv)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, "ok")
	})

	mixedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
			grpcServer.ServeHTTP(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})

	h2Server := &http2.Server{}
	httpServer := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: h2c.NewHandler(mixedHandler, h2Server),
	}

	errCh := make(chan error, 1)
	go func() {
		if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
			log.Printf("[sockcast-server] Listening on %s (TLS + HTTP/2 gRPC)", cfg.ListenAddr)
			errCh <- httpServer.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		} else {
			log.Printf("[sockcast-server] Listening on %s (h2c HTTP/2 cleartext for Nginx/Cloudflare proxy)", cfg.ListenAddr)
			errCh <- httpServer.ListenAndServe()
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		log.Printf("[sockcast-server] Received signal %v, shutting down...", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		grpcServer.Stop()
		_ = httpServer.Shutdown(ctx)
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("[sockcast-server] Server error: %v", err)
		}
	}
}
