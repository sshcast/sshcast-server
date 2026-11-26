package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	kongtoml "github.com/alecthomas/kong-toml"
	"github.com/coreos/go-systemd/v22/activation"
	"github.com/coreos/go-systemd/v22/daemon"
	sshcastv1 "stingr.net/go/sshcast-proto/gen/go/sshcast/v1"
	"stingr.net/go/sshcast-server/internal/config"
	"stingr.net/go/sshcast-server/internal/hub"
	"stingr.net/go/sshcast-server/internal/server"
	"stingr.net/go/sshcast-server/internal/web"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

type cli struct {
	ConfigFile    kong.ConfigFlag `name:"config" help:"Path to server.toml configuration file." placeholder:"PATH"`
	config.Config `embed:""`
}

// acquireStandaloneListener opens a Unix domain socket (if addr starts with "unix:" or "/")
// or a TCP listener when sshcast-server is started outside systemd socket activation.
func acquireStandaloneListener(addr string) (net.Listener, error) {
	trimmed := strings.TrimSpace(addr)
	if strings.HasPrefix(trimmed, "unix:") || strings.HasPrefix(trimmed, "/") {
		sockPath := strings.TrimPrefix(trimmed, "unix:")
		if err := os.MkdirAll(filepath.Dir(sockPath), 0755); err != nil {
			return nil, fmt.Errorf("mkdir socket parent %q: %w", filepath.Dir(sockPath), err)
		}
		_ = os.Remove(sockPath)
		ln, err := net.Listen("unix", sockPath)
		if err != nil {
			return nil, err
		}
		_ = os.Chmod(sockPath, 0666)
		return ln, nil
	}
	return net.Listen("tcp", trimmed)
}

func main() {
	var cliArgs cli
	kong.Parse(&cliArgs,
		kong.Name("sshcast-server"),
		kong.Description("Sshcast Coordinator Server (Roaming SSH Agent Router)"),
		kong.Configuration(kongtoml.Loader, config.DefaultPaths()...),
	)
	cfg := &cliArgs.Config

	if !cfg.AllowAnyUser && len(cfg.AllowedUserPubkeys) == 0 && len(cfg.TrustedOperatorPubkeys) == 0 {
		log.Printf("[warn] Neither allow_any_user, trusted_operator_pubkeys, nor allowed_user_pubkeys is configured; all requests will be denied until configured.")
	}

	registry := hub.NewRegistryWithLimits(cfg.SignAckTimeout(), cfg.SignResponseTimeout(), hub.Limits{
		MaxWorkstationsPerUser: cfg.MaxWorkstationsPerUser,
		MaxRelaysPerUser:       cfg.MaxRelaysPerUser,
		MaxPendingSignsPerUser: cfg.MaxPendingSignsPerUser,
		MaxUsers:               cfg.MaxUsers,
	})
	sshcastSrv := server.New(cfg, registry)

	grpcOpts := []grpc.ServerOption{
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    30 * time.Second,
			Timeout: 10 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	}
	if cfg.MaxGRPCMessageBytes > 0 {
		grpcOpts = append(grpcOpts,
			grpc.MaxRecvMsgSize(cfg.MaxGRPCMessageBytes),
			grpc.MaxSendMsgSize(cfg.MaxGRPCMessageBytes),
		)
	}
	grpcServer := grpc.NewServer(grpcOpts...)
	sshcastv1.RegisterSshcastServiceServer(grpcServer, sshcastSrv)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = fmt.Fprintln(w, "ok")
	})
	mux.Handle("/ws/workstation", sshcastSrv.WorkstationWebSocketHandler())
	mux.HandleFunc("GET /web/coordinators", web.HandleCoordinators)
	mux.HandleFunc("GET /web/", web.HandleAssets(cfg.WebDir))
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/web/", http.StatusFound)
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
		Handler: h2c.NewHandler(mixedHandler, h2Server),
	}

	listeners, err := activation.Listeners()
	if err != nil {
		log.Fatalf("Failed to acquire systemd socket-activated listeners: %v", err)
	}
	if len(listeners) == 0 {
		ln, err := acquireStandaloneListener(cfg.ListenAddr)
		if err != nil {
			log.Fatalf("Failed to listen on %s: %v", cfg.ListenAddr, err)
		}
		listeners = append(listeners, ln)
	}

	errCh := make(chan error, len(listeners))
	for _, ln := range listeners {
		if ln == nil {
			continue
		}
		ln := ln
		go func() {
			if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
				log.Printf("[sshcast-server] Listening on %s://%s (TLS + HTTP/2 gRPC)", ln.Addr().Network(), ln.Addr().String())
				errCh <- httpServer.ServeTLS(ln, cfg.TLSCertFile, cfg.TLSKeyFile)
			} else {
				log.Printf("[sshcast-server] Listening on %s://%s (h2c HTTP/2 cleartext for Nginx/Cloudflare proxy)", ln.Addr().Network(), ln.Addr().String())
				errCh <- httpServer.Serve(ln)
			}
		}()
	}

	_, _ = daemon.SdNotify(false, daemon.SdNotifyReady)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		log.Printf("[sshcast-server] Received signal %v, shutting down...", sig)
		_, _ = daemon.SdNotify(false, daemon.SdNotifyStopping)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		grpcServer.Stop()
		_ = httpServer.Shutdown(ctx)
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("[sshcast-server] Server error: %v", err)
		}
	}
}
