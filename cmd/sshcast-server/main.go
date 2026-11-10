package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

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

const systemdListenFDsStart = 3

type stringSliceFlag []string

func (s *stringSliceFlag) String() string { return strings.Join(*s, ",") }
func (s *stringSliceFlag) Set(val string) error {
	*s = append(*s, val)
	return nil
}

// acquireSystemdListeners inspects LISTEN_FDS (and LISTEN_PID if set) and returns a net.Listener
// for every socket file descriptor passed by systemd (starting at FD 3).
// This allows sshcast-server to simultaneously serve any combination of sshcast-server.socket
// (/run/sshcast/server.sock) and sshcast-server-tcp@<port>.socket (127.0.0.1:<port>).
func acquireSystemdListeners() ([]net.Listener, error) {
	nfdsStr := strings.TrimSpace(os.Getenv("LISTEN_FDS"))
	if nfdsStr == "" {
		return nil, nil
	}
	if pidStr := strings.TrimSpace(os.Getenv("LISTEN_PID")); pidStr != "" {
		pid, err := strconv.Atoi(pidStr)
		if err != nil || pid != os.Getpid() {
			return nil, nil
		}
	}
	nfds, err := strconv.Atoi(nfdsStr)
	if err != nil || nfds <= 0 {
		return nil, fmt.Errorf("invalid LISTEN_FDS=%q", nfdsStr)
	}

	listeners := make([]net.Listener, 0, nfds)
	for i := 0; i < nfds; i++ {
		fd := systemdListenFDsStart + i
		syscall.CloseOnExec(fd)
		f := os.NewFile(uintptr(fd), fmt.Sprintf("systemd-listen-fd-%d", fd))
		if f == nil {
			for _, ln := range listeners {
				_ = ln.Close()
			}
			return nil, fmt.Errorf("failed to wrap systemd file descriptor %d", fd)
		}
		ln, err := net.FileListener(f)
		_ = f.Close()
		if err != nil {
			for _, prev := range listeners {
				_ = prev.Close()
			}
			return nil, fmt.Errorf("net.FileListener on fd %d: %w", fd, err)
		}
		listeners = append(listeners, ln)
	}
	return listeners, nil
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
	var (
		configPath   = flag.String("config", "", "Path to server.toml configuration file")
		listenAddr   = flag.String("listen", "", "Listen address override when not socket-activated (e.g. unix:/run/sshcast/server.sock or 127.0.0.1:8080)")
		tlsCertFile  = flag.String("tls-cert", "", "Optional TLS certificate file (leave empty for h2c behind Nginx/Cloudflare)")
		tlsKeyFile   = flag.String("tls-key", "", "Optional TLS private key file")
		webDir       = flag.String("web-dir", "", "Optional custom directory for /web/ static assets (e.g. custom sshcast_proto.wasm)")
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
	if *webDir != "" {
		cfg.WebDir = *webDir
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
	sshcastSrv := server.New(cfg, registry)

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
	sshcastv1.RegisterSshcastServiceServer(grpcServer, sshcastSrv)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, "ok")
	})
	mux.Handle("/ws/workstation", sshcastSrv.WorkstationWebSocketHandler())
	webHandler := web.Handler(cfg.WebDir)
	mux.Handle("/web", webHandler)
	mux.Handle("/web/", webHandler)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/web/", http.StatusFound)
			return
		}
		http.NotFound(w, r)
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

	listeners, err := acquireSystemdListeners()
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

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		log.Printf("[sshcast-server] Received signal %v, shutting down...", sig)
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
