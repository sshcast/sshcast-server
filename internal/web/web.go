package web

import (
	"bytes"
	"compress/gzip"
	"embed"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"stingr.net/go/sshcast-proto/pkg/dns"
)

//go:embed assets/*
var embeddedAssets embed.FS

// Handler returns an http.Handler serving the Browser Workstation Web App (HTML + JS + WASM)
// under /web/ (and optionally overlaid by a custom directory on disk if customDir != "").
func Handler(customDir string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		rel := strings.TrimPrefix(r.URL.Path, "/web")
		if rel == "" {
			http.Redirect(w, r, "/web/", http.StatusMovedPermanently)
			return
		}
		rel = strings.TrimPrefix(rel, "/")
		if rel == "" {
			rel = "index.html"
		}
		if strings.Contains(rel, "..") || strings.Contains(rel, "\\") {
			http.NotFound(w, r)
			return
		}

		// 0. DNS TXT coordinator discovery helper for the Browser Workstation UI (/web/coordinators?domain=...)
		if rel == "coordinators" {
			domain := strings.TrimSpace(r.URL.Query().Get("domain"))
			var servers []string
			if domain != "" {
				servers = dns.ResolveCoordinatorServers(r.Context(), []string{domain})
			}
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":      true,
				"domain":  domain,
				"servers": servers,
			})
			return
		}

		// 1. Check optional custom directory override on disk (e.g. for custom sshcast_proto.wasm)
		if customDir != "" {
			diskPath := filepath.Join(customDir, filepath.FromSlash(rel))
			if info, err := os.Stat(diskPath); err == nil && !info.IsDir() {
				setContentType(w, rel)
				http.ServeFile(w, r, diskPath)
				return
			}
		}

		// 2. Special handling for sshcast_wasm.wasm stored as assets/sshcast_wasm.wasm.gz
		if rel == "sshcast_wasm.wasm" {
			gzBytes, err := embeddedAssets.ReadFile("assets/sshcast_wasm.wasm.gz")
			if err != nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/wasm")
			w.Header().Set("Cache-Control", "public, max-age=3600")
			if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
				w.Header().Set("Content-Encoding", "gzip")
				w.WriteHeader(http.StatusOK)
				if r.Method != http.MethodHead {
					_, _ = w.Write(gzBytes)
				}
				return
			}
			gr, err := gzip.NewReader(bytes.NewReader(gzBytes))
			if err != nil {
				http.Error(w, "failed to decompress wasm", http.StatusInternalServerError)
				return
			}
			defer gr.Close()
			w.WriteHeader(http.StatusOK)
			if r.Method != http.MethodHead {
				_, _ = io.Copy(w, gr)
			}
			return
		}

		// 3. Serve embedded asset from assets/<rel>
		data, err := embeddedAssets.ReadFile("assets/" + rel)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		setContentType(w, rel)
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = w.Write(data)
		}
	})
}

func setContentType(w http.ResponseWriter, rel string) {
	switch {
	case strings.HasSuffix(rel, ".html"):
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	case strings.HasSuffix(rel, ".js"):
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	case strings.HasSuffix(rel, ".wasm"):
		w.Header().Set("Content-Type", "application/wasm")
	case strings.HasSuffix(rel, ".css"):
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	}
}
