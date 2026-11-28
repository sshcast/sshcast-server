package web

import (
	"embed"
	"encoding/json"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"stingr.net/go/sshcast-proto/pkg/dns"
)

//go:embed assets/*
var embeddedAssets embed.FS

var assetsFS, _ = fs.Sub(embeddedAssets, "assets")

func init() {
	_ = mime.AddExtensionType(".wasm", "application/wasm")
}

// HandleCoordinators resolves _sshcast.<domain> DNS TXT coordinator records for the Browser Workstation UI.
func HandleCoordinators(w http.ResponseWriter, r *http.Request) {
	HandleCoordinatorsWithDefaults("", "").ServeHTTP(w, r)
}

// HandleCoordinatorsWithDefaults resolves _sshcast.<domain> DNS TXT records, falling back
// to defaultDomain and defaultOperatorURL when omitted by the request or DNS TXT records.
func HandleCoordinatorsWithDefaults(defaultDomain, defaultOperatorURL string) http.HandlerFunc {
	defDomain := strings.TrimSpace(defaultDomain)
	defOpURL := strings.TrimSpace(defaultOperatorURL)
	return func(w http.ResponseWriter, r *http.Request) {
		domain := strings.TrimSpace(r.URL.Query().Get("domain"))
		if domain == "" && defDomain != "" {
			domain = defDomain
		}
		var disc dns.SwarmDiscovery
		if domain != "" {
			disc = dns.ResolveSwarmDiscovery(r.Context(), []string{domain})
		}
		if disc.OperatorURL == "" && defOpURL != "" {
			disc.OperatorURL = defOpURL
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":             true,
			"domain":         domain,
			"default_domain": defDomain,
			"servers":        disc.Servers,
			"operator_url":   disc.OperatorURL,
		})
	}
}

// HandleAssets returns an http.HandlerFunc serving the Browser Workstation Web App under /web/
// using http.ServeFile (when overlaid by baseDir on disk) and http.ServeFileFS (from embed.FS).
func HandleAssets(baseDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		rel := strings.TrimPrefix(r.URL.Path, "/web/")
		if baseDir != "" {
			diskPath := filepath.Join(baseDir, filepath.FromSlash(rel))
			if info, err := os.Stat(diskPath); err == nil && !info.IsDir() {
				http.ServeFile(w, r, diskPath)
				return
			}
		}

		name := rel
		if name == "" {
			name = "index.html"
		}
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			if _, err := fs.Stat(assetsFS, name+".gz"); err == nil {
				if ct := mime.TypeByExtension(path.Ext(name)); ct != "" {
					w.Header().Set("Content-Type", ct)
				}
				w.Header().Set("Content-Encoding", "gzip")
				http.ServeFileFS(w, r, assetsFS, name+".gz")
				return
			}
		}
		http.ServeFileFS(w, r, assetsFS, name)
	}
}
