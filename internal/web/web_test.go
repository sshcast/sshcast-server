package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleCoordinatorsIncludesOperatorURL(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/web/coordinators?domain=https://coord1.example.com", nil)
	rec := httptest.NewRecorder()

	HandleCoordinators(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if payload["ok"] != true {
		t.Fatalf("expected ok=true, got %v", payload["ok"])
	}
	if payload["domain"] != "https://coord1.example.com" {
		t.Fatalf("unexpected domain: %v", payload["domain"])
	}
	if _, hasOpURL := payload["operator_url"]; !hasOpURL {
		t.Fatalf("expected operator_url key in JSON response: %+v", payload)
	}
	servers, ok := payload["servers"].([]any)
	if !ok || len(servers) != 1 || servers[0] != "https://coord1.example.com" {
		t.Fatalf("unexpected servers field: %#v", payload["servers"])
	}

	// Empty domain should also include operator_url key cleanly.
	emptyReq := httptest.NewRequest(http.MethodGet, "/web/coordinators", nil)
	emptyRec := httptest.NewRecorder()
	HandleCoordinators(emptyRec, emptyReq)
	var emptyPayload map[string]any
	if err := json.Unmarshal(emptyRec.Body.Bytes(), &emptyPayload); err != nil {
		t.Fatalf("unmarshal empty response: %v", err)
	}
	if _, hasOpURL := emptyPayload["operator_url"]; !hasOpURL {
		t.Fatalf("expected operator_url key on empty domain response: %+v", emptyPayload)
	}
}

func TestHandleCoordinatorsWithDefaultsAndAssetHeaders(t *testing.T) {
	h := HandleCoordinatorsWithDefaults("https://c1.example.com", "https://op.example.com")

	// Empty query falls back to default_domain and default_operator_url
	req := httptest.NewRequest(http.MethodGet, "/web/coordinators", nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if payload["domain"] != "https://c1.example.com" || payload["default_domain"] != "https://c1.example.com" {
		t.Fatalf("unexpected domain fields: %+v", payload)
	}
	if payload["operator_url"] != "https://op.example.com" {
		t.Fatalf("unexpected operator_url fallback: %+v", payload)
	}

	// Explicit query overrides default_domain while keeping operator_url fallback if DNS yields none
	req2 := httptest.NewRequest(http.MethodGet, "/web/coordinators?domain=https://c2.example.com", nil)
	rec2 := httptest.NewRecorder()
	h(rec2, req2)
	var p2 map[string]any
	if err := json.Unmarshal(rec2.Body.Bytes(), &p2); err != nil {
		t.Fatalf("unmarshal override: %v", err)
	}
	if p2["domain"] != "https://c2.example.com" {
		t.Fatalf("expected explicit domain override, got %+v", p2["domain"])
	}
	servers, ok := p2["servers"].([]any)
	if !ok || len(servers) != 1 || servers[0] != "https://c2.example.com" {
		t.Fatalf("unexpected servers override: %+v", p2["servers"])
	}

	// HandleAssets sets security headers
	assetReq := httptest.NewRequest(http.MethodGet, "/web/", nil)
	assetRec := httptest.NewRecorder()
	HandleAssets("")(assetRec, assetReq)
	if assetRec.Code != http.StatusOK {
		t.Fatalf("expected 200 from /web/, got %d", assetRec.Code)
	}
	if got := assetRec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("expected X-Content-Type-Options nosniff, got %q", got)
	}
	if got := assetRec.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("expected X-Frame-Options DENY, got %q", got)
	}
	if got := assetRec.Header().Get("Referrer-Policy"); got != "strict-origin-when-cross-origin" {
		t.Fatalf("expected Referrer-Policy strict-origin-when-cross-origin, got %q", got)
	}
}
