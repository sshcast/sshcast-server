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
