package wasmengine

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	sockcastv1 "github.com/theraphim/sockcast-proto/gen/go/sockcast/v1"
	"github.com/theraphim/sockcast-proto/pkg/auth"
	"google.golang.org/protobuf/proto"
)

const bundlePrefix = "sc1_"

type enrollmentBundleWire struct {
	Servers            []string `json:"servers"`
	NodePrivkeySeedB64 string   `json:"node_privkey_seed_b64"`
	GrantProtoB64      string   `json:"grant_proto_b64"`
}

type decodedBundle struct {
	Servers    []string
	NodePriv   ed25519.PrivateKey
	Grant      *sockcastv1.NodeGrant
}

func decodeBundle(token string) (*decodedBundle, error) {
	token = strings.TrimSpace(token)
	if !strings.HasPrefix(token, bundlePrefix) {
		return nil, fmt.Errorf("enrollment bundle must start with %q", bundlePrefix)
	}
	b64Part := strings.TrimPrefix(token, bundlePrefix)
	jsonBytes, err := base64.RawURLEncoding.DecodeString(b64Part)
	if err != nil {
		return nil, fmt.Errorf("base64 decode error: %w", err)
	}
	var wire enrollmentBundleWire
	if err := json.Unmarshal(jsonBytes, &wire); err != nil {
		return nil, fmt.Errorf("json decode error: %w", err)
	}
	seed, err := base64.RawURLEncoding.DecodeString(wire.NodePrivkeySeedB64)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("invalid node private key seed (expected 32 bytes)")
	}
	grantBytes, err := base64.RawURLEncoding.DecodeString(wire.GrantProtoB64)
	if err != nil {
		return nil, fmt.Errorf("grant base64 decode error: %w", err)
	}
	grant := &sockcastv1.NodeGrant{}
	if err := proto.Unmarshal(grantBytes, grant); err != nil {
		return nil, fmt.Errorf("grant protobuf decode error: %w", err)
	}
	return &decodedBundle{
		Servers:  wire.Servers,
		NodePriv: ed25519.NewKeyFromSeed(seed),
		Grant:    grant,
	}, nil
}

type HeldKeyInfo struct {
	KeyType           string `json:"key_type"`
	FingerprintSha256 string `json:"fingerprint_sha256"`
	Comment           string `json:"comment"`
}

type AncestorInfo struct {
	Pid     uint32 `json:"pid"`
	Comm    string `json:"comm"`
	Cmdline string `json:"cmdline"`
}

type SignRequestInfo struct {
	RequestID         string         `json:"request_id"`
	TimestampUnixMs   uint64         `json:"timestamp_unix_ms"`
	VerifiedNodeID    string         `json:"verified_node_id"`
	Hostname          string         `json:"hostname"`
	UID               uint32         `json:"uid"`
	PID               uint32         `json:"pid"`
	Comm              string         `json:"comm"`
	Cmdline           string         `json:"cmdline"`
	Cwd               string         `json:"cwd"`
	PrimaryTool       string         `json:"primary_tool"`
	PrimaryCmdline    string         `json:"primary_cmdline"`
	Ancestors         []AncestorInfo `json:"ancestors"`
	IsUserauthRequest bool           `json:"is_userauth_request"`
	TargetUsername    string         `json:"target_username"`
	ServiceName       string         `json:"service_name"`
	PubkeyAlgorithm   string         `json:"pubkey_algorithm"`
	KeyFingerprint    string         `json:"key_fingerprint"`
	KeyComment        string         `json:"key_comment"`
	HasMatchingKey    bool           `json:"has_matching_key"`
}

type Engine struct {
	mu              sync.Mutex
	bundle          *decodedBundle
	keys            []*LoadedSshKey
	pendingRequests map[string]*sockcastv1.SignRequest
	nonceCounter    uint64
}

func NewEngine() *Engine {
	return &Engine{
		pendingRequests: make(map[string]*sockcastv1.SignRequest),
	}
}

func (e *Engine) keySummaries() []HeldKeyInfo {
	out := make([]HeldKeyInfo, 0, len(e.keys))
	for _, k := range e.keys {
		out = append(out, HeldKeyInfo{
			KeyType:           k.PublicKey.GetKeyType(),
			FingerprintSha256: k.PublicKey.GetFingerprintSha256(),
			Comment:           k.PublicKey.GetComment(),
		})
	}
	return out
}

func deriveWSURL(serverURL string) string {
	trimmed := strings.TrimRight(strings.TrimSpace(serverURL), "/")
	if after, ok := strings.CutPrefix(trimmed, "https://"); ok {
		return "wss://" + after + "/ws/workstation"
	}
	if after, ok := strings.CutPrefix(trimmed, "http://"); ok {
		return "ws://" + after + "/ws/workstation"
	}
	if strings.HasPrefix(trimmed, "wss://") || strings.HasPrefix(trimmed, "ws://") {
		if strings.HasSuffix(trimmed, "/ws/workstation") {
			return trimmed
		}
		return trimmed + "/ws/workstation"
	}
	return "wss://" + trimmed + "/ws/workstation"
}

func extractPrimaryTool(pc *sockcastv1.ProcessContext) (string, string) {
	if pc == nil {
		return "ssh", ""
	}
	shells := map[string]bool{
		"sh": true, "bash": true, "zsh": true, "fish": true, "dash": true,
		"ksh": true, "tcsh": true, "csh": true, "sshd": true, "systemd": true,
		"init": true, "tmux": true, "zellij": true, "screen": true,
	}
	for _, anc := range pc.GetAncestors() {
		parts := strings.Split(anc.GetComm(), "/")
		base := strings.TrimLeft(parts[len(parts)-1], "-")
		if base != "" && !shells[base] && base != "ssh" {
			cmd := strings.TrimSpace(anc.GetCmdline())
			if cmd == "" {
				cmd = anc.GetComm()
			}
			return base, cmd
		}
	}
	comm := strings.TrimSpace(pc.GetComm())
	if comm == "" {
		comm = "ssh"
	}
	cmdline := strings.TrimSpace(pc.GetCmdline())
	if cmdline == "" {
		cmdline = comm
	}
	return comm, cmdline
}

func (e *Engine) CallJSON(requestJSON string) string {
	e.mu.Lock()
	defer e.mu.Unlock()

	var req map[string]any
	if err := json.Unmarshal([]byte(requestJSON), &req); err != nil {
		return marshalJSON(map[string]any{
			"ok":    false,
			"error": fmt.Sprintf("Invalid JSON request: %v", err),
		})
	}
	resp := e.callMap(req)
	return marshalJSON(resp)
}

func marshalJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return `{"ok":false,"error":"json marshal failed"}`
	}
	return string(b)
}

func getString(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func getUint64(m map[string]any, key string) uint64 {
	if v, ok := m[key].(float64); ok && v >= 0 {
		return uint64(v)
	}
	return 0
}

func getBool(m map[string]any, key string, def bool) bool {
	if v, ok := m[key].(bool); ok {
		return v
	}
	return def
}

func (e *Engine) callMap(req map[string]any) map[string]any {
	op := getString(req, "op")
	switch op {
	case "parse_bundle", "set_bundle":
		bundleStr := strings.TrimSpace(getString(req, "bundle_str"))
		nowSec := getUint64(req, "now_unix_sec")
		b, err := decodeBundle(bundleStr)
		if err != nil {
			return map[string]any{
				"ok":    false,
				"error": fmt.Sprintf("Invalid enrollment bundle: %v", err),
			}
		}
		if err := auth.VerifyNodeGrant(b.Grant, nowSec); err != nil {
			return map[string]any{
				"ok":    false,
				"error": fmt.Sprintf("Node grant verification failed: %v", err),
			}
		}
		if b.Grant.GetRole() != sockcastv1.NodeRole_NODE_ROLE_CLIENT {
			return map[string]any{
				"ok":    false,
				"error": "Enrollment bundle has RELAY role; browser workstation requires a CLIENT bundle",
			}
		}
		var coordURL string
		if len(b.Servers) > 0 {
			coordURL = b.Servers[0]
		}
		wsURL := deriveWSURL(coordURL)
		if op == "set_bundle" {
			e.bundle = b
		}
		return map[string]any{
			"ok":                 true,
			"coordinator_url":    coordURL,
			"ws_url":             wsURL,
			"servers":            b.Servers,
			"user_id":            b.Grant.GetUserId(),
			"node_id":            b.Grant.GetNodeId(),
			"role":               "CLIENT",
			"issued_at_unix_sec": b.Grant.GetIssuedAtUnixSec(),
			"expires_at_unix_sec": b.Grant.GetExpiresAtUnixSec(),
		}

	case "add_ssh_key":
		pemStr := getString(req, "pem")
		passphrase := getString(req, "passphrase")
		key, err := ParseOpenSSHPEM(pemStr, passphrase, passphrase != "")
		if err != nil {
			return map[string]any{
				"ok":               false,
				"error":            err.Error(),
				"needs_passphrase": errors.Is(err, ErrPassphraseRequired),
			}
		}
		added := HeldKeyInfo{
			KeyType:           key.PublicKey.GetKeyType(),
			FingerprintSha256: key.PublicKey.GetFingerprintSha256(),
			Comment:           key.PublicKey.GetComment(),
		}
		replaced := false
		for i, existing := range e.keys {
			if bytes.Equal(existing.PublicKey.GetKeyBlob(), key.PublicKey.GetKeyBlob()) {
				e.keys[i] = key
				replaced = true
				break
			}
		}
		if !replaced {
			e.keys = append(e.keys, key)
		}
		return map[string]any{
			"ok":        true,
			"added_key": added,
			"keys":      e.keySummaries(),
		}

	case "remove_ssh_key":
		fp := strings.TrimSpace(getString(req, "fingerprint_sha256"))
		filtered := make([]*LoadedSshKey, 0, len(e.keys))
		removed := false
		for _, k := range e.keys {
			if k.PublicKey.GetFingerprintSha256() == fp {
				removed = true
			} else {
				filtered = append(filtered, k)
			}
		}
		e.keys = filtered
		return map[string]any{
			"ok":      true,
			"removed": removed,
			"keys":    e.keySummaries(),
		}

	case "list_ssh_keys":
		return map[string]any{
			"ok":   true,
			"keys": e.keySummaries(),
		}

	case "build_auth_handshake_frame":
		if e.bundle == nil {
			return map[string]any{
				"ok":    false,
				"error": "No enrollment bundle configured in WASM engine",
			}
		}
		nowMs := getUint64(req, "now_unix_ms")
		e.nonceCounter++
		var nonce []byte
		if hexStr := getString(req, "nonce_hex"); hexStr != "" {
			if decoded, err := hex.DecodeString(hexStr); err == nil {
				nonce = decoded
			}
		}
		if len(nonce) == 0 {
			h := sha256.New()
			h.Write([]byte("sockcast-wasm-nonce-v1"))
			var buf [16]byte
			binary.BigEndian.PutUint64(buf[0:8], nowMs)
			binary.BigEndian.PutUint64(buf[8:16], e.nonceCounter)
			h.Write(buf[:])
			h.Write(e.bundle.Grant.GetNodePubkey())
			sum := h.Sum(nil)
			nonce = sum[:16]
		}
		nodeAuth := &sockcastv1.NodeAuth{
			Grant:           e.bundle.Grant,
			TimestampUnixMs: nowMs,
			Nonce:           nonce,
		}
		if err := auth.SignNodeAuth(nodeAuth, e.bundle.NodePriv); err != nil {
			return map[string]any{"ok": false, "error": err.Error()}
		}
		msg := &sockcastv1.ClientStreamMessage{
			Payload: &sockcastv1.ClientStreamMessage_AuthHandshake{
				AuthHandshake: nodeAuth,
			},
		}
		raw, err := proto.Marshal(msg)
		if err != nil {
			return map[string]any{"ok": false, "error": err.Error()}
		}
		return map[string]any{
			"ok":        true,
			"frame_b64": base64.StdEncoding.EncodeToString(raw),
		}

	case "build_status_frame":
		lastInputMs := getUint64(req, "last_input_epoch_ms")
		forceActive := getBool(req, "force_active", false)
		osName := getString(req, "os")
		if osName == "" {
			osName = "browser-wasm"
		}
		pks := make([]*sockcastv1.PublicKey, 0, len(e.keys))
		for _, k := range e.keys {
			pks = append(pks, k.PublicKey)
		}
		msg := &sockcastv1.ClientStreamMessage{
			Payload: &sockcastv1.ClientStreamMessage_Status{
				Status: &sockcastv1.WorkstationStatus{
					LastInputEpochMs: lastInputMs,
					Keys:             pks,
					Os:               osName,
					ForceActive:      forceActive,
				},
			},
		}
		raw, err := proto.Marshal(msg)
		if err != nil {
			return map[string]any{"ok": false, "error": err.Error()}
		}
		return map[string]any{
			"ok":        true,
			"frame_b64": base64.StdEncoding.EncodeToString(raw),
		}

	case "build_request_zellij_hosts_frame":
		refresh := getBool(req, "refresh", true)
		msg := &sockcastv1.ClientStreamMessage{
			Payload: &sockcastv1.ClientStreamMessage_RequestZellijHosts{
				RequestZellijHosts: refresh,
			},
		}
		raw, _ := proto.Marshal(msg)
		return map[string]any{
			"ok":        true,
			"frame_b64": base64.StdEncoding.EncodeToString(raw),
		}

	case "decode_server_frame":
		frameB64 := getString(req, "frame_b64")
		nowSec := getUint64(req, "now_unix_sec")
		raw, err := base64.StdEncoding.DecodeString(frameB64)
		if err != nil {
			return map[string]any{"ok": false, "error": fmt.Sprintf("base64 decode: %v", err)}
		}
		srvMsg := &sockcastv1.ServerStreamMessage{}
		if err := proto.Unmarshal(raw, srvMsg); err != nil {
			return map[string]any{"ok": false, "error": fmt.Sprintf("protobuf decode: %v", err)}
		}

		switch p := srvMsg.GetPayload().(type) {
		case *sockcastv1.ServerStreamMessage_ServerHeartbeatEpochMs:
			return map[string]any{
				"ok":                        true,
				"frame_type":                "heartbeat",
				"server_heartbeat_epoch_ms": p.ServerHeartbeatEpochMs,
			}
		case *sockcastv1.ServerStreamMessage_CancelSignRequest:
			reqID := p.CancelSignRequest.GetRequestId()
			delete(e.pendingRequests, reqID)
			return map[string]any{
				"ok":         true,
				"frame_type": "cancel_sign_request",
				"request_id": reqID,
			}
		case *sockcastv1.ServerStreamMessage_ZellijHostList:
			hosts := make([]map[string]any, 0, len(p.ZellijHostList.GetHosts()))
			for _, h := range p.ZellijHostList.GetHosts() {
				sessions := make([]map[string]any, 0, len(h.GetSessions()))
				for _, s := range h.GetSessions() {
					sessions = append(sessions, map[string]any{
						"name":         s.GetName(),
						"created_info": s.GetCreatedInfo(),
						"exited":       s.GetExited(),
					})
				}
				hosts = append(hosts, map[string]any{
					"node_id":        h.GetNodeId(),
					"zellij_enabled": h.GetZellijEnabled(),
					"sessions":       sessions,
				})
			}
			return map[string]any{
				"ok":         true,
				"frame_type": "zellij_host_list",
				"hosts":      hosts,
			}
		case *sockcastv1.ServerStreamMessage_ZellijFrame:
			zf := p.ZellijFrame
			return map[string]any{
				"ok":             true,
				"frame_type":     "zellij_frame",
				"tunnel_id":      zf.GetTunnelId(),
				"relay_node_id":  zf.GetRelayNodeId(),
				"client_node_id": zf.GetClientNodeId(),
				"zf_type":        int32(zf.GetFrameType()),
				"payload_b64":    base64.StdEncoding.EncodeToString(zf.GetPayload()),
			}
		case *sockcastv1.ServerStreamMessage_SignRequest:
			signReq := p.SignRequest
			ackMsg := &sockcastv1.ClientStreamMessage{
				Payload: &sockcastv1.ClientStreamMessage_SignAck{
					SignAck: &sockcastv1.SignAck{RequestId: signReq.GetRequestId()},
				},
			}
			ackRaw, _ := proto.Marshal(ackMsg)
			ackB64 := base64.StdEncoding.EncodeToString(ackRaw)

			var handledBy string
			if e.bundle != nil {
				handledBy = e.bundle.Grant.GetNodeId()
			}

			if err := auth.VerifySignRequest(signReq, nowSec); err != nil {
				denyMsg := &sockcastv1.ClientStreamMessage{
					Payload: &sockcastv1.ClientStreamMessage_SignResponse{
						SignResponse: &sockcastv1.SignResponse{
							RequestId:       signReq.GetRequestId(),
							Approved:        false,
							ErrorMessage:    fmt.Sprintf("End-to-end verification failed: %v", err),
							HandledByNodeId: handledBy,
						},
					},
				}
				denyRaw, _ := proto.Marshal(denyMsg)
				return map[string]any{
					"ok":             true,
					"frame_type":     "sign_request_invalid",
					"request_id":     signReq.GetRequestId(),
					"error":          err.Error(),
					"ack_frame_b64":  ackB64,
					"deny_frame_b64": base64.StdEncoding.EncodeToString(denyRaw),
				}
			}

			if e.bundle != nil {
				if !bytes.Equal(signReq.GetRelayGrant().GetUserPubkey(), e.bundle.Grant.GetUserPubkey()) {
					denyMsg := &sockcastv1.ClientStreamMessage{
						Payload: &sockcastv1.ClientStreamMessage_SignResponse{
							SignResponse: &sockcastv1.SignResponse{
								RequestId:       signReq.GetRequestId(),
								Approved:        false,
								ErrorMessage:    "Relay user_pubkey mismatch",
								HandledByNodeId: handledBy,
							},
						},
					}
					denyRaw, _ := proto.Marshal(denyMsg)
					return map[string]any{
						"ok":             true,
						"frame_type":     "sign_request_invalid",
						"request_id":     signReq.GetRequestId(),
						"error":          "Relay user_pubkey does not match client bundle user_pubkey",
						"ack_frame_b64":  ackB64,
						"deny_frame_b64": base64.StdEncoding.EncodeToString(denyRaw),
					}
				}
			}

			verifiedNodeID := signReq.GetRelayGrant().GetNodeId()
			pc := signReq.GetProcessContext()
			primaryTool, primaryCmdline := extractPrimaryTool(pc)
			ancestors := make([]AncestorInfo, 0, len(pc.GetAncestors()))
			for _, a := range pc.GetAncestors() {
				ancestors = append(ancestors, AncestorInfo{
					Pid:     a.GetPid(),
					Comm:    a.GetComm(),
					Cmdline: a.GetCmdline(),
				})
			}

			parsedSSH := signReq.GetSshAuthContext()
			if parsedSSH == nil {
				parsedSSH = ParseSshAuthContext(signReq.GetData())
			}
			pkInfo := ParsePublicKeyBlob(signReq.GetKeyBlob(), "")
			var matchingKey *LoadedSshKey
			for _, k := range e.keys {
				if bytes.Equal(k.PublicKey.GetKeyBlob(), signReq.GetKeyBlob()) {
					matchingKey = k
					break
				}
			}
			hostname := pc.GetHostname()
			if hostname == "" {
				hostname = verifiedNodeID
			}
			var keyComment string
			if matchingKey != nil {
				keyComment = matchingKey.PublicKey.GetComment()
			}

			info := SignRequestInfo{
				RequestID:         signReq.GetRequestId(),
				TimestampUnixMs:   signReq.GetTimestampUnixMs(),
				VerifiedNodeID:    verifiedNodeID,
				Hostname:          hostname,
				UID:               pc.GetUid(),
				PID:               pc.GetPid(),
				Comm:              pc.GetComm(),
				Cmdline:           pc.GetCmdline(),
				Cwd:               pc.GetCwd(),
				PrimaryTool:       primaryTool,
				PrimaryCmdline:    primaryCmdline,
				Ancestors:         ancestors,
				IsUserauthRequest: parsedSSH.GetIsUserauthRequest(),
				TargetUsername:    parsedSSH.GetTargetUsername(),
				ServiceName:       parsedSSH.GetServiceName(),
				PubkeyAlgorithm:   parsedSSH.GetPubkeyAlgorithm(),
				KeyFingerprint:    pkInfo.GetFingerprintSha256(),
				KeyComment:        keyComment,
				HasMatchingKey:    matchingKey != nil,
			}

			e.pendingRequests[signReq.GetRequestId()] = signReq
			return map[string]any{
				"ok":            true,
				"frame_type":    "sign_request",
				"ack_frame_b64": ackB64,
				"request":       info,
			}
		default:
			return map[string]any{
				"ok":         true,
				"frame_type": "empty",
			}
		}

	case "decide_sign_request":
		reqID := getString(req, "request_id")
		approved := getBool(req, "approved", false)
		signReq, ok := e.pendingRequests[reqID]
		if !ok {
			return map[string]any{
				"ok":    false,
				"error": fmt.Sprintf("SignRequest %q is no longer pending", reqID),
			}
		}
		delete(e.pendingRequests, reqID)

		var handledBy string
		if e.bundle != nil {
			handledBy = e.bundle.Grant.GetNodeId()
		}

		if !approved {
			respMsg := &sockcastv1.ClientStreamMessage{
				Payload: &sockcastv1.ClientStreamMessage_SignResponse{
					SignResponse: &sockcastv1.SignResponse{
						RequestId:       reqID,
						Approved:        false,
						ErrorMessage:    "Denied by user in browser workstation",
						HandledByNodeId: handledBy,
					},
				},
			}
			raw, _ := proto.Marshal(respMsg)
			return map[string]any{
				"ok":        true,
				"approved":  false,
				"frame_b64": base64.StdEncoding.EncodeToString(raw),
			}
		}

		var matchingKey *LoadedSshKey
		for _, k := range e.keys {
			if bytes.Equal(k.PublicKey.GetKeyBlob(), signReq.GetKeyBlob()) {
				matchingKey = k
				break
			}
		}
		if matchingKey == nil {
			respMsg := &sockcastv1.ClientStreamMessage{
				Payload: &sockcastv1.ClientStreamMessage_SignResponse{
					SignResponse: &sockcastv1.SignResponse{
						RequestId:       reqID,
						Approved:        false,
						ErrorMessage:    "Requested SSH key is not loaded in browser workstation",
						HandledByNodeId: handledBy,
					},
				},
			}
			raw, _ := proto.Marshal(respMsg)
			return map[string]any{
				"ok":        false,
				"error":     "Requested SSH key is not loaded in browser workstation",
				"frame_b64": base64.StdEncoding.EncodeToString(raw),
			}
		}

		sigBlob := matchingKey.SignSSHData(signReq.GetData(), signReq.GetFlags())
		respMsg := &sockcastv1.ClientStreamMessage{
			Payload: &sockcastv1.ClientStreamMessage_SignResponse{
				SignResponse: &sockcastv1.SignResponse{
					RequestId:       reqID,
					Approved:        true,
					SignatureBlob:   sigBlob,
					HandledByNodeId: handledBy,
				},
			},
		}
		raw, _ := proto.Marshal(respMsg)
		return map[string]any{
			"ok":            true,
			"approved":      true,
			"signature_b64": base64.StdEncoding.EncodeToString(sigBlob),
			"frame_b64":     base64.StdEncoding.EncodeToString(raw),
		}

	default:
		return map[string]any{
			"ok":    false,
			"error": fmt.Sprintf("Unknown WASM operation: %q", op),
		}
	}
}
