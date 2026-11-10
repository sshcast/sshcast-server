package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sockcastv1 "github.com/theraphim/sockcast-proto/gen/go/sockcast/v1"
	"github.com/theraphim/sockcast-proto/pkg/auth"
	"github.com/theraphim/sockcast-server/internal/config"
	"github.com/theraphim/sockcast-server/internal/hub"
	"github.com/theraphim/sockcast-server/internal/wasmengine"
	"github.com/theraphim/sockcast-server/internal/web"
	"golang.org/x/net/websocket"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
)

func keypair(seedByte byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := bytes.Repeat([]byte{seedByte}, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(seed)
	return priv.Public().(ed25519.PublicKey), priv
}

func makeSignedGrantAndAuth(t *testing.T, userPriv ed25519.PrivateKey, nodePub ed25519.PublicKey, nodePriv ed25519.PrivateKey, nodeID string, role sockcastv1.NodeRole) (*sockcastv1.NodeGrant, *sockcastv1.NodeAuth) {
	t.Helper()
	grant := &sockcastv1.NodeGrant{
		NodeId:          nodeID,
		Role:            role,
		NodePubkey:      nodePub,
		IssuedAtUnixSec: uint64(time.Now().Unix() - 60),
	}
	if err := auth.SignNodeGrant(grant, userPriv); err != nil {
		t.Fatalf("SignNodeGrant: %v", err)
	}
	nodeAuth := &sockcastv1.NodeAuth{
		Grant:           grant,
		TimestampUnixMs: uint64(time.Now().UnixMilli()),
		Nonce:           []byte{1, 2, 3, 4, 5, 6, 7, 8},
	}
	if err := auth.SignNodeAuth(nodeAuth, nodePriv); err != nil {
		t.Fatalf("SignNodeAuth: %v", err)
	}
	return grant, nodeAuth
}

func TestSignAckFailoverAndIdentities(t *testing.T) {
	userPub, userPriv := keypair(0x10)
	ws1Pub, ws1Priv := keypair(0x21)
	ws2Pub, ws2Priv := keypair(0x22)
	relayPub, relayPriv := keypair(0x31)

	cfg := config.Default()
	cfg.AllowAnyUser = false
	cfg.AllowedUserPubkeys = []string{"sc_pub_" + auth.DeriveUserID(userPub)[5:]} // test compile fallback below
	cfg.AllowedUserPubkeys = nil
	cfg.AllowAnyUser = true
	cfg.SignAckTimeoutMs = 120
	cfg.SignResponseTimeoutMs = 5000

	reg := hub.NewRegistry(cfg.SignAckTimeout(), cfg.SignResponseTimeout())
	srv := New(cfg, reg)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	grpcServer := grpc.NewServer()
	sockcastv1.RegisterSockcastServiceServer(grpcServer, srv)
	go func() {
		_ = grpcServer.Serve(lis)
	}()
	defer grpcServer.Stop()

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer conn.Close()
	client := sockcastv1.NewSockcastServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Connect Workstation 1 (macbook-asleep: higher last_input_epoch_ms, but will NOT send SignAck)
	_, ws1Auth := makeSignedGrantAndAuth(t, userPriv, ws1Pub, ws1Priv, "macbook-asleep", sockcastv1.NodeRole_NODE_ROLE_CLIENT)
	stream1, err := client.ConnectWorkstation(ctx)
	if err != nil {
		t.Fatalf("ConnectWorkstation 1: %v", err)
	}
	if err := stream1.Send(&sockcastv1.ClientStreamMessage{
		Payload: &sockcastv1.ClientStreamMessage_AuthHandshake{AuthHandshake: ws1Auth},
	}); err != nil {
		t.Fatalf("stream1 Send handshake: %v", err)
	}
	// Receive initial server heartbeat
	if _, err := stream1.Recv(); err != nil {
		t.Fatalf("stream1 Recv heartbeat: %v", err)
	}
	if err := stream1.Send(&sockcastv1.ClientStreamMessage{
		Payload: &sockcastv1.ClientStreamMessage_Status{
			Status: &sockcastv1.WorkstationStatus{
				LastInputEpochMs: 2000,
				Os:               "macos",
				Keys: []*sockcastv1.PublicKey{
					{KeyBlob: []byte("key-1"), Comment: "pavel@mac", KeyType: "ssh-ed25519"},
				},
			},
		},
	}); err != nil {
		t.Fatalf("stream1 Send status: %v", err)
	}

	// Connect Workstation 2 (win-desktop: lower last_input_epoch_ms=1000, WILL send SignAck and SignResponse)
	_, ws2Auth := makeSignedGrantAndAuth(t, userPriv, ws2Pub, ws2Priv, "win-desktop", sockcastv1.NodeRole_NODE_ROLE_CLIENT)
	stream2, err := client.ConnectWorkstation(ctx)
	if err != nil {
		t.Fatalf("ConnectWorkstation 2: %v", err)
	}
	if err := stream2.Send(&sockcastv1.ClientStreamMessage{
		Payload: &sockcastv1.ClientStreamMessage_AuthHandshake{AuthHandshake: ws2Auth},
	}); err != nil {
		t.Fatalf("stream2 Send handshake: %v", err)
	}
	if _, err := stream2.Recv(); err != nil {
		t.Fatalf("stream2 Recv heartbeat: %v", err)
	}
	if err := stream2.Send(&sockcastv1.ClientStreamMessage{
		Payload: &sockcastv1.ClientStreamMessage_Status{
			Status: &sockcastv1.WorkstationStatus{
				LastInputEpochMs: 1000,
				Os:               "windows",
			},
		},
	}); err != nil {
		t.Fatalf("stream2 Send status: %v", err)
	}

	// Give server a moment to process status frames
	time.Sleep(30 * time.Millisecond)

	// Relay fetches identities
	relayGrant, relayAuth := makeSignedGrantAndAuth(t, userPriv, relayPub, relayPriv, "server-x.local", sockcastv1.NodeRole_NODE_ROLE_RELAY)
	idResp, err := client.GetIdentities(ctx, &sockcastv1.GetIdentitiesRequest{Auth: relayAuth})
	if err != nil {
		t.Fatalf("GetIdentities: %v", err)
	}
	if len(idResp.GetKeys()) != 1 || idResp.GetKeys()[0].GetComment() != "pavel@mac" {
		t.Fatalf("unexpected keys: %+v", idResp.GetKeys())
	}

	// Workstation 2 background loop: immediately SignAck, then SignResponse
	go func() {
		for {
			msg, err := stream2.Recv()
			if err != nil {
				return
			}
			if sr := msg.GetSignRequest(); sr != nil {
				_ = stream2.Send(&sockcastv1.ClientStreamMessage{
					Payload: &sockcastv1.ClientStreamMessage_SignAck{
						SignAck: &sockcastv1.SignAck{RequestId: sr.GetRequestId()},
					},
				})
				time.Sleep(40 * time.Millisecond)
				_ = stream2.Send(&sockcastv1.ClientStreamMessage{
					Payload: &sockcastv1.ClientStreamMessage_SignResponse{
						SignResponse: &sockcastv1.SignResponse{
							RequestId:     sr.GetRequestId(),
							Approved:      true,
							SignatureBlob: []byte("valid-ssh-signature"),
						},
					},
				})
				return
			}
		}
	}()

	// Relay sends SignRequest
	signReq := &sockcastv1.SignRequest{
		RequestId:       "req-failover-1",
		TimestampUnixMs: uint64(time.Now().UnixMilli()),
		KeyBlob:         []byte("key-1"),
		Data:            []byte("challenge"),
		ProcessContext: &sockcastv1.ProcessContext{
			Hostname: "server-x.local",
			Uid:      1000,
			Pid:      1234,
			Comm:     "ssh",
		},
		RelayGrant: relayGrant,
		Auth:       relayAuth,
	}
	if err := auth.SignSignRequest(signReq, relayPriv); err != nil {
		t.Fatalf("SignSignRequest: %v", err)
	}

	signResp, err := client.Sign(ctx, signReq)
	if err != nil {
		t.Fatalf("Sign RPC error: %v", err)
	}
	if !signResp.GetApproved() || string(signResp.GetSignatureBlob()) != "valid-ssh-signature" {
		t.Fatalf("unexpected SignResponse: %+v", signResp)
	}
	if signResp.GetHandledByNodeId() != "win-desktop" {
		t.Fatalf("expected HandledByNodeId='win-desktop', got %q", signResp.GetHandledByNodeId())
	}

	// Verify Workstation 1 received the initial SignRequest AND then a CancelSignRequest after Workstation 2 handled it!
	msg1, err := stream1.Recv()
	if err != nil || msg1.GetSignRequest() == nil {
		t.Fatalf("expected stream1 to receive SignRequest first, got %+v, err=%v", msg1, err)
	}
	msg2, err := stream1.Recv()
	if err != nil || msg2.GetCancelSignRequest() == nil {
		t.Fatalf("expected stream1 to receive CancelSignRequest after failover win, got %+v, err=%v", msg2, err)
	}
	if msg2.GetCancelSignRequest().GetRequestId() != "req-failover-1" {
		t.Fatalf("unexpected CancelSignRequest ID: %s", msg2.GetCancelSignRequest().GetRequestId())
	}
	_ = userPub
}

func TestZellijHostDiscoveryAndTunnelRouting(t *testing.T) {
	_, userPriv := keypair(0x40)
	wsPub, wsPriv := keypair(0x41)
	relayPub, relayPriv := keypair(0x42)

	cfg := config.Default()
	cfg.AllowAnyUser = true
	reg := hub.NewRegistry(cfg.SignAckTimeout(), cfg.SignResponseTimeout())
	srv := New(cfg, reg)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	grpcServer := grpc.NewServer()
	sockcastv1.RegisterSockcastServiceServer(grpcServer, srv)
	go func() {
		_ = grpcServer.Serve(lis)
	}()
	defer grpcServer.Stop()

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer conn.Close()
	client := sockcastv1.NewSockcastServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. Connect Workstation
	_, wsAuth := makeSignedGrantAndAuth(t, userPriv, wsPub, wsPriv, "workstation-1", sockcastv1.NodeRole_NODE_ROLE_CLIENT)
	wsStream, err := client.ConnectWorkstation(ctx)
	if err != nil {
		t.Fatalf("ConnectWorkstation: %v", err)
	}
	if err := wsStream.Send(&sockcastv1.ClientStreamMessage{
		Payload: &sockcastv1.ClientStreamMessage_AuthHandshake{AuthHandshake: wsAuth},
	}); err != nil {
		t.Fatalf("wsStream Send handshake: %v", err)
	}
	if _, err := wsStream.Recv(); err != nil {
		t.Fatalf("wsStream Recv heartbeat: %v", err)
	}

	// 2. Connect Relay with Zellij enabled
	_, relayAuth := makeSignedGrantAndAuth(t, userPriv, relayPub, relayPriv, "sunduk.infra.local", sockcastv1.NodeRole_NODE_ROLE_RELAY)
	relayStream, err := client.ConnectRelay(ctx)
	if err != nil {
		t.Fatalf("ConnectRelay: %v", err)
	}
	if err := relayStream.Send(&sockcastv1.RelayStreamMessage{
		Payload: &sockcastv1.RelayStreamMessage_AuthHandshake{AuthHandshake: relayAuth},
	}); err != nil {
		t.Fatalf("relayStream Send handshake: %v", err)
	}
	if _, err := relayStream.Recv(); err != nil {
		t.Fatalf("relayStream Recv heartbeat: %v", err)
	}

	// 3. Relay publishes ZellijStatus -> Workstation automatically receives ZellijHostList
	if err := relayStream.Send(&sockcastv1.RelayStreamMessage{
		Payload: &sockcastv1.RelayStreamMessage_ZellijStatus{
			ZellijStatus: &sockcastv1.RelayZellijStatus{
				NodeId:        "sunduk.infra.local",
				ZellijEnabled: true,
				Sessions: []*sockcastv1.ZellijSessionInfo{
					{Name: "dev", CreatedInfo: "10m ago", Exited: false},
				},
			},
		},
	}); err != nil {
		t.Fatalf("relayStream Send ZellijStatus: %v", err)
	}

	wsMsg, err := wsStream.Recv()
	if err != nil || wsMsg.GetZellijHostList() == nil {
		t.Fatalf("expected ZellijHostList on wsStream, got %+v, err=%v", wsMsg, err)
	}
	hosts := wsMsg.GetZellijHostList().GetHosts()
	if len(hosts) != 1 || hosts[0].GetNodeId() != "sunduk.infra.local" || len(hosts[0].GetSessions()) != 1 {
		t.Fatalf("unexpected ZellijHostList: %+v", hosts)
	}

	// 4. Workstation routes a ZellijTunnelFrame using short hostname "sunduk" -> Relay receives it
	if err := wsStream.Send(&sockcastv1.ClientStreamMessage{
		Payload: &sockcastv1.ClientStreamMessage_ZellijFrame{
			ZellijFrame: &sockcastv1.ZellijTunnelFrame{
				TunnelId:    "stream-1",
				RelayNodeId: "sunduk",
				FrameType:   sockcastv1.ZellijFrameType_ZELLIJ_FRAME_TYPE_OPEN,
				Payload:     []byte("GET /dev HTTP/1.1\r\n\r\n"),
			},
		},
	}); err != nil {
		t.Fatalf("wsStream Send ZellijFrame: %v", err)
	}

	relayMsg, err := relayStream.Recv()
	if err != nil || relayMsg.GetZellijFrame() == nil {
		t.Fatalf("expected ZellijFrame on relayStream, got %+v, err=%v", relayMsg, err)
	}
	if relayMsg.GetZellijFrame().GetClientNodeId() != "workstation-1" || string(relayMsg.GetZellijFrame().GetPayload()) != "GET /dev HTTP/1.1\r\n\r\n" {
		t.Fatalf("unexpected relay ZellijFrame: %+v", relayMsg.GetZellijFrame())
	}

	// 5. Relay replies with DATA frame -> Workstation receives it
	if err := relayStream.Send(&sockcastv1.RelayStreamMessage{
		Payload: &sockcastv1.RelayStreamMessage_ZellijFrame{
			ZellijFrame: &sockcastv1.ZellijTunnelFrame{
				TunnelId:     "stream-1",
				ClientNodeId: "workstation-1",
				FrameType:    sockcastv1.ZellijFrameType_ZELLIJ_FRAME_TYPE_DATA,
				Payload:      []byte("HTTP/1.1 200 OK\r\n\r\n"),
			},
		},
	}); err != nil {
		t.Fatalf("relayStream Send reply ZellijFrame: %v", err)
	}

	wsReply, err := wsStream.Recv()
	if err != nil || wsReply.GetZellijFrame() == nil {
		t.Fatalf("expected reply ZellijFrame on wsStream, got %+v, err=%v", wsReply, err)
	}
	if string(wsReply.GetZellijFrame().GetPayload()) != "HTTP/1.1 200 OK\r\n\r\n" {
		t.Fatalf("unexpected wsReply data: %q", string(wsReply.GetZellijFrame().GetPayload()))
	}
}

func TestBrowserWasmWebSocketWorkstationAndWebHandler(t *testing.T) {
	_, userPriv := keypair(0x60)
	wsPub, wsPriv := keypair(0x61)
	relayPub, relayPriv := keypair(0x62)

	cfg := config.Default()
	cfg.AllowAnyUser = true
	reg := hub.NewRegistry(cfg.SignAckTimeout(), cfg.SignResponseTimeout())
	srv := New(cfg, reg)

	// Start gRPC server for relay
	grpcLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen gRPC: %v", err)
	}
	grpcServer := grpc.NewServer()
	sockcastv1.RegisterSockcastServiceServer(grpcServer, srv)
	go func() {
		_ = grpcServer.Serve(grpcLis)
	}()
	defer grpcServer.Stop()

	// Start HTTP server with /ws/workstation and /web/
	mux := http.NewServeMux()
	mux.Handle("/ws/workstation", srv.WorkstationWebSocketHandler())
	mux.Handle("/web/", web.Handler(""))
	httpSrv := httptest.NewServer(mux)
	defer httpSrv.Close()

	// 1. Verify /web/ serves index.html, app.js, and sockcast_wasm.wasm
	respIndex, err := http.Get(httpSrv.URL + "/web/")
	if err != nil || respIndex.StatusCode != http.StatusOK {
		t.Fatalf("GET /web/ failed: status=%v err=%v", respIndex, err)
	}
	_ = respIndex.Body.Close()

	respWasm, err := http.Get(httpSrv.URL + "/web/sockcast_wasm.wasm")
	if err != nil || respWasm.StatusCode != http.StatusOK {
		t.Fatalf("GET /web/sockcast_wasm.wasm failed: status=%v err=%v", respWasm, err)
	}
	if ct := respWasm.Header.Get("Content-Type"); ct != "application/wasm" {
		t.Fatalf("expected Content-Type application/wasm, got %q", ct)
	}
	_ = respWasm.Body.Close()

	// 2. Build an sc1_ client enrollment bundle and load an encrypted ssh-keygen key into wasmengine
	wsGrant, _ := makeSignedGrantAndAuth(t, userPriv, wsPub, wsPriv, "chrome-wasm-node", sockcastv1.NodeRole_NODE_ROLE_CLIENT)
	grantBytes, err := proto.Marshal(wsGrant)
	if err != nil {
		t.Fatalf("proto.Marshal grant: %v", err)
	}
	wireJSON, err := json.Marshal(map[string]any{
		"servers":               []string{httpSrv.URL},
		"node_privkey_seed_b64": base64.RawURLEncoding.EncodeToString(wsPriv.Seed()),
		"grant_proto_b64":       base64.RawURLEncoding.EncodeToString(grantBytes),
	})
	if err != nil {
		t.Fatalf("json.Marshal bundle wire: %v", err)
	}
	bundleToken := "sc1_" + base64.RawURLEncoding.EncodeToString(wireJSON) + ".rk_" + base64.RawURLEncoding.EncodeToString(userPriv.Seed())

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "id_ed25519_wasm")
	cmd := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-a", "4", "-Z", "aes256-ctr", "-N", "wasm-pass-123", "-C", "browser@chrome", "-f", keyPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen failed: %v: %s", err, string(out))
	}
	pemBytes, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("ReadFile keyPath: %v", err)
	}

	eng := wasmengine.NewEngine()
	callWasm := func(req map[string]any) map[string]any {
		t.Helper()
		b, _ := json.Marshal(req)
		outStr := eng.CallJSON(string(b))
		var resp map[string]any
		if err := json.Unmarshal([]byte(outStr), &resp); err != nil {
			t.Fatalf("Unmarshal wasm response: %v (%s)", err, outStr)
		}
		return resp
	}

	rBundle := callWasm(map[string]any{
		"op":           "set_bundle",
		"bundle_str":   bundleToken,
		"now_unix_sec": time.Now().Unix(),
	})
	if rBundle["ok"] != true {
		t.Fatalf("set_bundle failed: %+v", rBundle)
	}

	rKey := callWasm(map[string]any{
		"op":         "add_ssh_key",
		"pem":        string(pemBytes),
		"passphrase": "wasm-pass-123",
	})
	if rKey["ok"] != true {
		t.Fatalf("add_ssh_key failed: %+v", rKey)
	}

	// Also verify RSA keys (both OpenSSH format and classic BEGIN RSA PRIVATE KEY PEM format)
	rsaOpenSSHPath := filepath.Join(tmpDir, "id_rsa_openssh")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "rsa", "-b", "2048", "-N", "", "-C", "rsa@chrome", "-f", rsaOpenSSHPath).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen rsa openssh failed: %v: %s", err, string(out))
	}
	rsaOpenSSHPem, _ := os.ReadFile(rsaOpenSSHPath)
	if r := callWasm(map[string]any{"op": "add_ssh_key", "pem": string(rsaOpenSSHPem)}); r["ok"] != true {
		t.Fatalf("add_ssh_key (rsa openssh) failed: %+v", r)
	}

	rsaPEMPath := filepath.Join(tmpDir, "id_rsa_pem")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "rsa", "-b", "2048", "-m", "PEM", "-N", "", "-f", rsaPEMPath).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen rsa pem failed: %v: %s", err, string(out))
	}
	rsaPEMBytes, _ := os.ReadFile(rsaPEMPath)
	if r := callWasm(map[string]any{"op": "add_ssh_key", "pem": string(rsaPEMBytes)}); r["ok"] != true {
		t.Fatalf("add_ssh_key (rsa classic PEM) failed: %+v", r)
	}

	// 3. Connect Browser WASM Workstation over WebSocket (/ws/workstation)
	wsURL := "ws://" + strings.TrimPrefix(httpSrv.URL, "http://") + "/ws/workstation"
	wsConn, err := websocket.Dial(wsURL, "", httpSrv.URL)
	if err != nil {
		t.Fatalf("websocket.Dial: %v", err)
	}
	defer wsConn.Close()

	sendFrameB64 := func(b64 string) {
		t.Helper()
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			t.Fatalf("DecodeString frame_b64: %v", err)
		}
		if err := websocket.Message.Send(wsConn, raw); err != nil {
			t.Fatalf("websocket.Message.Send: %v", err)
		}
	}

	rHS := callWasm(map[string]any{
		"op":          "build_auth_handshake_frame",
		"now_unix_ms": time.Now().UnixMilli(),
	})
	sendFrameB64(rHS["frame_b64"].(string))

	rStatus := callWasm(map[string]any{
		"op":                  "build_status_frame",
		"last_input_epoch_ms": time.Now().UnixMilli(),
		"force_active":        true,
	})
	sendFrameB64(rStatus["frame_b64"].(string))

	// Background browser WebSocket receive loop (auto-approving SignRequest via wasmengine)
	go func() {
		for {
			var raw []byte
			if err := websocket.Message.Receive(wsConn, &raw); err != nil {
				return
			}
			decoded := callWasm(map[string]any{
				"op":           "decode_server_frame",
				"frame_b64":    base64.StdEncoding.EncodeToString(raw),
				"now_unix_sec": time.Now().Unix(),
			})
			if decoded["frame_type"] == "sign_request" {
				sendFrameB64(decoded["ack_frame_b64"].(string))
				reqInfo := decoded["request"].(map[string]any)
				reqID := reqInfo["request_id"].(string)
				dec := callWasm(map[string]any{
					"op":         "decide_sign_request",
					"request_id": reqID,
					"approved":   true,
				})
				sendFrameB64(dec["frame_b64"].(string))
				return
			}
		}
	}()

	time.Sleep(40 * time.Millisecond)

	// 4. Connect Relay via gRPC, call GetIdentities and Sign
	grpcConn, err := grpc.NewClient(grpcLis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	defer grpcConn.Close()
	relayClient := sockcastv1.NewSockcastServiceClient(grpcConn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	relayGrant, relayAuth := makeSignedGrantAndAuth(t, userPriv, relayPub, relayPriv, "bastion.infra.local", sockcastv1.NodeRole_NODE_ROLE_RELAY)
	idResp, err := relayClient.GetIdentities(ctx, &sockcastv1.GetIdentitiesRequest{Auth: relayAuth})
	if err != nil {
		t.Fatalf("GetIdentities: %v", err)
	}
	if len(idResp.GetKeys()) != 3 || idResp.GetKeys()[0].GetComment() != "browser@chrome" || idResp.GetKeys()[1].GetKeyType() != "ssh-rsa" {
		t.Fatalf("expected 3 keys (ed25519 + 2 rsa) from WASM workstation, got %+v", idResp.GetKeys())
	}

	signReq := &sockcastv1.SignRequest{
		RequestId:       "req-browser-ws-1",
		TimestampUnixMs: uint64(time.Now().UnixMilli()),
		KeyBlob:         idResp.GetKeys()[0].GetKeyBlob(),
		Data:            []byte("ssh-userauth-challenge-data"),
		ProcessContext: &sockcastv1.ProcessContext{
			Hostname: "bastion.infra.local",
			Uid:      1000,
			Pid:      4321,
			Comm:     "ssh",
			Cmdline:  "ssh prod",
		},
		RelayGrant: relayGrant,
		Auth:       relayAuth,
	}
	if err := auth.SignSignRequest(signReq, relayPriv); err != nil {
		t.Fatalf("SignSignRequest: %v", err)
	}

	signResp, err := relayClient.Sign(ctx, signReq)
	if err != nil {
		t.Fatalf("Sign RPC failed: %v", err)
	}
	if !signResp.GetApproved() || signResp.GetHandledByNodeId() != "chrome-wasm-node" {
		t.Fatalf("unexpected SignResponse: %+v", signResp)
	}
	if len(signResp.GetSignatureBlob()) < 64 {
		t.Fatalf("expected valid SSH signature blob, got %d bytes", len(signResp.GetSignatureBlob()))
	}
}
