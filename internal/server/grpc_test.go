package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sshcastv1 "stingr.net/go/sshcast-proto/gen/go/sshcast/v1"
	"stingr.net/go/sshcast-proto/pkg/auth"
	"stingr.net/go/sshcast-server/internal/config"
	"stingr.net/go/sshcast-server/internal/hub"
	"stingr.net/go/sshcast-server/internal/web"
	"golang.org/x/net/websocket"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func keypair(seedByte byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := bytes.Repeat([]byte{seedByte}, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(seed)
	return priv.Public().(ed25519.PublicKey), priv
}

func makeSignedGrantAndAuth(t *testing.T, userPriv ed25519.PrivateKey, nodePub ed25519.PublicKey, nodePriv ed25519.PrivateKey, nodeID string, role sshcastv1.NodeRole) (*sshcastv1.NodeGrant, *sshcastv1.NodeAuth) {
	t.Helper()
	grant := &sshcastv1.NodeGrant{
		NodeId:          nodeID,
		Role:            role,
		NodePubkey:      nodePub,
		IssuedAtUnixSec: uint64(time.Now().Unix() - 60),
	}
	if err := auth.SignNodeGrant(grant, userPriv); err != nil {
		t.Fatalf("SignNodeGrant: %v", err)
	}
	nodeAuth := &sshcastv1.NodeAuth{
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
	sshcastv1.RegisterSshcastServiceServer(grpcServer, srv)
	go func() {
		_ = grpcServer.Serve(lis)
	}()
	defer grpcServer.Stop()

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer conn.Close()
	client := sshcastv1.NewSshcastServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Connect Workstation 1 (macbook-asleep: higher last_input_epoch_ms, but will NOT send SignAck)
	_, ws1Auth := makeSignedGrantAndAuth(t, userPriv, ws1Pub, ws1Priv, "macbook-asleep", sshcastv1.NodeRole_NODE_ROLE_CLIENT)
	stream1, err := client.ConnectWorkstation(ctx)
	if err != nil {
		t.Fatalf("ConnectWorkstation 1: %v", err)
	}
	if err := stream1.Send(&sshcastv1.ClientStreamMessage{
		Payload: &sshcastv1.ClientStreamMessage_AuthHandshake{AuthHandshake: ws1Auth},
	}); err != nil {
		t.Fatalf("stream1 Send handshake: %v", err)
	}
	// Receive initial server heartbeat
	if _, err := stream1.Recv(); err != nil {
		t.Fatalf("stream1 Recv heartbeat: %v", err)
	}
	if err := stream1.Send(&sshcastv1.ClientStreamMessage{
		Payload: &sshcastv1.ClientStreamMessage_Status{
			Status: &sshcastv1.WorkstationStatus{
				LastInputEpochMs: 2000,
				Os:               "macos",
				Keys: []*sshcastv1.PublicKey{
					{KeyBlob: []byte("key-1"), Comment: "pavel@mac", KeyType: "ssh-ed25519"},
				},
			},
		},
	}); err != nil {
		t.Fatalf("stream1 Send status: %v", err)
	}

	// Connect Workstation 2 (win-desktop: lower last_input_epoch_ms=1000, WILL send SignAck and SignResponse)
	_, ws2Auth := makeSignedGrantAndAuth(t, userPriv, ws2Pub, ws2Priv, "win-desktop", sshcastv1.NodeRole_NODE_ROLE_CLIENT)
	stream2, err := client.ConnectWorkstation(ctx)
	if err != nil {
		t.Fatalf("ConnectWorkstation 2: %v", err)
	}
	if err := stream2.Send(&sshcastv1.ClientStreamMessage{
		Payload: &sshcastv1.ClientStreamMessage_AuthHandshake{AuthHandshake: ws2Auth},
	}); err != nil {
		t.Fatalf("stream2 Send handshake: %v", err)
	}
	if _, err := stream2.Recv(); err != nil {
		t.Fatalf("stream2 Recv heartbeat: %v", err)
	}
	if err := stream2.Send(&sshcastv1.ClientStreamMessage{
		Payload: &sshcastv1.ClientStreamMessage_Status{
			Status: &sshcastv1.WorkstationStatus{
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
	relayGrant, relayAuth := makeSignedGrantAndAuth(t, userPriv, relayPub, relayPriv, "server-x.local", sshcastv1.NodeRole_NODE_ROLE_RELAY)
	idResp, err := client.GetIdentities(ctx, &sshcastv1.GetIdentitiesRequest{Auth: relayAuth})
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
				_ = stream2.Send(&sshcastv1.ClientStreamMessage{
					Payload: &sshcastv1.ClientStreamMessage_SignAck{
						SignAck: &sshcastv1.SignAck{RequestId: sr.GetRequestId()},
					},
				})
				time.Sleep(40 * time.Millisecond)
				_ = stream2.Send(&sshcastv1.ClientStreamMessage{
					Payload: &sshcastv1.ClientStreamMessage_SignResponse{
						SignResponse: &sshcastv1.SignResponse{
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
	signReq := &sshcastv1.SignRequest{
		RequestId:       "req-failover-1",
		TimestampUnixMs: uint64(time.Now().UnixMilli()),
		KeyBlob:         []byte("key-1"),
		Data:            []byte("challenge"),
		ProcessContext: &sshcastv1.ProcessContext{
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
	sshcastv1.RegisterSshcastServiceServer(grpcServer, srv)
	go func() {
		_ = grpcServer.Serve(lis)
	}()
	defer grpcServer.Stop()

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer conn.Close()
	client := sshcastv1.NewSshcastServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. Connect Workstation
	_, wsAuth := makeSignedGrantAndAuth(t, userPriv, wsPub, wsPriv, "workstation-1", sshcastv1.NodeRole_NODE_ROLE_CLIENT)
	wsStream, err := client.ConnectWorkstation(ctx)
	if err != nil {
		t.Fatalf("ConnectWorkstation: %v", err)
	}
	if err := wsStream.Send(&sshcastv1.ClientStreamMessage{
		Payload: &sshcastv1.ClientStreamMessage_AuthHandshake{AuthHandshake: wsAuth},
	}); err != nil {
		t.Fatalf("wsStream Send handshake: %v", err)
	}
	if _, err := wsStream.Recv(); err != nil {
		t.Fatalf("wsStream Recv heartbeat: %v", err)
	}

	// 2. Connect Relay with Zellij enabled
	_, relayAuth := makeSignedGrantAndAuth(t, userPriv, relayPub, relayPriv, "sunduk.infra.local", sshcastv1.NodeRole_NODE_ROLE_RELAY)
	relayStream, err := client.ConnectRelay(ctx)
	if err != nil {
		t.Fatalf("ConnectRelay: %v", err)
	}
	if err := relayStream.Send(&sshcastv1.RelayStreamMessage{
		Payload: &sshcastv1.RelayStreamMessage_AuthHandshake{AuthHandshake: relayAuth},
	}); err != nil {
		t.Fatalf("relayStream Send handshake: %v", err)
	}
	if _, err := relayStream.Recv(); err != nil {
		t.Fatalf("relayStream Recv heartbeat: %v", err)
	}

	// 3. Relay publishes ZellijStatus -> Workstation automatically receives ZellijHostList
	if err := relayStream.Send(&sshcastv1.RelayStreamMessage{
		Payload: &sshcastv1.RelayStreamMessage_ZellijStatus{
			ZellijStatus: &sshcastv1.RelayZellijStatus{
				NodeId:        "sunduk.infra.local",
				ZellijEnabled: true,
				Sessions: []*sshcastv1.ZellijSessionInfo{
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
	if err := wsStream.Send(&sshcastv1.ClientStreamMessage{
		Payload: &sshcastv1.ClientStreamMessage_ZellijFrame{
			ZellijFrame: &sshcastv1.ZellijTunnelFrame{
				TunnelId:    "stream-1",
				RelayNodeId: "sunduk",
				FrameType:   sshcastv1.ZellijFrameType_ZELLIJ_FRAME_TYPE_OPEN,
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
	if err := relayStream.Send(&sshcastv1.RelayStreamMessage{
		Payload: &sshcastv1.RelayStreamMessage_ZellijFrame{
			ZellijFrame: &sshcastv1.ZellijTunnelFrame{
				TunnelId:     "stream-1",
				ClientNodeId: "workstation-1",
				FrameType:    sshcastv1.ZellijFrameType_ZELLIJ_FRAME_TYPE_DATA,
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
	sshcastv1.RegisterSshcastServiceServer(grpcServer, srv)
	go func() {
		_ = grpcServer.Serve(grpcLis)
	}()
	defer grpcServer.Stop()

	// Start HTTP server with /ws/workstation and /web/
	mux := http.NewServeMux()
	mux.Handle("/ws/workstation", srv.WorkstationWebSocketHandler())
	mux.HandleFunc("GET /web/coordinators", web.HandleCoordinators)
	mux.HandleFunc("GET /web/", web.HandleAssets(""))
	httpSrv := httptest.NewServer(mux)
	defer httpSrv.Close()

	// 1. Verify /web/ serves index.html, app.js, and the Rust sshcast-client sshcast_wasm.wasm binary
	respIndex, err := http.Get(httpSrv.URL + "/web/")
	if err != nil || respIndex.StatusCode != http.StatusOK {
		t.Fatalf("GET /web/ failed: status=%v err=%v", respIndex, err)
	}
	_ = respIndex.Body.Close()

	respWasm, err := http.Get(httpSrv.URL + "/web/sshcast_wasm.wasm")
	if err != nil || respWasm.StatusCode != http.StatusOK {
		t.Fatalf("GET /web/sshcast_wasm.wasm failed: status=%v err=%v", respWasm, err)
	}
	if ct := respWasm.Header.Get("Content-Type"); ct != "application/wasm" {
		t.Fatalf("expected Content-Type application/wasm, got %q", ct)
	}
	wasmBytes, err := io.ReadAll(respWasm.Body)
	_ = respWasm.Body.Close()
	if err != nil || len(wasmBytes) < 8 || !bytes.Equal(wasmBytes[:4], []byte{0x00, 0x61, 0x73, 0x6d}) {
		t.Fatalf("expected valid WebAssembly binary magic header, got len=%d err=%v", len(wasmBytes), err)
	}
	if !bytes.Contains(wasmBytes, []byte("sshcast_wasm_call")) {
		t.Fatalf("expected sshcast_wasm.wasm to export sshcast_wasm_call from sshcast-client")
	}

	// 2. Connect Browser WASM Workstation over WebSocket (/ws/workstation)
	_, wsAuth := makeSignedGrantAndAuth(t, userPriv, wsPub, wsPriv, "chrome-wasm-node", sshcastv1.NodeRole_NODE_ROLE_CLIENT)

	wsURL := "ws://" + strings.TrimPrefix(httpSrv.URL, "http://") + "/ws/workstation"
	wsConn, err := websocket.Dial(wsURL, "", httpSrv.URL)
	if err != nil {
		t.Fatalf("websocket.Dial: %v", err)
	}
	defer wsConn.Close()

	sendClientFrame := func(msg *sshcastv1.ClientStreamMessage) {
		t.Helper()
		raw, err := proto.Marshal(msg)
		if err != nil {
			t.Fatalf("proto.Marshal ClientStreamMessage: %v", err)
		}
		if err := websocket.Message.Send(wsConn, raw); err != nil {
			t.Fatalf("websocket.Message.Send: %v", err)
		}
	}

	sendClientFrame(&sshcastv1.ClientStreamMessage{
		Payload: &sshcastv1.ClientStreamMessage_AuthHandshake{
			AuthHandshake: wsAuth,
		},
	})

	testKeyBlob := []byte("ssh-ed25519-test-key-blob-for-ws")
	sendClientFrame(&sshcastv1.ClientStreamMessage{
		Payload: &sshcastv1.ClientStreamMessage_Status{
			Status: &sshcastv1.WorkstationStatus{
				LastInputEpochMs: uint64(time.Now().UnixMilli()),
				ForceActive:      true,
				Os:               "browser-wasm",
				Keys: []*sshcastv1.PublicKey{
					{
						KeyBlob:           testKeyBlob,
						KeyType:           "ssh-ed25519",
						FingerprintSha256: "SHA256:test-ws-fp",
						Comment:           "browser@chrome",
					},
				},
			},
		},
	})

	// Background browser WebSocket receive loop
	go func() {
		for {
			var raw []byte
			if err := websocket.Message.Receive(wsConn, &raw); err != nil {
				return
			}
			var srvMsg sshcastv1.ServerStreamMessage
			if err := proto.Unmarshal(raw, &srvMsg); err != nil {
				return
			}
			if sr := srvMsg.GetSignRequest(); sr != nil {
				sendClientFrame(&sshcastv1.ClientStreamMessage{
					Payload: &sshcastv1.ClientStreamMessage_SignAck{
						SignAck: &sshcastv1.SignAck{RequestId: sr.GetRequestId()},
					},
				})
				sendClientFrame(&sshcastv1.ClientStreamMessage{
					Payload: &sshcastv1.ClientStreamMessage_SignResponse{
						SignResponse: &sshcastv1.SignResponse{
							RequestId:       sr.GetRequestId(),
							Approved:        true,
							SignatureBlob:   bytes.Repeat([]byte{0xab}, 64),
							HandledByNodeId: "chrome-wasm-node",
						},
					},
				})
				return
			}
		}
	}()

	time.Sleep(40 * time.Millisecond)

	// 3. Connect Relay via gRPC, call GetIdentities and Sign
	grpcConn, err := grpc.NewClient(grpcLis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	defer grpcConn.Close()
	relayClient := sshcastv1.NewSshcastServiceClient(grpcConn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	relayGrant, relayAuth := makeSignedGrantAndAuth(t, userPriv, relayPub, relayPriv, "bastion.infra.local", sshcastv1.NodeRole_NODE_ROLE_RELAY)
	idResp, err := relayClient.GetIdentities(ctx, &sshcastv1.GetIdentitiesRequest{Auth: relayAuth})
	if err != nil {
		t.Fatalf("GetIdentities: %v", err)
	}
	if len(idResp.GetKeys()) != 1 || idResp.GetKeys()[0].GetComment() != "browser@chrome" {
		t.Fatalf("expected 1 key from WASM workstation, got %+v", idResp.GetKeys())
	}

	signReq := &sshcastv1.SignRequest{
		RequestId:       "req-browser-ws-1",
		TimestampUnixMs: uint64(time.Now().UnixMilli()),
		KeyBlob:         idResp.GetKeys()[0].GetKeyBlob(),
		Data:            []byte("ssh-userauth-challenge-data"),
		ProcessContext: &sshcastv1.ProcessContext{
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

func TestOperatorSignedUserCertAuthorization(t *testing.T) {
	opPub, opPriv := keypair(0x91)
	userPub, userPriv := keypair(0x92)
	relayPub, relayPriv := keypair(0x93)

	cfg := config.Default()
	cfg.TrustedOperatorPubkeys = []string{"sc_op_pub_" + hex.EncodeToString(opPub)}
	if err := cfg.CompileAllowedKeys(); err != nil {
		t.Fatalf("CompileAllowedKeys: %v", err)
	}

	registry := hub.NewRegistry(cfg.SignAckTimeout(), cfg.SignResponseTimeout())
	srv := New(cfg, registry)

	grpcSrv := grpc.NewServer()
	sshcastv1.RegisterSshcastServiceServer(grpcSrv, srv)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer grpcSrv.Stop()
	go func() { _ = grpcSrv.Serve(ln) }()

	conn, err := grpc.NewClient(ln.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	client := sshcastv1.NewSshcastServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Without UserCert, user not in allowed_user_pubkeys is rejected with PermissionDenied
	_, uncertAuth := makeSignedGrantAndAuth(t, userPriv, relayPub, relayPriv, "relay-1", sshcastv1.NodeRole_NODE_ROLE_RELAY)
	if _, err := client.GetIdentities(ctx, &sshcastv1.GetIdentitiesRequest{Auth: uncertAuth}); err == nil {
		t.Fatalf("expected uncertified user to be rejected")
	}

	// 2. With UserCert signed by trusted operator, user is authorized without being in allowed_user_pubkeys
	nowSec := uint64(time.Now().Unix())
	cert := &sshcastv1.UserCert{
		UserId:           "alice",
		UserPubkey:       userPub,
		IssuedAtUnixSec:  nowSec - 60,
		ExpiresAtUnixSec: nowSec + 86400,
	}
	if err := auth.SignUserCert(cert, opPriv); err != nil {
		t.Fatalf("SignUserCert: %v", err)
	}
	certGrant, _ := makeSignedGrantAndAuth(t, userPriv, relayPub, relayPriv, "relay-1", sshcastv1.NodeRole_NODE_ROLE_RELAY)
	certGrant.UserCert = cert
	certAuth := &sshcastv1.NodeAuth{
		Grant:           certGrant,
		TimestampUnixMs: uint64(time.Now().UnixMilli()),
		Nonce:           []byte{1, 2, 3, 4, 5, 6, 7, 8},
	}
	if err := auth.SignNodeAuth(certAuth, relayPriv); err != nil {
		t.Fatalf("SignNodeAuth: %v", err)
	}
	if _, err := client.GetIdentities(ctx, &sshcastv1.GetIdentitiesRequest{Auth: certAuth}); err != nil {
		t.Fatalf("expected operator-certified user to be authorized, got: %v", err)
	}
}

func TestCoordinatorSafetyLimitsGRPCAndWS(t *testing.T) {
	_, userPriv := keypair(0xa1)
	ws1Pub, ws1Priv := keypair(0xa2)
	ws2Pub, ws2Priv := keypair(0xa3)
	ws3Pub, ws3Priv := keypair(0xa4)
	r1Pub, r1Priv := keypair(0xa5)
	r2Pub, r2Priv := keypair(0xa6)
	r3Pub, r3Priv := keypair(0xa7)
	_, otherUserPriv := keypair(0xa8)
	otherWsPub, otherWsPriv := keypair(0xa9)

	cfg := config.Default()
	cfg.AllowAnyUser = true
	cfg.SignAckTimeoutMs = 500
	cfg.SignResponseTimeoutMs = 3000

	reg := hub.NewRegistryWithLimits(cfg.SignAckTimeout(), cfg.SignResponseTimeout(), hub.Limits{
		MaxWorkstationsPerUser: 2,
		MaxRelaysPerUser:       2,
		MaxPendingSignsPerUser: 1,
		MaxUsers:               1,
	})
	srv := New(cfg, reg)

	grpcLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen gRPC: %v", err)
	}
	grpcServer := grpc.NewServer(
		grpc.MaxRecvMsgSize(cfg.MaxGRPCMessageBytes),
		grpc.MaxSendMsgSize(cfg.MaxGRPCMessageBytes),
	)
	sshcastv1.RegisterSshcastServiceServer(grpcServer, srv)
	go func() { _ = grpcServer.Serve(grpcLis) }()
	defer grpcServer.Stop()

	mux := http.NewServeMux()
	mux.Handle("/ws/workstation", srv.WorkstationWebSocketHandler())
	httpSrv := httptest.NewServer(mux)
	defer httpSrv.Close()

	conn, err := grpc.NewClient(grpcLis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	defer conn.Close()
	client := sshcastv1.NewSshcastServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. Connect 2 workstations (1 gRPC + 1 WebSocket).
	_, ws1Auth := makeSignedGrantAndAuth(t, userPriv, ws1Pub, ws1Priv, "ws-1", sshcastv1.NodeRole_NODE_ROLE_CLIENT)
	ws1Stream, err := client.ConnectWorkstation(ctx)
	if err != nil {
		t.Fatalf("ConnectWorkstation ws-1: %v", err)
	}
	if err := ws1Stream.Send(&sshcastv1.ClientStreamMessage{
		Payload: &sshcastv1.ClientStreamMessage_AuthHandshake{AuthHandshake: ws1Auth},
	}); err != nil {
		t.Fatalf("ws1 Send handshake: %v", err)
	}
	if _, err := ws1Stream.Recv(); err != nil {
		t.Fatalf("ws1 Recv heartbeat: %v", err)
	}

	wsURL := "ws://" + strings.TrimPrefix(httpSrv.URL, "http://") + "/ws/workstation"
	_, ws2Auth := makeSignedGrantAndAuth(t, userPriv, ws2Pub, ws2Priv, "ws-2", sshcastv1.NodeRole_NODE_ROLE_CLIENT)
	ws2Conn, err := websocket.Dial(wsURL, "", httpSrv.URL)
	if err != nil {
		t.Fatalf("websocket.Dial ws-2: %v", err)
	}
	defer ws2Conn.Close()
	rawWs2Auth, err := proto.Marshal(&sshcastv1.ClientStreamMessage{
		Payload: &sshcastv1.ClientStreamMessage_AuthHandshake{AuthHandshake: ws2Auth},
	})
	if err != nil {
		t.Fatalf("Marshal ws2Auth: %v", err)
	}
	if err := websocket.Message.Send(ws2Conn, rawWs2Auth); err != nil {
		t.Fatalf("Send ws2Auth: %v", err)
	}
	var hbRaw []byte
	if err := websocket.Message.Receive(ws2Conn, &hbRaw); err != nil {
		t.Fatalf("Receive ws2 heartbeat: %v", err)
	}

	// 2. 3rd workstation over gRPC fails with ResourceExhausted.
	_, ws3Auth := makeSignedGrantAndAuth(t, userPriv, ws3Pub, ws3Priv, "ws-3", sshcastv1.NodeRole_NODE_ROLE_CLIENT)
	ws3Stream, err := client.ConnectWorkstation(ctx)
	if err != nil {
		t.Fatalf("ConnectWorkstation ws-3 dial: %v", err)
	}
	if err := ws3Stream.Send(&sshcastv1.ClientStreamMessage{
		Payload: &sshcastv1.ClientStreamMessage_AuthHandshake{AuthHandshake: ws3Auth},
	}); err != nil {
		t.Fatalf("ws3 Send handshake: %v", err)
	}
	if _, err := ws3Stream.Recv(); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("expected ResourceExhausted for 3rd workstation over gRPC, got %v", err)
	}

	// 3. 3rd workstation over WebSocket is closed cleanly without receiving heartbeat.
	ws3Conn, err := websocket.Dial(wsURL, "", httpSrv.URL)
	if err != nil {
		t.Fatalf("websocket.Dial ws-3: %v", err)
	}
	defer ws3Conn.Close()
	rawWs3Auth, err := proto.Marshal(&sshcastv1.ClientStreamMessage{
		Payload: &sshcastv1.ClientStreamMessage_AuthHandshake{AuthHandshake: ws3Auth},
	})
	if err != nil {
		t.Fatalf("Marshal ws3Auth: %v", err)
	}
	if err := websocket.Message.Send(ws3Conn, rawWs3Auth); err != nil {
		t.Fatalf("Send ws3Auth: %v", err)
	}
	var rejectedRaw []byte
	if err := websocket.Message.Receive(ws3Conn, &rejectedRaw); err == nil {
		t.Fatalf("expected 3rd workstation WebSocket to close cleanly on ResourceExhausted, got %d bytes", len(rejectedRaw))
	}

	// 4. Reconnecting with same nodeID "ws-1" succeeds even at MaxWorkstationsPerUser=2.
	ws1ReconnectStream, err := client.ConnectWorkstation(ctx)
	if err != nil {
		t.Fatalf("ConnectWorkstation ws-1 reconnect: %v", err)
	}
	if err := ws1ReconnectStream.Send(&sshcastv1.ClientStreamMessage{
		Payload: &sshcastv1.ClientStreamMessage_AuthHandshake{AuthHandshake: ws1Auth},
	}); err != nil {
		t.Fatalf("ws1Reconnect Send handshake: %v", err)
	}
	if _, err := ws1ReconnectStream.Recv(); err != nil {
		t.Fatalf("expected same-nodeID reconnect to succeed, got %v", err)
	}

	// 5. Connect 2 relays; 3rd relay fails with ResourceExhausted.
	connectRelay := func(nodeID string, pub ed25519.PublicKey, priv ed25519.PrivateKey) (sshcastv1.SshcastService_ConnectRelayClient, *sshcastv1.NodeGrant, *sshcastv1.NodeAuth, error) {
		grant, authMsg := makeSignedGrantAndAuth(t, userPriv, pub, priv, nodeID, sshcastv1.NodeRole_NODE_ROLE_RELAY)
		rs, err := client.ConnectRelay(ctx)
		if err != nil {
			return nil, grant, authMsg, err
		}
		if err := rs.Send(&sshcastv1.RelayStreamMessage{
			Payload: &sshcastv1.RelayStreamMessage_AuthHandshake{AuthHandshake: authMsg},
		}); err != nil {
			return nil, grant, authMsg, err
		}
		_, err = rs.Recv()
		return rs, grant, authMsg, err
	}

	r1Stream, r1Grant, r1Auth, err := connectRelay("relay-1", r1Pub, r1Priv)
	if err != nil {
		t.Fatalf("connectRelay relay-1: %v", err)
	}
	defer func() { _ = r1Stream.CloseSend() }()
	r2Stream, _, _, err := connectRelay("relay-2", r2Pub, r2Priv)
	if err != nil {
		t.Fatalf("connectRelay relay-2: %v", err)
	}
	defer func() { _ = r2Stream.CloseSend() }()
	if _, _, _, err := connectRelay("relay-3", r3Pub, r3Priv); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("expected ResourceExhausted for 3rd relay, got %v", err)
	}

	// 6. MaxUsers=1 rejects a second user over gRPC with ResourceExhausted.
	_, otherAuth := makeSignedGrantAndAuth(t, otherUserPriv, otherWsPub, otherWsPriv, "other-ws", sshcastv1.NodeRole_NODE_ROLE_CLIENT)
	otherStream, err := client.ConnectWorkstation(ctx)
	if err != nil {
		t.Fatalf("ConnectWorkstation other user: %v", err)
	}
	if err := otherStream.Send(&sshcastv1.ClientStreamMessage{
		Payload: &sshcastv1.ClientStreamMessage_AuthHandshake{AuthHandshake: otherAuth},
	}); err != nil {
		t.Fatalf("otherStream Send handshake: %v", err)
	}
	if _, err := otherStream.Recv(); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("expected ResourceExhausted for MaxUsers exceeded, got %v", err)
	}

	// 7. Pending SignRequest cap (MaxPendingSignsPerUser = 1):
	// Push status on ws1Reconnect so it handles SignRequest.
	testKey := []byte("ssh-ed25519-limit-test-key")
	if err := ws1ReconnectStream.Send(&sshcastv1.ClientStreamMessage{
		Payload: &sshcastv1.ClientStreamMessage_Status{
			Status: &sshcastv1.WorkstationStatus{
				LastInputEpochMs: uint64(time.Now().UnixMilli()),
				ForceActive:      true,
				Keys: []*sshcastv1.PublicKey{
					{KeyBlob: testKey, KeyType: "ssh-ed25519", Comment: "limit@ws1"},
				},
			},
		},
	}); err != nil {
		t.Fatalf("ws1Reconnect Send status: %v", err)
	}
	time.Sleep(30 * time.Millisecond)

	ackedFirst := make(chan string, 1)
	releaseFirst := make(chan struct{})
	go func() {
		for {
			msg, err := ws1ReconnectStream.Recv()
			if err != nil {
				return
			}
			if sr := msg.GetSignRequest(); sr != nil {
				_ = ws1ReconnectStream.Send(&sshcastv1.ClientStreamMessage{
					Payload: &sshcastv1.ClientStreamMessage_SignAck{
						SignAck: &sshcastv1.SignAck{RequestId: sr.GetRequestId()},
					},
				})
				ackedFirst <- sr.GetRequestId()
				<-releaseFirst
				_ = ws1ReconnectStream.Send(&sshcastv1.ClientStreamMessage{
					Payload: &sshcastv1.ClientStreamMessage_SignResponse{
						SignResponse: &sshcastv1.SignResponse{
							RequestId:       sr.GetRequestId(),
							Approved:        true,
							SignatureBlob:   []byte("sig-ok"),
							HandledByNodeId: "ws-1",
						},
					},
				})
				return
			}
		}
	}()

	makeSignReq := func(reqID string) *sshcastv1.SignRequest {
		req := &sshcastv1.SignRequest{
			RequestId:       reqID,
			TimestampUnixMs: uint64(time.Now().UnixMilli()),
			KeyBlob:         testKey,
			Data:            []byte("challenge-" + reqID),
			ProcessContext:  &sshcastv1.ProcessContext{Hostname: "relay-1", Uid: 1000, Pid: 1, Comm: "ssh"},
			RelayGrant:      r1Grant,
			Auth:            r1Auth,
		}
		if err := auth.SignSignRequest(req, r1Priv); err != nil {
			t.Fatalf("SignSignRequest %s: %v", reqID, err)
		}
		return req
	}

	firstRespCh := make(chan *sshcastv1.SignResponse, 1)
	firstErrCh := make(chan error, 1)
	go func() {
		resp, err := client.Sign(ctx, makeSignReq("req-cap-1"))
		firstRespCh <- resp
		firstErrCh <- err
	}()

	select {
	case <-ackedFirst:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for first SignRequest SignAck")
	}

	// Second concurrent Sign RPC exceeds MaxPendingSignsPerUser=1.
	secondResp, secondErr := client.Sign(ctx, makeSignReq("req-cap-2"))
	if secondErr != nil {
		if status.Code(secondErr) != codes.ResourceExhausted {
			t.Fatalf("expected either SignResponse{Approved: false} or ResourceExhausted, got err=%v", secondErr)
		}
	} else if secondResp.GetApproved() || !strings.Contains(secondResp.GetErrorMessage(), hub.ErrTooManyPendingSigns.Error()) {
		t.Fatalf("expected unapproved SignResponse mentioning ErrTooManyPendingSigns, got %+v", secondResp)
	}

	close(releaseFirst)
	if err := <-firstErrCh; err != nil {
		t.Fatalf("first Sign RPC error: %v", err)
	}
	if resp := <-firstRespCh; !resp.GetApproved() {
		t.Fatalf("expected first Sign RPC to be approved, got %+v", resp)
	}
}
