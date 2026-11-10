package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sockcastv1 "github.com/theraphim/sockcast-proto/gen/go/sockcast/v1"
	"github.com/theraphim/sockcast-proto/pkg/auth"
	"github.com/theraphim/sockcast-server/internal/config"
	"github.com/theraphim/sockcast-server/internal/hub"
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

	// 1. Verify /web/ serves index.html, app.js, and the Rust sockcast-client sockcast_wasm.wasm binary
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
	wasmBytes, err := io.ReadAll(respWasm.Body)
	_ = respWasm.Body.Close()
	if err != nil || len(wasmBytes) < 8 || !bytes.Equal(wasmBytes[:4], []byte{0x00, 0x61, 0x73, 0x6d}) {
		t.Fatalf("expected valid WebAssembly binary magic header, got len=%d err=%v", len(wasmBytes), err)
	}
	if !bytes.Contains(wasmBytes, []byte("sockcast_wasm_call")) {
		t.Fatalf("expected sockcast_wasm.wasm to export sockcast_wasm_call from sockcast-client")
	}

	// 2. Connect Browser WASM Workstation over WebSocket (/ws/workstation)
	_, wsAuth := makeSignedGrantAndAuth(t, userPriv, wsPub, wsPriv, "chrome-wasm-node", sockcastv1.NodeRole_NODE_ROLE_CLIENT)

	wsURL := "ws://" + strings.TrimPrefix(httpSrv.URL, "http://") + "/ws/workstation"
	wsConn, err := websocket.Dial(wsURL, "", httpSrv.URL)
	if err != nil {
		t.Fatalf("websocket.Dial: %v", err)
	}
	defer wsConn.Close()

	sendClientFrame := func(msg *sockcastv1.ClientStreamMessage) {
		t.Helper()
		raw, err := proto.Marshal(msg)
		if err != nil {
			t.Fatalf("proto.Marshal ClientStreamMessage: %v", err)
		}
		if err := websocket.Message.Send(wsConn, raw); err != nil {
			t.Fatalf("websocket.Message.Send: %v", err)
		}
	}

	sendClientFrame(&sockcastv1.ClientStreamMessage{
		Payload: &sockcastv1.ClientStreamMessage_AuthHandshake{
			AuthHandshake: wsAuth,
		},
	})

	testKeyBlob := []byte("ssh-ed25519-test-key-blob-for-ws")
	sendClientFrame(&sockcastv1.ClientStreamMessage{
		Payload: &sockcastv1.ClientStreamMessage_Status{
			Status: &sockcastv1.WorkstationStatus{
				LastInputEpochMs: uint64(time.Now().UnixMilli()),
				ForceActive:      true,
				Os:               "browser-wasm",
				Keys: []*sockcastv1.PublicKey{
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
			var srvMsg sockcastv1.ServerStreamMessage
			if err := proto.Unmarshal(raw, &srvMsg); err != nil {
				return
			}
			if sr := srvMsg.GetSignRequest(); sr != nil {
				sendClientFrame(&sockcastv1.ClientStreamMessage{
					Payload: &sockcastv1.ClientStreamMessage_SignAck{
						SignAck: &sockcastv1.SignAck{RequestId: sr.GetRequestId()},
					},
				})
				sendClientFrame(&sockcastv1.ClientStreamMessage{
					Payload: &sockcastv1.ClientStreamMessage_SignResponse{
						SignResponse: &sockcastv1.SignResponse{
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
	relayClient := sockcastv1.NewSockcastServiceClient(grpcConn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	relayGrant, relayAuth := makeSignedGrantAndAuth(t, userPriv, relayPub, relayPriv, "bastion.infra.local", sockcastv1.NodeRole_NODE_ROLE_RELAY)
	idResp, err := relayClient.GetIdentities(ctx, &sockcastv1.GetIdentitiesRequest{Auth: relayAuth})
	if err != nil {
		t.Fatalf("GetIdentities: %v", err)
	}
	if len(idResp.GetKeys()) != 1 || idResp.GetKeys()[0].GetComment() != "browser@chrome" {
		t.Fatalf("expected 1 key from WASM workstation, got %+v", idResp.GetKeys())
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
