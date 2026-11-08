package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"net"
	"testing"
	"time"

	sockcastv1 "github.com/theraphim/sockcast-proto/gen/go/sockcast/v1"
	"github.com/theraphim/sockcast-proto/pkg/auth"
	"github.com/theraphim/sockcast-server/internal/config"
	"github.com/theraphim/sockcast-server/internal/hub"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
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
