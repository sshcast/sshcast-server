package hub

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	sshcastv1 "stingr.net/go/sshcast-proto/gen/go/sshcast/v1"
)

func TestMultiWorkstationKeyUnionAndRouting(t *testing.T) {
	reg := NewRegistry(200*time.Millisecond, 2*time.Second)
	userID := "sc_u_testuser"

	keyA := &sshcastv1.PublicKey{
		KeyBlob:           []byte("ssh-ed25519-key-A"),
		Comment:           "key-a@ws1",
		KeyType:           "ssh-ed25519",
		FingerprintSha256: "SHA256:aaaa",
	}
	keyB := &sshcastv1.PublicKey{
		KeyBlob:           []byte("ssh-ed25519-key-B"),
		Comment:           "key-b@ws2",
		KeyType:           "ssh-ed25519",
		FingerprintSha256: "SHA256:bbbb",
	}

	ws1, err := reg.RegisterWorkstation(userID, "ws1")
	if err != nil {
		t.Fatalf("RegisterWorkstation ws1: %v", err)
	}
	ws2, err := reg.RegisterWorkstation(userID, "ws2")
	if err != nil {
		t.Fatalf("RegisterWorkstation ws2: %v", err)
	}

	// ws1 pushes Key A (input timestamp = 1000)
	reg.UpdateWorkstationStatus(ws1, &sshcastv1.WorkstationStatus{
		LastInputEpochMs: 1000,
		Keys:             []*sshcastv1.PublicKey{keyA},
	})

	// ws2 pushes Key B more recently (input timestamp = 2000)
	reg.UpdateWorkstationStatus(ws2, &sshcastv1.WorkstationStatus{
		LastInputEpochMs: 2000,
		Keys:             []*sshcastv1.PublicKey{keyB},
	})

	// 1. GetIdentities must return the union [keyB, keyA] (active ws2 first, ws1 second), NOT overwrite keyA!
	identities := reg.GetIdentities(userID)
	if len(identities) != 2 {
		t.Fatalf("expected 2 merged identities across workstations, got %d", len(identities))
	}
	if !bytes.Equal(identities[0].GetKeyBlob(), keyB.GetKeyBlob()) {
		t.Fatalf("expected most active workstation's keyB first, got %q", identities[0].GetComment())
	}
	if !bytes.Equal(identities[1].GetKeyBlob(), keyA.GetKeyBlob()) {
		t.Fatalf("expected second workstation's keyA second, got %q", identities[1].GetComment())
	}

	// 2. RouteSignRequest for keyA must route directly to ws1 (which holds keyA), skipping ws2 even though ws2 is more active!
	go func() {
		select {
		case msg := <-ws1.SendCh:
			sr := msg.GetSignRequest()
			if sr == nil {
				return
			}
			reg.HandleSignAck(userID, "ws1", &sshcastv1.SignAck{RequestId: sr.GetRequestId()})
			reg.HandleSignResponse(userID, "ws1", &sshcastv1.SignResponse{
				RequestId:       sr.GetRequestId(),
				Approved:        true,
				SignatureBlob:   []byte("sig-from-ws1"),
				HandledByNodeId: "ws1",
			})
		case <-time.After(time.Second):
		}
	}()

	resp, err := reg.RouteSignRequest(context.Background(), userID, &sshcastv1.SignRequest{
		RequestId: "req-for-key-a",
		KeyBlob:   keyA.GetKeyBlob(),
	})
	if err != nil {
		t.Fatalf("RouteSignRequest for keyA failed: %v", err)
	}
	if !resp.GetApproved() || resp.GetHandledByNodeId() != "ws1" {
		t.Fatalf("expected keyA SignRequest to be handled by ws1, got %+v", resp)
	}

	// Ensure ws2 was never prompted for keyA
	select {
	case msg := <-ws2.SendCh:
		t.Fatalf("ws2 should not have received SignRequest for keyA, but got: %+v", msg)
	default:
	}

	// 3. When ws1 disconnects while ws2 stays connected, GetIdentities reflects only ws2's keys
	reg.UnregisterWorkstation(ws1)
	remaining := reg.GetIdentities(userID)
	if len(remaining) != 1 || !bytes.Equal(remaining[0].GetKeyBlob(), keyB.GetKeyBlob()) {
		t.Fatalf("expected only keyB after ws1 disconnected, got %+v", remaining)
	}
}

func TestCascadeAndCancelSignRequestToIgnoredWorkstation(t *testing.T) {
	// signAckTimeout = 100ms, signResponseTimeout = 300ms (cascadeInterval = 75ms)
	reg := NewRegistry(100*time.Millisecond, 300*time.Millisecond)
	userID := "sc_u_cascadeuser"
	sharedKey := &sshcastv1.PublicKey{
		KeyBlob:           []byte("ssh-ed25519-shared-key"),
		Comment:           "shared@user",
		KeyType:           "ssh-ed25519",
		FingerprintSha256: "SHA256:shared",
	}

	ws1, err := reg.RegisterWorkstation(userID, "ws1-unattended")
	if err != nil {
		t.Fatalf("RegisterWorkstation ws1-unattended: %v", err)
	}
	ws2, err := reg.RegisterWorkstation(userID, "ws2-attended")
	if err != nil {
		t.Fatalf("RegisterWorkstation ws2-attended: %v", err)
	}

	reg.UpdateWorkstationStatus(ws1, &sshcastv1.WorkstationStatus{
		LastInputEpochMs: 2000,
		Keys:             []*sshcastv1.PublicKey{sharedKey},
	})
	reg.UpdateWorkstationStatus(ws2, &sshcastv1.WorkstationStatus{
		LastInputEpochMs: 1000,
		Keys:             []*sshcastv1.PublicKey{sharedKey},
	})

	ws1GotCancel := make(chan string, 1)
	go func() {
		// ws1 receives SignRequest and immediately SignAcks, but the user is away and ignores the modal
		msg1 := <-ws1.SendCh
		if sr := msg1.GetSignRequest(); sr != nil {
			reg.HandleSignAck(userID, "ws1-unattended", &sshcastv1.SignAck{RequestId: sr.GetRequestId()})
		}
		// Expect CancelSignRequest when ws2 answers after cascade
		msg2 := <-ws1.SendCh
		if cancel := msg2.GetCancelSignRequest(); cancel != nil {
			ws1GotCancel <- cancel.GetRequestId()
		}
	}()

	go func() {
		// ws2 receives the cascaded SignRequest and approves it
		msg := <-ws2.SendCh
		if sr := msg.GetSignRequest(); sr != nil {
			reg.HandleSignResponse(userID, "ws2-attended", &sshcastv1.SignResponse{
				RequestId:       sr.GetRequestId(),
				Approved:        true,
				SignatureBlob:   []byte("sig-from-ws2"),
				HandledByNodeId: "ws2-attended",
			})
		}
	}()

	resp, err := reg.RouteSignRequest(context.Background(), userID, &sshcastv1.SignRequest{
		RequestId: "req-cascade-1",
		KeyBlob:   sharedKey.GetKeyBlob(),
	})
	if err != nil {
		t.Fatalf("RouteSignRequest failed: %v", err)
	}
	if !resp.GetApproved() || resp.GetHandledByNodeId() != "ws2-attended" {
		t.Fatalf("expected cascaded SignResponse from ws2-attended, got %+v", resp)
	}

	select {
	case canceledID := <-ws1GotCancel:
		if canceledID != "req-cascade-1" {
			t.Fatalf("unexpected CancelSignRequest ID on ws1: %q", canceledID)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for CancelSignRequest on ignored workstation ws1")
	}
}

func TestRegistrySafetyLimitsAndReconnect(t *testing.T) {
	defaults := DefaultLimits()
	if defaults.MaxWorkstationsPerUser != 16 || defaults.MaxRelaysPerUser != 64 ||
		defaults.MaxPendingSignsPerUser != 16 || defaults.MaxUsers != 10000 {
		t.Fatalf("unexpected DefaultLimits: %+v", defaults)
	}

	reg := NewRegistryWithLimits(200*time.Millisecond, 2*time.Second, Limits{
		MaxWorkstationsPerUser: 2,
		MaxRelaysPerUser:       2,
		MaxPendingSignsPerUser: 2,
		MaxUsers:               2,
	})

	u1 := "sc_u_user1"
	u2 := "sc_u_user2"
	u3 := "sc_u_user3"

	// 1. Workstation cap & same-nodeID reconnect
	ws1, err := reg.RegisterWorkstation(u1, "ws-1")
	if err != nil {
		t.Fatalf("RegisterWorkstation ws-1: %v", err)
	}
	ws2, err := reg.RegisterWorkstation(u1, "ws-2")
	if err != nil {
		t.Fatalf("RegisterWorkstation ws-2: %v", err)
	}
	if _, err := reg.RegisterWorkstation(u1, "ws-3"); !errors.Is(err, ErrTooManyWorkstations) {
		t.Fatalf("expected ErrTooManyWorkstations, got %v", err)
	}

	// Same nodeID reconnect succeeds without hitting MaxWorkstationsPerUser and closes old DoneCh.
	ws1Reconnect, err := reg.RegisterWorkstation(u1, "ws-1")
	if err != nil {
		t.Fatalf("reconnect RegisterWorkstation ws-1: %v", err)
	}
	select {
	case <-ws1.DoneCh:
	default:
		t.Fatal("expected old ws1 DoneCh to be closed on reconnect")
	}
	// Stale UnregisterWorkstation(ws1) must not remove ws1Reconnect.
	reg.UnregisterWorkstation(ws1)
	if _, err := reg.RegisterWorkstation(u1, "ws-3"); !errors.Is(err, ErrTooManyWorkstations) {
		t.Fatalf("expected stale unregister to preserve cap, got %v", err)
	}

	// Unregistering active ws2 frees a slot.
	reg.UnregisterWorkstation(ws2)
	ws3, err := reg.RegisterWorkstation(u1, "ws-3")
	if err != nil {
		t.Fatalf("RegisterWorkstation ws-3 after unregister: %v", err)
	}

	// 2. Relay cap & same-nodeID reconnect
	r1, err := reg.RegisterRelay(u1, "relay-1")
	if err != nil {
		t.Fatalf("RegisterRelay relay-1: %v", err)
	}
	r2, err := reg.RegisterRelay(u1, "relay-2")
	if err != nil {
		t.Fatalf("RegisterRelay relay-2: %v", err)
	}
	if _, err := reg.RegisterRelay(u1, "relay-3"); !errors.Is(err, ErrTooManyRelays) {
		t.Fatalf("expected ErrTooManyRelays, got %v", err)
	}
	r1Reconnect, err := reg.RegisterRelay(u1, "relay-1")
	if err != nil {
		t.Fatalf("reconnect RegisterRelay relay-1: %v", err)
	}
	select {
	case <-r1.DoneCh:
	default:
		t.Fatal("expected old r1 DoneCh to be closed on reconnect")
	}
	reg.UnregisterRelay(r1)
	reg.UnregisterRelay(r2)
	r3, err := reg.RegisterRelay(u1, "relay-3")
	if err != nil {
		t.Fatalf("RegisterRelay relay-3 after unregister: %v", err)
	}
	_ = r1Reconnect
	_ = r3

	// 3. Pending SignRequest cap (MaxPendingSignsPerUser = 2)
	key := &sshcastv1.PublicKey{KeyBlob: []byte("ssh-ed25519-cap-key"), KeyType: "ssh-ed25519"}
	reg.UpdateWorkstationStatus(ws1Reconnect, &sshcastv1.WorkstationStatus{
		LastInputEpochMs: 5000,
		Keys:             []*sshcastv1.PublicKey{key},
	})
	// Disconnect ws3 so only ws1Reconnect receives prompts cleanly.
	reg.UnregisterWorkstation(ws3)

	type signResult struct {
		resp *sshcastv1.SignResponse
		err  error
	}
	res1Ch := make(chan signResult, 1)
	res2Ch := make(chan signResult, 1)
	go func() {
		resp, err := reg.RouteSignRequest(context.Background(), u1, &sshcastv1.SignRequest{
			RequestId: "pending-1",
			KeyBlob:   key.GetKeyBlob(),
		})
		res1Ch <- signResult{resp: resp, err: err}
	}()
	go func() {
		resp, err := reg.RouteSignRequest(context.Background(), u1, &sshcastv1.SignRequest{
			RequestId: "pending-2",
			KeyBlob:   key.GetKeyBlob(),
		})
		res2Ch <- signResult{resp: resp, err: err}
	}()

	// Acknowledge both pending SignRequests so both stay in uh.pending waiting for approval.
	acked := 0
	deadline := time.After(time.Second)
	for acked < 2 {
		select {
		case msg := <-ws1Reconnect.SendCh:
			sr := msg.GetSignRequest()
			if sr == nil {
				continue
			}
			reg.HandleSignAck(u1, "ws-1", &sshcastv1.SignAck{RequestId: sr.GetRequestId()})
			acked++
		case <-deadline:
			t.Fatal("timed out waiting for pending SignRequests on ws1Reconnect")
		}
	}

	// Third concurrent SignRequest must be rejected immediately with ErrTooManyPendingSigns.
	if _, err := reg.RouteSignRequest(context.Background(), u1, &sshcastv1.SignRequest{
		RequestId: "pending-3",
		KeyBlob:   key.GetKeyBlob(),
	}); !errors.Is(err, ErrTooManyPendingSigns) {
		t.Fatalf("expected ErrTooManyPendingSigns, got %v", err)
	}

	// Approve both in-flight requests to release pending slots.
	for _, reqID := range []string{"pending-1", "pending-2"} {
		reg.HandleSignResponse(u1, "ws-1", &sshcastv1.SignResponse{
			RequestId:       reqID,
			Approved:        true,
			SignatureBlob:   []byte("sig-" + reqID),
			HandledByNodeId: "ws-1",
		})
	}
	for _, ch := range []chan signResult{res1Ch, res2Ch} {
		res := <-ch
		if res.err != nil || !res.resp.GetApproved() {
			t.Fatalf("expected pending SignRequest to succeed, got resp=%+v err=%v", res.resp, res.err)
		}
	}

	// 4. MaxUsers cap (MaxUsers = 2)
	wsU2, err := reg.RegisterWorkstation(u2, "ws-u2")
	if err != nil {
		t.Fatalf("RegisterWorkstation u2: %v", err)
	}
	if _, err := reg.RegisterWorkstation(u3, "ws-u3"); !errors.Is(err, ErrTooManyUsers) {
		t.Fatalf("expected ErrTooManyUsers for u3 workstation, got %v", err)
	}
	if _, err := reg.RegisterRelay(u3, "relay-u3"); !errors.Is(err, ErrTooManyUsers) {
		t.Fatalf("expected ErrTooManyUsers for u3 relay, got %v", err)
	}
	// Existing user u2 can still add a relay.
	if _, err := reg.RegisterRelay(u2, "relay-u2"); err != nil {
		t.Fatalf("expected existing user u2 to still register relay, got %v", err)
	}

	// Disconnecting all sessions for u1 (even with cachedKeys present) frees the user slot for u3.
	reg.UnregisterWorkstation(ws1Reconnect)
	reg.UnregisterRelay(r1Reconnect)
	reg.UnregisterRelay(r3)
	if len(reg.GetIdentities(u1)) != 1 {
		t.Fatalf("expected u1 cached keys to still be available while capacity exists")
	}
	wsU3, err := reg.RegisterWorkstation(u3, "ws-u3")
	if err != nil {
		t.Fatalf("expected u3 to succeed after u1 became inactive, got %v", err)
	}
	reg.UnregisterWorkstation(wsU2)
	reg.UnregisterWorkstation(wsU3)
}

