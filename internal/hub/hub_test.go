package hub

import (
	"bytes"
	"context"
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

	ws1 := reg.RegisterWorkstation(userID, "ws1")
	ws2 := reg.RegisterWorkstation(userID, "ws2")

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
