package hub

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	sockcastv1 "github.com/theraphim/sockcast-proto/gen/go/sockcast/v1"
)

var (
	ErrNoWorkstationConnected = errors.New("no workstation connected for user")
	ErrNoWorkstationAcked     = errors.New("no connected workstation acknowledged sign request within timeout")
	ErrSignApprovalTimedOut   = errors.New("timed out waiting for workstation sign approval")
)

type WorkstationSession struct {
	UserID           string
	NodeID           string
	OS               string
	LastInputEpochMs uint64
	ForceActive      bool
	ConnectedAt      time.Time
	SendCh           chan *sockcastv1.ServerStreamMessage
	DoneCh           chan struct{}
}

func (ws *WorkstationSession) TrySend(msg *sockcastv1.ServerStreamMessage) bool {
	select {
	case <-ws.DoneCh:
		return false
	default:
	}
	select {
	case ws.SendCh <- msg:
		return true
	case <-ws.DoneCh:
		return false
	default:
		return false
	}
}

type pendingSignRequest struct {
	req              *sockcastv1.SignRequest
	ackCh            chan string
	respCh           chan *sockcastv1.SignResponse
	promptedNodes    map[string]uint64 // node_id -> last_input_epoch_ms at prompt time
	highestInputSeen uint64
}

type UserHub struct {
	mu           sync.Mutex
	userID       string
	cachedKeys   []*sockcastv1.PublicKey
	workstations map[string]*WorkstationSession
	pending      map[string]*pendingSignRequest
}

func newUserHub(userID string) *UserHub {
	return &UserHub{
		userID:       userID,
		workstations: make(map[string]*WorkstationSession),
		pending:      make(map[string]*pendingSignRequest),
	}
}

type Registry struct {
	mu                  sync.Mutex
	users               map[string]*UserHub
	signAckTimeout      time.Duration
	signResponseTimeout time.Duration
}

func NewRegistry(signAckTimeout, signResponseTimeout time.Duration) *Registry {
	return &Registry{
		users:               make(map[string]*UserHub),
		signAckTimeout:      signAckTimeout,
		signResponseTimeout: signResponseTimeout,
	}
}

func (r *Registry) getOrCreateUserHub(userID string) *UserHub {
	r.mu.Lock()
	defer r.mu.Unlock()
	uh, ok := r.users[userID]
	if !ok {
		uh = newUserHub(userID)
		r.users[userID] = uh
	}
	return uh
}

// RegisterWorkstation registers a connected workstation stream for userID.
// If an older session with the same nodeID exists, it is closed and replaced.
func (r *Registry) RegisterWorkstation(userID, nodeID string) *WorkstationSession {
	uh := r.getOrCreateUserHub(userID)
	uh.mu.Lock()
	defer uh.mu.Unlock()

	if old, exists := uh.workstations[nodeID]; exists {
		close(old.DoneCh)
	}

	ws := &WorkstationSession{
		UserID:      userID,
		NodeID:      nodeID,
		ConnectedAt: time.Now(),
		SendCh:      make(chan *sockcastv1.ServerStreamMessage, 64),
		DoneCh:      make(chan struct{}),
	}
	uh.workstations[nodeID] = ws
	return ws
}

// UnregisterWorkstation removes the workstation session if it matches the given pointer.
func (r *Registry) UnregisterWorkstation(ws *WorkstationSession) {
	uh := r.getOrCreateUserHub(ws.UserID)
	uh.mu.Lock()
	defer uh.mu.Unlock()

	current, exists := uh.workstations[ws.NodeID]
	if exists && current == ws {
		delete(uh.workstations, ws.NodeID)
		select {
		case <-ws.DoneCh:
		default:
			close(ws.DoneCh)
		}
	}
}

// UpdateWorkstationStatus updates presence metadata and cached public keys for a workstation.
// If any pending SignRequests are waiting for human approval and this workstation just became newly active,
// the SignRequest is also forwarded to this workstation.
func (r *Registry) UpdateWorkstationStatus(ws *WorkstationSession, status *sockcastv1.WorkstationStatus) {
	if status == nil {
		return
	}
	uh := r.getOrCreateUserHub(ws.UserID)
	uh.mu.Lock()
	defer uh.mu.Unlock()

	ws.LastInputEpochMs = status.GetLastInputEpochMs()
	ws.ForceActive = status.GetForceActive()
	if status.GetOs() != "" {
		ws.OS = status.GetOs()
	}
	// Always update cached keys when status is pushed (allows empty list if user filtered all keys,
	// or non-empty list when keys are present).
	if status.Keys != nil {
		cloned := make([]*sockcastv1.PublicKey, len(status.Keys))
		copy(cloned, status.Keys)
		uh.cachedKeys = cloned
	}

	// Dynamic promotion: if a SignRequest is currently waiting for human action on another workstation,
	// and this workstation reports ForceActive or a strictly newer LastInputEpochMs, also prompt this workstation.
	for _, p := range uh.pending {
		if _, alreadyPrompted := p.promptedNodes[ws.NodeID]; alreadyPrompted {
			continue
		}
		if ws.ForceActive || (ws.LastInputEpochMs > 0 && ws.LastInputEpochMs > p.highestInputSeen) {
			if ws.TrySend(&sockcastv1.ServerStreamMessage{
				Payload: &sockcastv1.ServerStreamMessage_SignRequest{
					SignRequest: p.req,
				},
			}) {
				p.promptedNodes[ws.NodeID] = ws.LastInputEpochMs
				if ws.LastInputEpochMs > p.highestInputSeen {
					p.highestInputSeen = ws.LastInputEpochMs
				}
			}
		}
	}
}

// GetIdentities returns the latest cached public keys for userID.
func (r *Registry) GetIdentities(userID string) []*sockcastv1.PublicKey {
	uh := r.getOrCreateUserHub(userID)
	uh.mu.Lock()
	defer uh.mu.Unlock()

	out := make([]*sockcastv1.PublicKey, len(uh.cachedKeys))
	copy(out, uh.cachedKeys)
	return out
}

// HandleSignAck records an immediate SignAck from a workstation.
func (r *Registry) HandleSignAck(userID, nodeID string, ack *sockcastv1.SignAck) {
	if ack == nil {
		return
	}
	uh := r.getOrCreateUserHub(userID)
	uh.mu.Lock()
	p, ok := uh.pending[ack.GetRequestId()]
	uh.mu.Unlock()
	if !ok {
		return
	}
	select {
	case p.ackCh <- nodeID:
	default:
	}
}

// HandleSignResponse delivers a workstation's SignResponse to the waiting RPC handler.
func (r *Registry) HandleSignResponse(userID, nodeID string, resp *sockcastv1.SignResponse) {
	if resp == nil {
		return
	}
	if resp.HandledByNodeId == "" {
		resp.HandledByNodeId = nodeID
	}
	uh := r.getOrCreateUserHub(userID)
	uh.mu.Lock()
	p, ok := uh.pending[resp.GetRequestId()]
	uh.mu.Unlock()
	if !ok {
		return
	}
	select {
	case p.respCh <- resp:
	default:
	}
}

func (uh *UserHub) sortedCandidatesLocked() []*WorkstationSession {
	candidates := make([]*WorkstationSession, 0, len(uh.workstations))
	for _, ws := range uh.workstations {
		candidates = append(candidates, ws)
	}
	sort.Slice(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if a.ForceActive != b.ForceActive {
			return a.ForceActive
		}
		if a.LastInputEpochMs != b.LastInputEpochMs {
			return a.LastInputEpochMs > b.LastInputEpochMs
		}
		return a.ConnectedAt.After(b.ConnectedAt)
	})
	return candidates
}

// RouteSignRequest routes a SignRequest to the user's most recently active workstation using the
// two-phase 1.5s SignAck receipt + 60s SignResponse approval protocol.
func (r *Registry) RouteSignRequest(ctx context.Context, userID string, req *sockcastv1.SignRequest) (*sockcastv1.SignResponse, error) {
	uh := r.getOrCreateUserHub(userID)

	uh.mu.Lock()
	candidates := uh.sortedCandidatesLocked()
	if len(candidates) == 0 {
		uh.mu.Unlock()
		return nil, ErrNoWorkstationConnected
	}

	p := &pendingSignRequest{
		req:           req,
		ackCh:         make(chan string, 8),
		respCh:        make(chan *sockcastv1.SignResponse, 4),
		promptedNodes: make(map[string]uint64),
	}
	uh.pending[req.GetRequestId()] = p
	uh.mu.Unlock()

	var winningNodeID string
	defer func() {
		uh.mu.Lock()
		defer uh.mu.Unlock()
		delete(uh.pending, req.GetRequestId())

		// Cancel prompt on any workstation that was prompted except the one that already answered.
		for nodeID := range p.promptedNodes {
			if nodeID == winningNodeID {
				continue
			}
			if ws, ok := uh.workstations[nodeID]; ok {
				ws.TrySend(&sockcastv1.ServerStreamMessage{
					Payload: &sockcastv1.ServerStreamMessage_CancelSignRequest{
						CancelSignRequest: &sockcastv1.CancelSignRequest{
							RequestId: req.GetRequestId(),
							Reason:    "Handled or cancelled",
						},
					},
				})
			}
		}
	}()

	acked := false
	for _, ws := range candidates {
		uh.mu.Lock()
		sent := ws.TrySend(&sockcastv1.ServerStreamMessage{
			Payload: &sockcastv1.ServerStreamMessage_SignRequest{
				SignRequest: req,
			},
		})
		if sent {
			p.promptedNodes[ws.NodeID] = ws.LastInputEpochMs
			if ws.LastInputEpochMs > p.highestInputSeen {
				p.highestInputSeen = ws.LastInputEpochMs
			}
		}
		uh.mu.Unlock()

		if !sent {
			continue
		}

		ackTimer := time.NewTimer(r.signAckTimeout)
		select {
		case <-ctx.Done():
			ackTimer.Stop()
			return nil, ctx.Err()
		case resp := <-p.respCh:
			ackTimer.Stop()
			winningNodeID = resp.GetHandledByNodeId()
			return resp, nil
		case ackNode := <-p.ackCh:
			ackTimer.Stop()
			log.Printf("[hub] SignAck received for request %s from workstation %s", req.GetRequestId(), ackNode)
			acked = true
		case <-ws.DoneCh:
			ackTimer.Stop()
			log.Printf("[hub] Workstation %s disconnected before SignAck for request %s; failing over", ws.NodeID, req.GetRequestId())
			continue
		case <-ackTimer.C:
			log.Printf("[hub] Workstation %s did not SignAck request %s within %v; failing over", ws.NodeID, req.GetRequestId(), r.signAckTimeout)
			continue
		}

		if acked {
			break
		}
	}

	if !acked {
		return nil, fmt.Errorf("%w (tried %d workstation(s))", ErrNoWorkstationAcked, len(candidates))
	}

	// Phase 2: Wait up to signResponseTimeout (60s) for human approval or policy response.
	approvalTimer := time.NewTimer(r.signResponseTimeout)
	defer approvalTimer.Stop()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case resp := <-p.respCh:
		winningNodeID = resp.GetHandledByNodeId()
		return resp, nil
	case <-approvalTimer.C:
		return nil, ErrSignApprovalTimedOut
	}
}
