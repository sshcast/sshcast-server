package hub

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	sshcastv1 "stingr.net/go/sshcast-proto/gen/go/sshcast/v1"
)

var (
	ErrNoWorkstationConnected = errors.New("no workstation connected for user")
	ErrNoWorkstationAcked     = errors.New("no connected workstation acknowledged sign request within timeout")
	ErrSignApprovalTimedOut   = errors.New("timed out waiting for workstation sign approval")
	ErrTooManyUsers           = errors.New("maximum user capacity reached on coordinator")
	ErrTooManyWorkstations    = errors.New("maximum workstations per user reached")
	ErrTooManyRelays          = errors.New("maximum relays per user reached")
	ErrTooManyPendingSigns    = errors.New("maximum pending sign requests per user reached")
)

// Limits configures per-coordinator and per-user resource caps.
// Non-positive values disable the corresponding cap.
type Limits struct {
	MaxWorkstationsPerUser int
	MaxRelaysPerUser       int
	MaxPendingSignsPerUser int
	MaxUsers               int
}

// DefaultLimits returns the default safety caps for a coordinator hub Registry.
func DefaultLimits() Limits {
	return Limits{
		MaxWorkstationsPerUser: 16,
		MaxRelaysPerUser:       64,
		MaxPendingSignsPerUser: 16,
		MaxUsers:               10000,
	}
}

type WorkstationSession struct {
	UserID           string
	NodeID           string
	OS               string
	LastInputEpochMs uint64
	ForceActive      bool
	ConnectedAt      time.Time
	Keys             []*sshcastv1.PublicKey
	SendCh           chan *sshcastv1.ServerStreamMessage
	DoneCh           chan struct{}
}

func (ws *WorkstationSession) HasKeyBlob(keyBlob []byte) bool {
	if len(keyBlob) == 0 {
		return false
	}
	for _, k := range ws.Keys {
		if bytes.Equal(k.GetKeyBlob(), keyBlob) {
			return true
		}
	}
	return false
}

func (ws *WorkstationSession) TrySend(msg *sshcastv1.ServerStreamMessage) bool {
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

func (ws *WorkstationSession) SendReliable(msg *sshcastv1.ServerStreamMessage) bool {
	select {
	case ws.SendCh <- msg:
		return true
	case <-ws.DoneCh:
		return false
	case <-time.After(10 * time.Second):
		return false
	}
}

type RelaySession struct {
	UserID      string
	NodeID      string
	ConnectedAt time.Time
	Status      *sshcastv1.RelayZellijStatus
	SendCh      chan *sshcastv1.ServerToRelayMessage
	DoneCh      chan struct{}
}

func (rs *RelaySession) TrySend(msg *sshcastv1.ServerToRelayMessage) bool {
	select {
	case <-rs.DoneCh:
		return false
	default:
	}
	select {
	case rs.SendCh <- msg:
		return true
	case <-rs.DoneCh:
		return false
	default:
		return false
	}
}

func (rs *RelaySession) SendReliable(msg *sshcastv1.ServerToRelayMessage) bool {
	select {
	case rs.SendCh <- msg:
		return true
	case <-rs.DoneCh:
		return false
	case <-time.After(10 * time.Second):
		return false
	}
}

type pendingSignRequest struct {
	req              *sshcastv1.SignRequest
	ackCh            chan string
	respCh           chan *sshcastv1.SignResponse
	promptedNodes    map[string]uint64 // node_id -> last_input_epoch_ms at prompt time
	highestInputSeen uint64
}

type UserHub struct {
	mu           sync.Mutex
	userID       string
	cachedKeys   []*sshcastv1.PublicKey
	workstations map[string]*WorkstationSession
	relays       map[string]*RelaySession
	pending      map[string]*pendingSignRequest
}

func newUserHub(userID string) *UserHub {
	return &UserHub{
		userID:       userID,
		workstations: make(map[string]*WorkstationSession),
		relays:       make(map[string]*RelaySession),
		pending:      make(map[string]*pendingSignRequest),
	}
}

type Registry struct {
	mu                  sync.Mutex
	users               map[string]*UserHub
	signAckTimeout      time.Duration
	signResponseTimeout time.Duration
	limits              Limits
}

func NewRegistry(signAckTimeout, signResponseTimeout time.Duration) *Registry {
	return NewRegistryWithLimits(signAckTimeout, signResponseTimeout, DefaultLimits())
}

// NewRegistryWithLimits creates a Registry enforcing the specified safety Limits.
func NewRegistryWithLimits(signAckTimeout, signResponseTimeout time.Duration, limits Limits) *Registry {
	return &Registry{
		users:               make(map[string]*UserHub),
		signAckTimeout:      signAckTimeout,
		signResponseTimeout: signResponseTimeout,
		limits:              limits,
	}
}

func (r *Registry) getUserHub(userID string) *UserHub {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.users[userID]
}

func (r *Registry) evictOneInactiveUserLocked() {
	for uid, uh := range r.users {
		uh.mu.Lock()
		inactive := len(uh.workstations) == 0 && len(uh.relays) == 0 && len(uh.pending) == 0
		uh.mu.Unlock()
		if inactive {
			delete(r.users, uid)
			return
		}
	}
}

func (r *Registry) getOrCreateAndLockUserHub(userID string) (*UserHub, error) {
	r.mu.Lock()
	uh, ok := r.users[userID]
	if !ok {
		if r.limits.MaxUsers > 0 && len(r.users) >= r.limits.MaxUsers {
			r.evictOneInactiveUserLocked()
			if len(r.users) >= r.limits.MaxUsers {
				r.mu.Unlock()
				return nil, ErrTooManyUsers
			}
		}
		uh = newUserHub(userID)
		r.users[userID] = uh
	}
	uh.mu.Lock()
	r.mu.Unlock()
	return uh, nil
}

// RegisterWorkstation registers a connected workstation stream for userID.
// If an older session with the same nodeID exists, it is closed and replaced without counting against MaxWorkstationsPerUser.
func (r *Registry) RegisterWorkstation(userID, nodeID string) (*WorkstationSession, error) {
	uh, err := r.getOrCreateAndLockUserHub(userID)
	if err != nil {
		return nil, err
	}
	defer uh.mu.Unlock()

	if old, exists := uh.workstations[nodeID]; exists {
		select {
		case <-old.DoneCh:
		default:
			close(old.DoneCh)
		}
	} else if r.limits.MaxWorkstationsPerUser > 0 && len(uh.workstations) >= r.limits.MaxWorkstationsPerUser {
		return nil, ErrTooManyWorkstations
	}

	ws := &WorkstationSession{
		UserID:      userID,
		NodeID:      nodeID,
		ConnectedAt: time.Now(),
		SendCh:      make(chan *sshcastv1.ServerStreamMessage, 2048),
		DoneCh:      make(chan struct{}),
	}
	uh.workstations[nodeID] = ws
	return ws, nil
}

// UnregisterWorkstation removes the workstation session if it matches the given pointer.
func (r *Registry) UnregisterWorkstation(ws *WorkstationSession) {
	if ws == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	uh, ok := r.users[ws.UserID]
	if !ok {
		return
	}
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
		if len(uh.workstations) > 0 {
			uh.rebuildCachedKeysLocked()
		}
		if len(uh.workstations) == 0 && len(uh.relays) == 0 && len(uh.pending) == 0 && len(uh.cachedKeys) == 0 {
			delete(r.users, ws.UserID)
		}
	}
}

func (uh *UserHub) rebuildCachedKeysLocked() {
	ordered := uh.sortedCandidatesLocked()
	seen := make(map[string]struct{})
	merged := make([]*sshcastv1.PublicKey, 0)
	for _, ws := range ordered {
		for _, k := range ws.Keys {
			if k == nil || len(k.GetKeyBlob()) == 0 {
				continue
			}
			blobKey := string(k.GetKeyBlob())
			if _, dup := seen[blobKey]; dup {
				continue
			}
			seen[blobKey] = struct{}{}
			merged = append(merged, k)
		}
	}
	uh.cachedKeys = merged
}

func (uh *UserHub) anyWorkstationHasKeyLocked(keyBlob []byte) bool {
	if len(keyBlob) == 0 {
		return false
	}
	for _, ws := range uh.workstations {
		if ws.HasKeyBlob(keyBlob) {
			return true
		}
	}
	return false
}

// UpdateWorkstationStatus updates presence metadata and cached public keys for a workstation.
// If any pending SignRequests are waiting for human approval and this workstation just became newly active,
// the SignRequest is also forwarded to this workstation.
func (r *Registry) UpdateWorkstationStatus(ws *WorkstationSession, status *sshcastv1.WorkstationStatus) {
	if ws == nil || status == nil {
		return
	}
	uh := r.getUserHub(ws.UserID)
	if uh == nil {
		return
	}
	uh.mu.Lock()
	defer uh.mu.Unlock()

	if cur, ok := uh.workstations[ws.NodeID]; !ok || cur != ws {
		return
	}

	ws.LastInputEpochMs = status.GetLastInputEpochMs()
	ws.ForceActive = status.GetForceActive()
	if status.GetOs() != "" {
		ws.OS = status.GetOs()
	}
	// Update this workstation's keys and rebuild the deduplicated union across all connected workstations
	// (ordered by workstation activity so the most active workstation's keys are offered first).
	if status.Keys != nil {
		cloned := make([]*sshcastv1.PublicKey, len(status.Keys))
		copy(cloned, status.Keys)
		ws.Keys = cloned
	} else {
		ws.Keys = nil
	}
	uh.rebuildCachedKeysLocked()

	// Dynamic promotion: if a SignRequest is currently waiting for human action on another workstation,
	// and this workstation reports ForceActive or a strictly newer LastInputEpochMs, also prompt this workstation
	// (provided it actually holds the requested key, or no connected workstation advertised that key).
	for _, p := range uh.pending {
		if _, alreadyPrompted := p.promptedNodes[ws.NodeID]; alreadyPrompted {
			continue
		}
		reqKey := p.req.GetKeyBlob()
		if !ws.HasKeyBlob(reqKey) && uh.anyWorkstationHasKeyLocked(reqKey) {
			continue
		}
		if ws.ForceActive || (ws.LastInputEpochMs > 0 && ws.LastInputEpochMs > p.highestInputSeen) {
			if ws.TrySend(&sshcastv1.ServerStreamMessage{
				Payload: &sshcastv1.ServerStreamMessage_SignRequest{
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

// GetIdentities returns the union of public keys across all connected workstations for userID
// (ordered by workstation activity), or the last known cached keys if no workstations are connected.
func (r *Registry) GetIdentities(userID string) []*sshcastv1.PublicKey {
	uh := r.getUserHub(userID)
	if uh == nil {
		return nil
	}
	uh.mu.Lock()
	defer uh.mu.Unlock()

	if len(uh.workstations) > 0 {
		uh.rebuildCachedKeysLocked()
	}
	out := make([]*sshcastv1.PublicKey, len(uh.cachedKeys))
	copy(out, uh.cachedKeys)
	return out
}

// HandleSignAck records an immediate SignAck from a workstation.
func (r *Registry) HandleSignAck(userID, nodeID string, ack *sshcastv1.SignAck) {
	if ack == nil {
		return
	}
	uh := r.getUserHub(userID)
	if uh == nil {
		return
	}
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
func (r *Registry) HandleSignResponse(userID, nodeID string, resp *sshcastv1.SignResponse) {
	if resp == nil {
		return
	}
	if resp.HandledByNodeId == "" {
		resp.HandledByNodeId = nodeID
	}
	uh := r.getUserHub(userID)
	if uh == nil {
		return
	}
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

func (uh *UserHub) sortedCandidatesForKeyLocked(keyBlob []byte) []*WorkstationSession {
	all := uh.sortedCandidatesLocked()
	if len(all) <= 1 || len(keyBlob) == 0 {
		return all
	}
	matching := make([]*WorkstationSession, 0, len(all))
	others := make([]*WorkstationSession, 0, len(all))
	for _, ws := range all {
		if ws.HasKeyBlob(keyBlob) {
			matching = append(matching, ws)
		} else {
			others = append(others, ws)
		}
	}
	if len(matching) == 0 {
		return all
	}
	return append(matching, others...)
}

// RouteSignRequest routes a SignRequest to the user's most recently active workstation that holds
// req.KeyBlob using the two-phase 1.5s SignAck receipt + 60s SignResponse approval protocol.
func (r *Registry) RouteSignRequest(ctx context.Context, userID string, req *sshcastv1.SignRequest) (*sshcastv1.SignResponse, error) {
	uh := r.getUserHub(userID)
	if uh == nil {
		return nil, ErrNoWorkstationConnected
	}

	uh.mu.Lock()
	candidates := uh.sortedCandidatesForKeyLocked(req.GetKeyBlob())
	if len(candidates) == 0 {
		uh.mu.Unlock()
		return nil, ErrNoWorkstationConnected
	}
	if r.limits.MaxPendingSignsPerUser > 0 && len(uh.pending) >= r.limits.MaxPendingSignsPerUser {
		uh.mu.Unlock()
		return nil, ErrTooManyPendingSigns
	}

	p := &pendingSignRequest{
		req:           req,
		ackCh:         make(chan string, 8),
		respCh:        make(chan *sshcastv1.SignResponse, 4),
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
				ws.TrySend(&sshcastv1.ServerStreamMessage{
					Payload: &sshcastv1.ServerStreamMessage_CancelSignRequest{
						CancelSignRequest: &sshcastv1.CancelSignRequest{
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
		sent := ws.TrySend(&sshcastv1.ServerStreamMessage{
			Payload: &sshcastv1.ServerStreamMessage_SignRequest{
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

		tPush := time.Now()
		log.Printf("[hub] Pushed SignRequest %s to workstation %s (candidates=%d)", req.GetRequestId(), ws.NodeID, len(candidates))
		ackTimer := time.NewTimer(r.signAckTimeout)
		select {
		case <-ctx.Done():
			ackTimer.Stop()
			return nil, ctx.Err()
		case resp := <-p.respCh:
			ackTimer.Stop()
			winningNodeID = resp.GetHandledByNodeId()
			log.Printf("[hub] Immediate SignResponse received for %s from %s in %dms", req.GetRequestId(), winningNodeID, time.Since(tPush).Milliseconds())
			return resp, nil
		case ackNode := <-p.ackCh:
			ackTimer.Stop()
			log.Printf("[hub] SignAck received for request %s from workstation %s in %dms", req.GetRequestId(), ackNode, time.Since(tPush).Milliseconds())
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
	// If multiple candidate workstations are available and the first workstation does not respond
	// within cascadeInterval, step to the next unprompted candidate while keeping all notified
	// workstations in p.promptedNodes so CancelSignRequest is always emitted to non-winning clients.
	approvalTimer := time.NewTimer(r.signResponseTimeout)
	defer approvalTimer.Stop()

	cascadeInterval := r.signResponseTimeout / 4
	if cascadeInterval > 10*time.Second {
		cascadeInterval = 10 * time.Second
	}
	if cascadeInterval < 50*time.Millisecond {
		cascadeInterval = 50 * time.Millisecond
	}
	cascadeTimer := time.NewTimer(cascadeInterval)
	defer cascadeTimer.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case resp := <-p.respCh:
			winningNodeID = resp.GetHandledByNodeId()
			return resp, nil
		case <-approvalTimer.C:
			return nil, ErrSignApprovalTimedOut
		case <-cascadeTimer.C:
			uh.mu.Lock()
			reqKey := req.GetKeyBlob()
			anyHasKey := uh.anyWorkstationHasKeyLocked(reqKey)
			promptedNext := false
			for _, ws := range uh.sortedCandidatesForKeyLocked(reqKey) {
				if _, already := p.promptedNodes[ws.NodeID]; already {
					continue
				}
				if anyHasKey && !ws.HasKeyBlob(reqKey) {
					continue
				}
				if ws.TrySend(&sshcastv1.ServerStreamMessage{
					Payload: &sshcastv1.ServerStreamMessage_SignRequest{
						SignRequest: req,
					},
				}) {
					p.promptedNodes[ws.NodeID] = ws.LastInputEpochMs
					if ws.LastInputEpochMs > p.highestInputSeen {
						p.highestInputSeen = ws.LastInputEpochMs
					}
					log.Printf("[hub] Cascaded SignRequest %s to next workstation %s", req.GetRequestId(), ws.NodeID)
					promptedNext = true
					break
				}
			}
			uh.mu.Unlock()
			if promptedNext {
				cascadeTimer.Reset(cascadeInterval)
			}
		}
	}
}

// RegisterRelay registers a connected relay stream (Zellij service enabled) for userID.
// If an older session with the same nodeID exists, it is closed and replaced without counting against MaxRelaysPerUser.
func (r *Registry) RegisterRelay(userID, nodeID string) (*RelaySession, error) {
	uh, err := r.getOrCreateAndLockUserHub(userID)
	if err != nil {
		return nil, err
	}
	defer uh.mu.Unlock()

	if old, exists := uh.relays[nodeID]; exists {
		select {
		case <-old.DoneCh:
		default:
			close(old.DoneCh)
		}
	} else if r.limits.MaxRelaysPerUser > 0 && len(uh.relays) >= r.limits.MaxRelaysPerUser {
		return nil, ErrTooManyRelays
	}

	rs := &RelaySession{
		UserID:      userID,
		NodeID:      nodeID,
		ConnectedAt: time.Now(),
		SendCh:      make(chan *sshcastv1.ServerToRelayMessage, 2048),
		DoneCh:      make(chan struct{}),
	}
	uh.relays[nodeID] = rs
	return rs, nil
}

// UnregisterRelay removes the relay session if it matches rs and broadcasts the updated ZellijHostList.
func (r *Registry) UnregisterRelay(rs *RelaySession) {
	if rs == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	uh, ok := r.users[rs.UserID]
	if !ok {
		return
	}
	uh.mu.Lock()
	defer uh.mu.Unlock()

	current, exists := uh.relays[rs.NodeID]
	if exists && current == rs {
		delete(uh.relays, rs.NodeID)
		select {
		case <-rs.DoneCh:
		default:
			close(rs.DoneCh)
		}
		uh.broadcastZellijHostListLocked()
		if len(uh.workstations) == 0 && len(uh.relays) == 0 && len(uh.pending) == 0 && len(uh.cachedKeys) == 0 {
			delete(r.users, rs.UserID)
		}
	}
}

func (uh *UserHub) buildZellijHostListLocked() *sshcastv1.ZellijHostList {
	hosts := make([]*sshcastv1.RelayZellijStatus, 0, len(uh.relays))
	for _, rs := range uh.relays {
		if rs.Status != nil && rs.Status.GetZellijEnabled() {
			hosts = append(hosts, rs.Status)
		}
	}
	sort.Slice(hosts, func(i, j int) bool {
		return hosts[i].GetNodeId() < hosts[j].GetNodeId()
	})
	return &sshcastv1.ZellijHostList{Hosts: hosts}
}

func (uh *UserHub) broadcastZellijHostListLocked() {
	list := uh.buildZellijHostListLocked()
	msg := &sshcastv1.ServerStreamMessage{
		Payload: &sshcastv1.ServerStreamMessage_ZellijHostList{
			ZellijHostList: list,
		},
	}
	for _, ws := range uh.workstations {
		ws.TrySend(msg)
	}
}

// UpdateRelayZellijStatus updates the Zellij session discovery status for a connected relay and notifies workstations.
func (r *Registry) UpdateRelayZellijStatus(rs *RelaySession, status *sshcastv1.RelayZellijStatus) {
	if rs == nil || status == nil {
		return
	}
	uh := r.getUserHub(rs.UserID)
	if uh == nil {
		return
	}
	uh.mu.Lock()
	defer uh.mu.Unlock()

	if cur, ok := uh.relays[rs.NodeID]; !ok || cur != rs {
		return
	}

	clonedSessions := make([]*sshcastv1.ZellijSessionInfo, len(status.GetSessions()))
	copy(clonedSessions, status.GetSessions())
	rs.Status = &sshcastv1.RelayZellijStatus{
		NodeId:          rs.NodeID,
		ZellijEnabled:   status.GetZellijEnabled(),
		Sessions:        clonedSessions,
		UpdatedAtUnixMs: status.GetUpdatedAtUnixMs(),
	}
	uh.broadcastZellijHostListLocked()
}

// SendZellijHostsToWorkstation sends the current ZellijHostList to ws and optionally asks connected relays to refresh.
func (r *Registry) SendZellijHostsToWorkstation(ws *WorkstationSession, askRelaysToRefresh bool) {
	if ws == nil {
		return
	}
	uh := r.getUserHub(ws.UserID)
	if uh == nil {
		return
	}
	uh.mu.Lock()
	defer uh.mu.Unlock()

	list := uh.buildZellijHostListLocked()
	if askRelaysToRefresh || len(list.GetHosts()) > 0 {
		ws.TrySend(&sshcastv1.ServerStreamMessage{
			Payload: &sshcastv1.ServerStreamMessage_ZellijHostList{
				ZellijHostList: list,
			},
		})
	}

	if askRelaysToRefresh {
		refreshMsg := &sshcastv1.ServerToRelayMessage{
			Payload: &sshcastv1.ServerToRelayMessage_RefreshSessions{
				RefreshSessions: true,
			},
		}
		for _, rs := range uh.relays {
			rs.TrySend(refreshMsg)
		}
	}
}

func shortHostLabel(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if idx := strings.IndexByte(s, '.'); idx > 0 {
		return s[:idx]
	}
	return s
}

func (uh *UserHub) findRelayLocked(target string) *RelaySession {
	if rs, ok := uh.relays[target]; ok {
		return rs
	}
	targetLower := strings.ToLower(strings.TrimSpace(target))
	for _, rs := range uh.relays {
		if strings.EqualFold(rs.NodeID, targetLower) {
			return rs
		}
	}
	targetShort := shortHostLabel(targetLower)
	for _, rs := range uh.relays {
		if shortHostLabel(rs.NodeID) == targetShort {
			return rs
		}
	}
	return nil
}

// RouteZellijFrameFromClient routes a ZellijTunnelFrame from a workstation to the target relay.
func (r *Registry) RouteZellijFrameFromClient(userID, clientNodeID string, frame *sshcastv1.ZellijTunnelFrame) {
	if frame == nil {
		return
	}
	uh := r.getUserHub(userID)
	if uh == nil {
		return
	}
	uh.mu.Lock()
	frame.ClientNodeId = clientNodeID
	rs := uh.findRelayLocked(frame.GetRelayNodeId())
	if rs == nil {
		ws := uh.workstations[clientNodeID]
		uh.mu.Unlock()
		if frame.GetFrameType() == sshcastv1.ZellijFrameType_ZELLIJ_FRAME_TYPE_OPEN && ws != nil {
			ws.SendReliable(&sshcastv1.ServerStreamMessage{
				Payload: &sshcastv1.ServerStreamMessage_ZellijFrame{
					ZellijFrame: &sshcastv1.ZellijTunnelFrame{
						TunnelId:     frame.GetTunnelId(),
						RelayNodeId:  frame.GetRelayNodeId(),
						ClientNodeId: clientNodeID,
						FrameType:    sshcastv1.ZellijFrameType_ZELLIJ_FRAME_TYPE_CLOSE,
						ErrorMessage: fmt.Sprintf("relay %q is not online with Zellij enabled", frame.GetRelayNodeId()),
					},
				},
			})
		}
		return
	}

	frame.RelayNodeId = rs.NodeID
	uh.mu.Unlock()
	rs.SendReliable(&sshcastv1.ServerToRelayMessage{
		Payload: &sshcastv1.ServerToRelayMessage_ZellijFrame{
			ZellijFrame: frame,
		},
	})
}

// RouteZellijFrameFromRelay routes a ZellijTunnelFrame from a relay to the target workstation.
func (r *Registry) RouteZellijFrameFromRelay(userID, relayNodeID string, frame *sshcastv1.ZellijTunnelFrame) {
	if frame == nil {
		return
	}
	uh := r.getUserHub(userID)
	if uh == nil {
		return
	}
	uh.mu.Lock()
	frame.RelayNodeId = relayNodeID
	ws, ok := uh.workstations[frame.GetClientNodeId()]
	uh.mu.Unlock()
	if !ok {
		return
	}
	ws.SendReliable(&sshcastv1.ServerStreamMessage{
		Payload: &sshcastv1.ServerStreamMessage_ZellijFrame{
			ZellijFrame: frame,
		},
	})
}
