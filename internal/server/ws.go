package server

import (
	"context"
	"log"
	"net/http"
	"sync"

	sockcastv1 "github.com/theraphim/sockcast-proto/gen/go/sockcast/v1"
	"golang.org/x/net/websocket"
	"google.golang.org/protobuf/proto"
)

type wsWorkstationStream struct {
	ctx    context.Context
	conn   *websocket.Conn
	sendMu sync.Mutex
}

func (w *wsWorkstationStream) Context() context.Context {
	return w.ctx
}

func (w *wsWorkstationStream) Send(msg *sockcastv1.ServerStreamMessage) error {
	raw, err := proto.Marshal(msg)
	if err != nil {
		return err
	}
	w.sendMu.Lock()
	defer w.sendMu.Unlock()
	return websocket.Message.Send(w.conn, raw)
}

func (w *wsWorkstationStream) Recv() (*sockcastv1.ClientStreamMessage, error) {
	var raw []byte
	if err := websocket.Message.Receive(w.conn, &raw); err != nil {
		return nil, err
	}
	msg := &sockcastv1.ClientStreamMessage{}
	if err := proto.Unmarshal(raw, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

// WorkstationWebSocketHandler returns an http.Handler that upgrades HTTP GET /ws/workstation
// connections to binary WebSocket streams speaking Protobuf ClientStreamMessage / ServerStreamMessage.
// This allows the browser WASM workstation client to connect through standard HTTPS/WSS proxies.
func (s *SockcastServer) WorkstationWebSocketHandler() http.Handler {
	wsServer := websocket.Server{
		Handshake: func(cfg *websocket.Config, r *http.Request) error {
			// Accept browser WebSocket connections regardless of Origin header, since
			// authentication is enforced cryptographically via Ed25519 NodeAuth handshake.
			return nil
		},
		Handler: func(conn *websocket.Conn) {
			conn.PayloadType = websocket.BinaryFrame
			defer func() {
				_ = conn.Close()
			}()
			stream := &wsWorkstationStream{
				ctx:  conn.Request().Context(),
				conn: conn,
			}
			if err := s.serveWorkstationStream(stream, "ws"); err != nil {
				log.Printf("[ws] Workstation stream ended with error: %v", err)
			}
		},
	}
	return wsServer
}
