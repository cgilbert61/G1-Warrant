package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// SSEEvent represents a typed real-time state update pushed to Console subscribers.
type SSEEvent struct {
	Type      string    `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	Payload   any       `json:"payload"`
}

// SSEBroker manages real-time Server-Sent Events subscriptions.
type SSEBroker struct {
	mu      sync.RWMutex
	clients map[chan []byte]struct{}
}

// NewSSEBroker creates a new SSEBroker.
func NewSSEBroker() *SSEBroker {
	return &SSEBroker{
		clients: make(map[chan []byte]struct{}),
	}
}

// Broadcast serializes an SSEEvent and pushes it non-blockingly to all connected clients.
func (b *SSEBroker) Broadcast(eventType string, payload any) {
	evt := SSEEvent{
		Type:      eventType,
		Timestamp: time.Now().UTC(),
		Payload:   payload,
	}
	raw, err := json.Marshal(evt)
	if err != nil {
		return
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	for ch := range b.clients {
		select {
		case ch <- raw:
		default:
		}
	}
}

// ServeHTTP streams real-time SSE events with 15-second keepalive comments.
func (b *SSEBroker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch := make(chan []byte, 64)
	b.mu.Lock()
	b.clients[ch] = struct{}{}
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.clients, ch)
		b.mu.Unlock()
	}()

	_, _ = fmt.Fprintf(w, "event: connected\ndata: {\"status\":\"STREAM_ACTIVE\"}\n\n")
	flusher.Flush()

	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-keepalive.C:
			_, _ = fmt.Fprintf(w, ": heartbeat %d\n\n", time.Now().UTC().Unix())
			flusher.Flush()
		case msg := <-ch:
			_, _ = fmt.Fprintf(w, "data: %s\n\n", string(msg))
			flusher.Flush()
		}
	}
}
