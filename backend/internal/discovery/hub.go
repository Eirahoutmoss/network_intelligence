package discovery

import "sync"

// Message is a live update for a discovery run.
type Message struct {
	RunID   int64          `json:"run_id"`
	Step    *Step          `json:"step,omitempty"`
	Status  string         `json:"status,omitempty"` // set when the run changes state
	Summary map[string]any `json:"summary,omitempty"`
}

// Hub fans out run updates to subscribers (SSE clients).
type Hub struct {
	mu   sync.Mutex
	subs map[int64]map[chan Message]struct{}
}

func NewHub() *Hub { return &Hub{subs: map[int64]map[chan Message]struct{}{}} }

// Subscribe returns a channel of updates for runID and an unsubscribe func.
func (h *Hub) Subscribe(runID int64) (<-chan Message, func()) {
	ch := make(chan Message, 256)
	h.mu.Lock()
	if h.subs[runID] == nil {
		h.subs[runID] = map[chan Message]struct{}{}
	}
	h.subs[runID][ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		if _, ok := h.subs[runID][ch]; ok {
			delete(h.subs[runID], ch)
			close(ch)
		}
		h.mu.Unlock()
	}
}

// Publish delivers m without blocking; slow subscribers drop messages.
func (h *Hub) Publish(m Message) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs[m.RunID] {
		select {
		case ch <- m:
		default:
		}
	}
}
