package shadowagent

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

// Multiplexer serves several explicitly provisioned mailbox repositories on
// one provider endpoint. The request's full target tuple selects only among
// the immutable configured handlers; it can never construct a repository or
// provider session from caller input.
type Multiplexer struct {
	auth    *Handler
	targets map[target]*Handler
}

func NewMultiplexer(handlers ...*Handler) (*Multiplexer, error) {
	if len(handlers) == 0 {
		return nil, errors.New("shadow agent: at least one mailbox handler is required")
	}
	mux := &Multiplexer{auth: handlers[0], targets: make(map[target]*Handler, len(handlers))}
	for _, handler := range handlers {
		if handler == nil || handler.tokenHash != mux.auth.tokenHash {
			return nil, errors.New("shadow agent: multiplexed handlers require one exact relay token")
		}
		configured := handler.targetView()
		if _, duplicate := mux.targets[configured]; duplicate {
			return nil, errors.New("shadow agent: duplicate multiplexed target")
		}
		mux.targets[configured] = handler
	}
	return mux, nil
}

func (m *Multiplexer) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	if request.Method != http.MethodPost {
		response.Header().Set("Allow", "POST")
		http.Error(response, `{"error":"MethodNotAllowed"}`, http.StatusMethodNotAllowed)
		return
	}
	if !m.auth.authorized(request.Header.Get("Authorization")) {
		http.Error(response, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}
	request.Body = http.MaxBytesReader(response, request.Body, maxRequestBytes)
	body, err := io.ReadAll(request.Body)
	if err != nil {
		http.Error(response, `{"error":"InvalidTarget"}`, http.StatusBadRequest)
		return
	}
	var envelope struct {
		Target target `json:"target"`
	}
	// Decode only into the routing envelope without rejecting other fields:
	// endpoint-specific fields are intentionally validated by the selected
	// handler's strict decoder below.
	if err := json.Unmarshal(body, &envelope); err != nil {
		http.Error(response, `{"error":"InvalidTarget"}`, http.StatusBadRequest)
		return
	}
	handler := m.targets[envelope.Target]
	if handler == nil {
		http.Error(response, `{"error":"InvalidTarget"}`, http.StatusBadRequest)
		return
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	handler.ServeHTTP(response, request)
}
