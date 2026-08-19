package shadowagent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

// RouteTarget is the credential-free exact target carried by the relay
// protocol. A resolving multiplexer must return a handler for this identical
// tuple; it cannot rewrite or broaden any field.
type RouteTarget = target

// Resolver verifies one exact target and constructs its request handler. It
// runs only after relay bearer authentication and before endpoint-specific
// strict decoding.
type Resolver func(context.Context, RouteTarget) (*Handler, error)

// Multiplexer serves exact mailbox repositories on one provider endpoint. A
// static instance selects only among immutable configured handlers; a
// resolving instance verifies the complete target before constructing a
// handler.
type Multiplexer struct {
	tokenHash [sha256.Size]byte
	targets   map[target]*Handler
	resolver  Resolver
}

func NewMultiplexer(handlers ...*Handler) (*Multiplexer, error) {
	if len(handlers) == 0 {
		return nil, errors.New("shadow agent: at least one mailbox handler is required")
	}
	mux := &Multiplexer{tokenHash: handlers[0].tokenHash, targets: make(map[target]*Handler, len(handlers))}
	for _, handler := range handlers {
		if handler == nil || handler.tokenHash != mux.tokenHash {
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

// NewResolvingMultiplexer admits exact targets through a fail-closed resolver
// instead of a static per-mailbox startup list. The returned handler must use
// the same relay token and must preserve the requested target byte-for-byte.
func NewResolvingMultiplexer(token string, resolver Resolver) (*Multiplexer, error) {
	if token == "" || len(token) > 16*1024 || strings.ContainsAny(token, "\r\n\x00") || resolver == nil {
		return nil, errors.New("shadow agent: exact bearer token and target resolver are required")
	}
	return &Multiplexer{tokenHash: sha256.Sum256([]byte(token)), resolver: resolver}, nil
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
	if !m.authorized(request.Header.Get("Authorization")) {
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
	if m.resolver != nil {
		handler, err = m.resolver(request.Context(), envelope.Target)
	}
	if err != nil || handler == nil || handler.tokenHash != m.tokenHash || handler.targetView() != envelope.Target {
		http.Error(response, `{"error":"InvalidTarget"}`, http.StatusBadRequest)
		return
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	handler.ServeHTTP(response, request)
}

func (m *Multiplexer) authorized(header string) bool {
	token := strings.TrimPrefix(header, "Bearer ")
	if token == header || token == "" {
		return false
	}
	presented := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(m.tokenHash[:], presented[:]) == 1
}
