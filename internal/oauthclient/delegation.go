package oauthclient

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

const (
	delegationEndpoint         = "com.atproto.space.getDelegationToken"
	maxDelegationResponseBytes = 16 * 1024
	maxDelegationTokenBytes    = 12 * 1024
)

var ErrDelegationConsumed = errors.New("oauthclient: delegation token already consumed")

// Delegation contains one short-lived, single-use official Spaces delegation.
// Its token is never exported, serialized, or included in formatted output.
type Delegation struct {
	mu    sync.Mutex
	token string
	used  bool
}

func (d *Delegation) String() string   { return "oauthclient.Delegation(redacted)" }
func (d *Delegation) GoString() string { return "oauthclient.Delegation{redacted}" }

// Use releases the token to one in-process exchange callback and clears the
// reference before invoking it. The callback itself must not log or persist it.
func (d *Delegation) Use(exchange func(token string) error) error {
	if d == nil || exchange == nil {
		return ErrDelegationConsumed
	}
	d.mu.Lock()
	if d.used || d.token == "" {
		d.mu.Unlock()
		return ErrDelegationConsumed
	}
	d.used = true
	token := d.token
	d.token = ""
	d.mu.Unlock()
	return exchange(token)
}

// MintDelegation asks the pinned member PDS for a delegation over the one
// exact mailbox configured into this OAuth session. No request input can
// select another DID, space type, key, or origin.
func (d *SessionDoer) MintDelegation(ctx context.Context) (*Delegation, error) {
	did, rkey, err := parseSteadyTarget(d.did, d.spaceKey)
	if err != nil {
		return nil, err
	}
	spaceURI := "at://" + did.String() + "/space/email.atmos.mailbox/" + rkey.String()
	target, err := url.Parse(d.origin + "/xrpc/" + delegationEndpoint)
	if err != nil {
		return nil, errors.New("oauthclient: construct delegation endpoint")
	}
	query := make(url.Values)
	query.Set("space", spaceURI)
	target.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("oauthclient: construct delegation request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	response, err := d.Do(ctx, request, delegationEndpoint)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oauthclient: delegation request failed with HTTP %d", response.StatusCode)
	}
	var output struct {
		Token string `json:"token"`
	}
	if err := decodeBoundedJSON(response.Body, maxDelegationResponseBytes, &output); err != nil {
		return nil, fmt.Errorf("oauthclient: invalid delegation response: %w", err)
	}
	if !validCompactJWT(output.Token, maxDelegationTokenBytes) {
		return nil, errors.New("oauthclient: delegation response contained an invalid token")
	}
	return &Delegation{token: output.Token}, nil
}

// WithDelegation mints one new single-use delegation and exposes it only to
// the supplied in-process credential exchange callback.
func (d *SessionDoer) WithDelegation(ctx context.Context, exchange func(token string) error) error {
	delegation, err := d.MintDelegation(ctx)
	if err != nil {
		return err
	}
	return delegation.Use(exchange)
}

func decodeBoundedJSON(body io.Reader, maximum int64, output any) error {
	data, err := io.ReadAll(io.LimitReader(body, maximum+1))
	if err != nil {
		return errors.New("read bounded JSON")
	}
	if int64(len(data)) > maximum {
		return errors.New("JSON response exceeded limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return errors.New("decode strict JSON")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("JSON response contained trailing data")
	}
	return nil
}

func validCompactJWT(token string, maximum int) bool {
	if token == "" || len(token) > maximum || strings.ContainsAny(token, " \t\r\n") {
		return false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		if _, err := base64.RawURLEncoding.DecodeString(part); err != nil {
			return false
		}
	}
	return true
}
