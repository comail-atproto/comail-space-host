// Package onboardingbroker implements the production-dark browser handoff
// that acquires separate provisioning and steady official Spaces grants. It
// deliberately stops after grant verification and never activates authority.
package onboardingbroker

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/atproto/auth/oauth"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/comail-atproto/comail-space-host/internal/authvault"
	"github.com/comail-atproto/comail-space-host/internal/oauthclient"
)

const (
	statusReady                 = "ready"
	statusAuthorizationRequired = "authorization_required"
	statusRevoked               = "revoked"
	flowTTL                     = 15 * time.Minute
	maxStartBodyBytes           = 4096
	maxRevokeBodyBytes          = 4096
	fixedReturnURL              = "https://comail.at/webmail/login"
	maxRetiredSessions          = 16
	discardedCleanupTimeout     = 5 * time.Second
	revokeTimeout               = 30 * time.Second
	maxRevokeCASAttempts        = 8
)

var (
	ErrSteadyReauthorizationRequired = errors.New("onboardingbroker: steady grant requires reauthorization")
	errRevocationIncomplete          = errors.New("onboardingbroker: authorization revocation incomplete")
)

type Account struct {
	DID       string
	Handle    string
	PDSOrigin string
	SpaceKey  string
}

type Config struct {
	BrokerOrigin string
	RelayToken   string
	ReturnURL    string
	Accounts     []Account
	AllowHTTP    bool
}

type RecordStore interface {
	CreateRecord(context.Context, string, []byte, time.Time) error
	SetRecord(context.Context, string, []byte, time.Time) error
	GetRecord(context.Context, string) ([]byte, error)
	ConsumeRecord(context.Context, string) ([]byte, error)
	DeleteRecord(context.Context, string) error
	CompareAndSwapRecord(context.Context, string, []byte, []byte, time.Time) (bool, error)
	CompareAndDeleteRecord(context.Context, string, []byte) (bool, error)
}

type OAuthDriver interface {
	StartProvisioning(context.Context, Account) (oauthclient.StartResult, error)
	FinishProvisioning(context.Context, Account, url.Values) (string, error)
	RetireProvisioning(context.Context, Account, string) error
	StartSteady(context.Context, Account) (oauthclient.StartResult, error)
	FinishSteady(context.Context, Account, url.Values) (string, error)
	CheckSteady(context.Context, Account, string) error
	RetireSteady(context.Context, Account, string) error
	ClientMetadata(string) (oauth.ClientMetadata, bool)
}

type Handler struct {
	origin     string
	relayToken string
	returnURL  string
	accounts   []Account
	store      RecordStore
	driver     OAuthDriver
	now        func() time.Time
}

type startRequest struct {
	Version int    `json:"version"`
	DID     string `json:"did"`
	Handle  string `json:"handle"`
}

type startResponse struct {
	Version          int    `json:"version"`
	Status           string `json:"status"`
	AuthorizationURL string `json:"authorizationUrl,omitempty"`
}

type revokeRequest struct {
	Version int    `json:"version"`
	DID     string `json:"did"`
}

type revokeResponse struct {
	Version int    `json:"version"`
	Status  string `json:"status"`
}

type flowRecord struct {
	Version            int    `json:"version"`
	AccountFingerprint string `json:"accountFingerprint"`
}

type readyRecord struct {
	Version            int      `json:"version"`
	AccountFingerprint string   `json:"accountFingerprint"`
	SessionID          string   `json:"sessionId"`
	RetiredSessionIDs  []string `json:"retiredSessionIds,omitempty"`
}

// discardedRecord retains every newly issued steady session that failed its
// first live proof. It is separate from readyRecord because an account may not
// have an active session yet. Empty records are deliberately retained: CAS can
// then safely race a callback adding another cleanup handle without an unsafe
// read-then-delete window.
type discardedRecord struct {
	Version            int      `json:"version"`
	AccountFingerprint string   `json:"accountFingerprint"`
	SessionIDs         []string `json:"sessionIds"`
}

func New(config Config, store RecordStore, driver OAuthDriver) (*Handler, error) {
	origin, err := cleanBrokerOrigin(config.BrokerOrigin, config.AllowHTTP)
	if err != nil {
		return nil, err
	}
	if len(config.RelayToken) < 24 || strings.TrimSpace(config.RelayToken) != config.RelayToken || strings.ContainsAny(config.RelayToken, "\r\n\x00") {
		return nil, errors.New("onboardingbroker: bounded relay bearer is required")
	}
	if config.ReturnURL != fixedReturnURL {
		return nil, errors.New("onboardingbroker: return URL must be the fixed Comail webmail login")
	}
	if store == nil || driver == nil {
		return nil, errors.New("onboardingbroker: encrypted store and OAuth driver are required")
	}
	if len(config.Accounts) == 0 || len(config.Accounts) > 1024 {
		return nil, errors.New("onboardingbroker: explicit account allowlist is required")
	}
	seen := make(map[string]struct{}, len(config.Accounts))
	accounts := append([]Account(nil), config.Accounts...)
	for _, account := range accounts {
		if err := validateAccount(account); err != nil {
			return nil, err
		}
		key := account.DID
		if _, duplicate := seen[key]; duplicate {
			return nil, errors.New("onboardingbroker: duplicate allowlisted account")
		}
		seen[key] = struct{}{}
	}
	return &Handler{
		origin: origin, relayToken: config.RelayToken, returnURL: config.ReturnURL,
		accounts: accounts, store: store, driver: driver, now: time.Now,
	}, nil
}

func (h *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	securityHeaders(response)
	switch {
	case request.Method == http.MethodPost && request.URL.Path == "/v1/onboarding/start":
		h.handleStart(response, request)
	case request.Method == http.MethodPost && request.URL.Path == "/v1/onboarding/revoke":
		h.handleRevoke(response, request)
	case request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, "/onboarding/"):
		h.handleBrowserEntry(response, request)
	case request.Method == http.MethodGet && request.URL.Path == "/oauth/provision/callback":
		h.handleProvisioningCallback(response, request)
	case request.Method == http.MethodGet && request.URL.Path == "/oauth/steady/callback":
		h.handleSteadyCallback(response, request)
	case request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, "/oauth/client/"):
		h.handleClientMetadata(response, request)
	default:
		http.NotFound(response, request)
	}
}

func (h *Handler) handleRevoke(response http.ResponseWriter, request *http.Request) {
	if !h.authorized(request.Header.Get("Authorization")) {
		response.Header().Set("WWW-Authenticate", `Bearer realm="comail-onboarding"`)
		writeProblem(response, http.StatusUnauthorized, "unauthorized")
		return
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeProblem(response, http.StatusUnsupportedMediaType, "JSON required")
		return
	}
	var input revokeRequest
	if err := decodeStrictBounded(request.Body, maxRevokeBodyBytes, &input); err != nil || input.Version != 1 {
		writeProblem(response, http.StatusBadRequest, "invalid request")
		return
	}
	accountIndex := h.accountIndexByDID(input.DID)
	if accountIndex < 0 {
		writeProblem(response, http.StatusForbidden, "account is not enabled")
		return
	}
	account := h.accounts[accountIndex]
	ctx, cancel := context.WithTimeout(request.Context(), revokeTimeout)
	defer cancel()
	readyErr := h.revokeReadyState(ctx, account)
	discardedErr := h.revokeDiscardedState(ctx, account)
	provisioningErr := h.revokeProvisioningDiscardedState(ctx, account)
	combined := errors.Join(readyErr, discardedErr, provisioningErr)
	if combined != nil {
		if errors.Is(combined, errRevocationIncomplete) {
			writeProblem(response, http.StatusServiceUnavailable, "authorization revocation incomplete")
		} else {
			writeProblem(response, http.StatusInternalServerError, "authorization state is unavailable")
		}
		return
	}
	writeJSON(response, http.StatusOK, revokeResponse{Version: 1, Status: statusRevoked})
}

func (h *Handler) handleStart(response http.ResponseWriter, request *http.Request) {
	if !h.authorized(request.Header.Get("Authorization")) {
		response.Header().Set("WWW-Authenticate", `Bearer realm="comail-onboarding"`)
		writeProblem(response, http.StatusUnauthorized, "unauthorized")
		return
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeProblem(response, http.StatusUnsupportedMediaType, "JSON required")
		return
	}
	var input startRequest
	if err := decodeStrictBounded(request.Body, maxStartBodyBytes, &input); err != nil || input.Version != 1 {
		writeProblem(response, http.StatusBadRequest, "invalid request")
		return
	}
	accountIndex := h.accountIndex(input.DID, input.Handle)
	if accountIndex < 0 {
		writeProblem(response, http.StatusForbidden, "account is not enabled")
		return
	}
	account := h.accounts[accountIndex]
	h.cleanupDiscarded(request.Context(), account)
	h.cleanupDiscardedProvisioning(request.Context(), account)
	readyName := readyRecordName(account.DID)
	if encoded, readyErr := h.store.GetRecord(request.Context(), readyName); readyErr == nil {
		var ready readyRecord
		if decodeRecord(encoded, &ready) != nil || !validReadyRecord(ready, account) {
			writeProblem(response, http.StatusInternalServerError, "authorization state is unavailable")
			return
		}
		checkErr := h.driver.CheckSteady(request.Context(), account, ready.SessionID)
		if checkErr == nil {
			h.cleanupRetired(request.Context(), readyName, encoded, account, ready)
			writeJSON(response, http.StatusOK, startResponse{Version: 1, Status: statusReady})
			return
		}
		if !errors.Is(checkErr, ErrSteadyReauthorizationRequired) {
			// A provider/network failure is not evidence that the grant is gone.
			// Retain the only revocation handle and ask the relay to retry later.
			writeProblem(response, http.StatusServiceUnavailable, "authorization provider unavailable")
			return
		}
		if len(ready.RetiredSessionIDs) >= maxRetiredSessions {
			writeProblem(response, http.StatusServiceUnavailable, "authorization cleanup required")
			return
		}
	} else if !errors.Is(readyErr, authvault.ErrNotFound) {
		writeProblem(response, http.StatusInternalServerError, "authorization state is unavailable")
		return
	}

	token, err := randomToken()
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "unable to start authorization")
		return
	}
	flow := flowRecord{Version: 1, AccountFingerprint: accountFingerprint(account)}
	encoded, err := json.Marshal(flow)
	if err != nil || h.store.CreateRecord(request.Context(), recordName("entry", token), encoded, h.now().UTC().Add(flowTTL)) != nil {
		writeProblem(response, http.StatusInternalServerError, "unable to start authorization")
		return
	}
	writeJSON(response, http.StatusOK, startResponse{
		Version: 1, Status: statusAuthorizationRequired, AuthorizationURL: h.origin + "/onboarding/" + token,
	})
}

func (h *Handler) handleBrowserEntry(response http.ResponseWriter, request *http.Request) {
	token := strings.TrimPrefix(request.URL.Path, "/onboarding/")
	if request.URL.RawQuery != "" || request.URL.Fragment != "" || strings.Contains(token, "/") || !validToken(token) {
		http.NotFound(response, request)
		return
	}
	encoded, err := h.store.ConsumeRecord(request.Context(), recordName("entry", token))
	if err != nil {
		writeProblem(response, http.StatusGone, "authorization link expired")
		return
	}
	flow, account, err := h.decodeFlow(encoded)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid authorization flow")
		return
	}
	started, err := h.driver.StartProvisioning(request.Context(), account)
	if err != nil || h.validateOAuthStart(account, started) != nil {
		writeProblem(response, http.StatusBadGateway, "authorization provider unavailable")
		return
	}
	if err := h.saveOAuthFlow(request.Context(), "provision", started.State, flow); err != nil {
		writeProblem(response, http.StatusInternalServerError, "unable to persist authorization")
		return
	}
	http.Redirect(response, request, started.AuthorizationURL, http.StatusSeeOther)
}

func (h *Handler) handleProvisioningCallback(response http.ResponseWriter, request *http.Request) {
	values, flow, account, ok := h.consumeCallback(response, request, "provision")
	if !ok {
		return
	}
	sessionID, err := h.driver.FinishProvisioning(request.Context(), account, values)
	if err != nil {
		if sessionID != "" {
			if !validSessionID(sessionID) || h.enqueueDiscardedProvisioning(request.Context(), account, sessionID) != nil {
				writeProblem(response, http.StatusInternalServerError, "unable to retain rejected authorization")
				return
			}
			h.cleanupDiscardedProvisioning(request.Context(), account)
		}
		writeProblem(response, http.StatusBadRequest, "provisioning authorization rejected")
		return
	}
	started, err := h.driver.StartSteady(request.Context(), account)
	if err != nil || h.validateOAuthStart(account, started) != nil {
		writeProblem(response, http.StatusBadGateway, "steady authorization unavailable")
		return
	}
	if err := h.saveOAuthFlow(request.Context(), "steady", started.State, flow); err != nil {
		writeProblem(response, http.StatusInternalServerError, "unable to persist authorization")
		return
	}
	http.Redirect(response, request, started.AuthorizationURL, http.StatusSeeOther)
}

func (h *Handler) handleSteadyCallback(response http.ResponseWriter, request *http.Request) {
	values, _, account, ok := h.consumeCallback(response, request, "steady")
	if !ok {
		return
	}
	sessionID, err := h.driver.FinishSteady(request.Context(), account, values)
	if err != nil {
		if validSessionID(sessionID) {
			if queueErr := h.enqueueDiscarded(request.Context(), account, sessionID); queueErr != nil {
				writeProblem(response, http.StatusInternalServerError, "unable to retain rejected authorization")
				return
			}
			h.cleanupDiscarded(request.Context(), account)
		}
		writeProblem(response, http.StatusBadRequest, "steady authorization rejected")
		return
	}
	if !validSessionID(sessionID) {
		writeProblem(response, http.StatusBadRequest, "steady authorization rejected")
		return
	}
	readyName := readyRecordName(account.DID)
	if err := h.replaceReadySession(request.Context(), readyName, account, sessionID); err != nil {
		writeProblem(response, http.StatusInternalServerError, "unable to persist authorization")
		return
	}
	http.Redirect(response, request, h.returnURL, http.StatusSeeOther)
}

func (h *Handler) handleClientMetadata(response http.ResponseWriter, request *http.Request) {
	if request.URL.RawQuery != "" {
		http.NotFound(response, request)
		return
	}
	metadata, ok := h.driver.ClientMetadata(request.URL.Path)
	if !ok || metadata.ClientID != h.origin+request.URL.Path || len(metadata.RedirectURIs) != 1 ||
		(metadata.RedirectURIs[0] != h.origin+"/oauth/provision/callback" && metadata.RedirectURIs[0] != h.origin+"/oauth/steady/callback") {
		http.NotFound(response, request)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(response).Encode(metadata)
}

func (h *Handler) consumeCallback(response http.ResponseWriter, request *http.Request, stage string) (url.Values, flowRecord, Account, bool) {
	values := request.URL.Query()
	if !validCallbackValues(values) {
		writeProblem(response, http.StatusBadRequest, "invalid OAuth callback")
		return nil, flowRecord{}, Account{}, false
	}
	state := values.Get("state")
	encoded, err := h.store.ConsumeRecord(request.Context(), recordName(stage, state))
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid OAuth callback")
		return nil, flowRecord{}, Account{}, false
	}
	flow, account, err := h.decodeFlow(encoded)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid OAuth callback")
		return nil, flowRecord{}, Account{}, false
	}
	return values, flow, account, true
}

func (h *Handler) saveOAuthFlow(ctx context.Context, stage, state string, flow flowRecord) error {
	if state == "" || len(state) > 1024 || strings.ContainsAny(state, "\r\n\x00") {
		return errors.New("onboardingbroker: invalid OAuth state")
	}
	encoded, err := json.Marshal(flow)
	if err != nil {
		return err
	}
	return h.store.CreateRecord(ctx, recordName(stage, state), encoded, h.now().UTC().Add(flowTTL))
}

func (h *Handler) validateOAuthStart(account Account, started oauthclient.StartResult) error {
	if started.State == "" || started.AuthorizationURL == "" {
		return errors.New("onboardingbroker: incomplete OAuth start")
	}
	target, err := url.Parse(started.AuthorizationURL)
	if err != nil || !sameOrigin(target, account.PDSOrigin) || target.Scheme != "https" || target.User != nil || target.Fragment != "" {
		return errors.New("onboardingbroker: OAuth authorization escaped exact PDS")
	}
	return nil
}

func (h *Handler) decodeFlow(encoded []byte) (flowRecord, Account, error) {
	var flow flowRecord
	if err := decodeRecord(encoded, &flow); err != nil || flow.Version != 1 || flow.AccountFingerprint == "" {
		return flowRecord{}, Account{}, errors.New("onboardingbroker: invalid encrypted flow")
	}
	for _, account := range h.accounts {
		if accountFingerprint(account) == flow.AccountFingerprint {
			return flow, account, nil
		}
	}
	return flowRecord{}, Account{}, errors.New("onboardingbroker: encrypted flow target is no longer configured")
}

func validReadyRecord(ready readyRecord, account Account) bool {
	if ready.Version != 1 || ready.AccountFingerprint != accountFingerprint(account) ||
		!validSessionID(ready.SessionID) ||
		len(ready.RetiredSessionIDs) > maxRetiredSessions {
		return false
	}
	seen := map[string]struct{}{ready.SessionID: {}}
	for _, sessionID := range ready.RetiredSessionIDs {
		if !validSessionID(sessionID) {
			return false
		}
		if _, duplicate := seen[sessionID]; duplicate {
			return false
		}
		seen[sessionID] = struct{}{}
	}
	return true
}

func validDiscardedRecord(discarded discardedRecord, account Account) bool {
	if discarded.Version != 1 || discarded.AccountFingerprint != accountFingerprint(account) || len(discarded.SessionIDs) > maxRetiredSessions {
		return false
	}
	seen := make(map[string]struct{}, len(discarded.SessionIDs))
	for _, sessionID := range discarded.SessionIDs {
		if !validSessionID(sessionID) {
			return false
		}
		if _, duplicate := seen[sessionID]; duplicate {
			return false
		}
		seen[sessionID] = struct{}{}
	}
	return true
}

func validSessionID(sessionID string) bool {
	return sessionID != "" && len(sessionID) <= 1024 && !strings.ContainsAny(sessionID, "\r\n\x00")
}

func (h *Handler) replaceReadySession(ctx context.Context, name string, account Account, sessionID string) error {
	for attempt := 0; attempt < 8; attempt++ {
		var previousEncoded []byte
		var previous readyRecord
		encoded, err := h.store.GetRecord(ctx, name)
		if err == nil {
			if decodeRecord(encoded, &previous) != nil || !validReadyRecord(previous, account) {
				return errors.New("onboardingbroker: existing ready state is invalid")
			}
			previousEncoded = encoded
		} else if !errors.Is(err, authvault.ErrNotFound) {
			return err
		}
		retired := append([]string(nil), previous.RetiredSessionIDs...)
		if previous.SessionID != "" && previous.SessionID != sessionID {
			retired = append(retired, previous.SessionID)
		}
		retired = uniqueSessionIDs(retired, sessionID)
		if len(retired) > maxRetiredSessions {
			return errors.New("onboardingbroker: retired OAuth session bound exceeded")
		}
		next := readyRecord{
			Version: 1, AccountFingerprint: accountFingerprint(account),
			SessionID: sessionID, RetiredSessionIDs: retired,
		}
		nextEncoded, err := json.Marshal(next)
		if err != nil {
			return err
		}
		swapped, err := h.store.CompareAndSwapRecord(ctx, name, previousEncoded, nextEncoded, time.Time{})
		if err != nil {
			return err
		}
		if !swapped {
			continue
		}
		h.cleanupRetired(ctx, name, nextEncoded, account, next)
		return nil
	}
	return errors.New("onboardingbroker: ready session changed concurrently")
}

func (h *Handler) cleanupRetired(ctx context.Context, name string, encoded []byte, account Account, ready readyRecord) {
	if len(ready.RetiredSessionIDs) == 0 {
		return
	}
	remaining := make([]string, 0, len(ready.RetiredSessionIDs))
	for _, sessionID := range ready.RetiredSessionIDs {
		if err := h.driver.RetireSteady(ctx, account, sessionID); err != nil {
			remaining = append(remaining, sessionID)
		}
	}
	if len(remaining) == len(ready.RetiredSessionIDs) {
		return
	}
	ready.RetiredSessionIDs = remaining
	replacement, err := json.Marshal(ready)
	if err != nil {
		return
	}
	_, _ = h.store.CompareAndSwapRecord(ctx, name, encoded, replacement, time.Time{})
}

// revokeReadyState revokes the active and every retired steady session from
// one exact snapshot. It deletes the durable record only after every remote
// revocation in that snapshot is confirmed and a CAS proves the record was not
// replaced while those network calls were in flight.
func (h *Handler) revokeReadyState(ctx context.Context, account Account) error {
	name := readyRecordName(account.DID)
	for attempt := 0; attempt < maxRevokeCASAttempts; attempt++ {
		encoded, err := h.store.GetRecord(ctx, name)
		if errors.Is(err, authvault.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		var ready readyRecord
		if decodeRecord(encoded, &ready) != nil || !validReadyRecord(ready, account) {
			return errors.New("onboardingbroker: ready authorization state is invalid")
		}
		sessions := make([]string, 0, 1+len(ready.RetiredSessionIDs))
		sessions = append(sessions, ready.SessionID)
		sessions = append(sessions, ready.RetiredSessionIDs...)
		if err := h.retireSessions(ctx, account, sessions); err != nil {
			return errors.Join(errRevocationIncomplete, err)
		}
		deleted, err := h.store.CompareAndDeleteRecord(ctx, name, encoded)
		if err != nil {
			return err
		}
		if deleted {
			return nil
		}
	}
	return errRevocationIncomplete
}

// revokeDiscardedState applies the same remote-confirmation and CAS-delete
// rule to steady sessions that failed their first live proof. The record may
// be concurrently appended by another callback; a stale snapshot therefore
// never deletes the replacement.
func (h *Handler) revokeDiscardedState(ctx context.Context, account Account) error {
	name := discardedRecordName(account.DID)
	for attempt := 0; attempt < maxRevokeCASAttempts; attempt++ {
		encoded, err := h.store.GetRecord(ctx, name)
		if errors.Is(err, authvault.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		var discarded discardedRecord
		if decodeRecord(encoded, &discarded) != nil || !validDiscardedRecord(discarded, account) {
			return errors.New("onboardingbroker: discarded authorization state is invalid")
		}
		if err := h.retireSessions(ctx, account, discarded.SessionIDs); err != nil {
			return errors.Join(errRevocationIncomplete, err)
		}
		deleted, err := h.store.CompareAndDeleteRecord(ctx, name, encoded)
		if err != nil {
			return err
		}
		if deleted {
			return nil
		}
	}
	return errRevocationIncomplete
}

// revokeProvisioningDiscardedState drains the separate create-only grant queue.
// Provisioning and steady session IDs never share a record or retirement path.
func (h *Handler) revokeProvisioningDiscardedState(ctx context.Context, account Account) error {
	name := provisioningDiscardedRecordName(account.DID)
	for attempt := 0; attempt < maxRevokeCASAttempts; attempt++ {
		encoded, err := h.store.GetRecord(ctx, name)
		if errors.Is(err, authvault.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		var discarded discardedRecord
		if decodeRecord(encoded, &discarded) != nil || !validDiscardedRecord(discarded, account) {
			return errors.New("onboardingbroker: discarded provisioning authorization state is invalid")
		}
		var combined error
		for _, sessionID := range uniqueSessionIDs(discarded.SessionIDs, "") {
			if err := ctx.Err(); err != nil {
				combined = errors.Join(combined, err)
				continue
			}
			if err := h.driver.RetireProvisioning(ctx, account, sessionID); err != nil {
				combined = errors.Join(combined, err)
			}
		}
		if combined != nil {
			return errors.Join(errRevocationIncomplete, combined)
		}
		deleted, err := h.store.CompareAndDeleteRecord(ctx, name, encoded)
		if err != nil {
			return err
		}
		if deleted {
			return nil
		}
	}
	return errRevocationIncomplete
}

func (h *Handler) retireSessions(ctx context.Context, account Account, sessionIDs []string) error {
	var combined error
	for _, sessionID := range uniqueSessionIDs(sessionIDs, "") {
		if err := ctx.Err(); err != nil {
			combined = errors.Join(combined, err)
			continue
		}
		if err := h.driver.RetireSteady(ctx, account, sessionID); err != nil {
			combined = errors.Join(combined, err)
		}
	}
	return combined
}

func (h *Handler) enqueueDiscarded(ctx context.Context, account Account, sessionID string) error {
	name := discardedRecordName(account.DID)
	for attempt := 0; attempt < 8; attempt++ {
		var expected []byte
		discarded := discardedRecord{Version: 1, AccountFingerprint: accountFingerprint(account)}
		encoded, err := h.store.GetRecord(ctx, name)
		if err == nil {
			if decodeRecord(encoded, &discarded) != nil || !validDiscardedRecord(discarded, account) {
				return errors.New("onboardingbroker: discarded session state is invalid")
			}
			expected = encoded
		} else if !errors.Is(err, authvault.ErrNotFound) {
			return err
		}
		discarded.SessionIDs = uniqueSessionIDs(append(discarded.SessionIDs, sessionID), "")
		if len(discarded.SessionIDs) > maxRetiredSessions {
			return errors.New("onboardingbroker: discarded OAuth session bound exceeded")
		}
		replacement, err := json.Marshal(discarded)
		if err != nil {
			return err
		}
		swapped, err := h.store.CompareAndSwapRecord(ctx, name, expected, replacement, time.Time{})
		if err != nil {
			return err
		}
		if swapped {
			return nil
		}
	}
	return errors.New("onboardingbroker: discarded session state changed concurrently")
}

func (h *Handler) enqueueDiscardedProvisioning(ctx context.Context, account Account, sessionID string) error {
	name := provisioningDiscardedRecordName(account.DID)
	for attempt := 0; attempt < 8; attempt++ {
		var expected []byte
		discarded := discardedRecord{Version: 1, AccountFingerprint: accountFingerprint(account)}
		encoded, err := h.store.GetRecord(ctx, name)
		if err == nil {
			if decodeRecord(encoded, &discarded) != nil || !validDiscardedRecord(discarded, account) {
				return errors.New("onboardingbroker: discarded provisioning session state is invalid")
			}
			expected = encoded
		} else if !errors.Is(err, authvault.ErrNotFound) {
			return err
		}
		discarded.SessionIDs = uniqueSessionIDs(append(discarded.SessionIDs, sessionID), "")
		if len(discarded.SessionIDs) > maxRetiredSessions {
			return errors.New("onboardingbroker: discarded provisioning OAuth session bound exceeded")
		}
		replacement, err := json.Marshal(discarded)
		if err != nil {
			return err
		}
		swapped, err := h.store.CompareAndSwapRecord(ctx, name, expected, replacement, time.Time{})
		if err != nil {
			return err
		}
		if swapped {
			return nil
		}
	}
	return errors.New("onboardingbroker: discarded provisioning session state changed concurrently")
}

func (h *Handler) cleanupDiscarded(ctx context.Context, account Account) {
	name := discardedRecordName(account.DID)
	encoded, err := h.store.GetRecord(ctx, name)
	if err != nil {
		return
	}
	var discarded discardedRecord
	if decodeRecord(encoded, &discarded) != nil || !validDiscardedRecord(discarded, account) || len(discarded.SessionIDs) == 0 {
		return
	}
	cleanupCtx, cancel := context.WithTimeout(ctx, discardedCleanupTimeout)
	defer cancel()
	remaining := make([]string, 0, len(discarded.SessionIDs))
	for _, sessionID := range discarded.SessionIDs {
		if err := h.driver.RetireSteady(cleanupCtx, account, sessionID); err != nil {
			remaining = append(remaining, sessionID)
		}
	}
	if len(remaining) == len(discarded.SessionIDs) {
		return
	}
	discarded.SessionIDs = remaining
	replacement, err := json.Marshal(discarded)
	if err != nil {
		return
	}
	_, _ = h.store.CompareAndSwapRecord(ctx, name, encoded, replacement, time.Time{})
}

func (h *Handler) cleanupDiscardedProvisioning(ctx context.Context, account Account) {
	name := provisioningDiscardedRecordName(account.DID)
	encoded, err := h.store.GetRecord(ctx, name)
	if err != nil {
		return
	}
	var discarded discardedRecord
	if decodeRecord(encoded, &discarded) != nil || !validDiscardedRecord(discarded, account) || len(discarded.SessionIDs) == 0 {
		return
	}
	cleanupCtx, cancel := context.WithTimeout(ctx, discardedCleanupTimeout)
	defer cancel()
	remaining := make([]string, 0, len(discarded.SessionIDs))
	for _, sessionID := range discarded.SessionIDs {
		if err := h.driver.RetireProvisioning(cleanupCtx, account, sessionID); err != nil {
			remaining = append(remaining, sessionID)
		}
	}
	if len(remaining) == len(discarded.SessionIDs) {
		return
	}
	discarded.SessionIDs = remaining
	replacement, err := json.Marshal(discarded)
	if err != nil {
		return
	}
	_, _ = h.store.CompareAndSwapRecord(ctx, name, encoded, replacement, time.Time{})
}

func uniqueSessionIDs(input []string, active string) []string {
	seen := make(map[string]struct{}, len(input)+1)
	seen[active] = struct{}{}
	result := make([]string, 0, len(input))
	for _, sessionID := range input {
		if _, duplicate := seen[sessionID]; duplicate {
			continue
		}
		seen[sessionID] = struct{}{}
		result = append(result, sessionID)
	}
	return result
}

func accountFingerprint(account Account) string {
	digest := sha256.Sum256([]byte("comail-onboarding-account-v1\x00" + account.DID + "\x00" + account.PDSOrigin + "\x00" + account.SpaceKey))
	return "sha256-" + hex.EncodeToString(digest[:])
}

func (h *Handler) accountIndex(did, handle string) int {
	for index, account := range h.accounts {
		if account.DID == did && (handle == "" || account.Handle == handle) {
			return index
		}
	}
	return -1
}

func (h *Handler) accountIndexByDID(did string) int {
	for index, account := range h.accounts {
		if account.DID == did {
			return index
		}
	}
	return -1
}

func (h *Handler) authorized(header string) bool {
	prefix := "Bearer "
	if !strings.HasPrefix(header, prefix) || len(header) != len(prefix)+len(h.relayToken) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(header, prefix)), []byte(h.relayToken)) == 1
}

func validateAccount(account Account) error {
	did, didErr := syntax.ParseDID(account.DID)
	handle, handleErr := syntax.ParseHandle(account.Handle)
	key, keyErr := syntax.ParseRecordKey(account.SpaceKey)
	if didErr != nil || did.String() != account.DID || handleErr != nil || handle.String() != account.Handle || keyErr != nil || key.String() == "*" {
		return errors.New("onboardingbroker: account allowlist target is invalid")
	}
	pds, err := url.Parse(account.PDSOrigin)
	if err != nil || pds.Scheme != "https" || pds.Host == "" || pds.User != nil || pds.Path != "" || pds.RawQuery != "" || pds.Fragment != "" {
		return errors.New("onboardingbroker: account PDS must be an exact HTTPS origin")
	}
	return nil
}

func cleanBrokerOrigin(raw string, allowHTTP bool) (string, error) {
	origin, err := url.Parse(raw)
	if err != nil || origin.Host == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return "", errors.New("onboardingbroker: broker must be an exact origin")
	}
	if origin.Scheme == "http" {
		ip := net.ParseIP(origin.Hostname())
		if !allowHTTP || origin.Port() == "" || ip == nil || !ip.IsLoopback() {
			return "", errors.New("onboardingbroker: HTTP is allowed only for loopback tests")
		}
	} else if origin.Scheme != "https" || origin.Port() != "" || net.ParseIP(origin.Hostname()) != nil || !strings.Contains(origin.Hostname(), ".") {
		return "", errors.New("onboardingbroker: production broker must use a public HTTPS hostname")
	}
	return strings.TrimSuffix(origin.String(), "/"), nil
}

func validCallbackValues(values url.Values) bool {
	if values.Get("state") == "" {
		return false
	}
	allowed := map[string]bool{"state": true, "iss": true, "code": true, "error": true, "error_description": true, "error_uri": true}
	for key, value := range values {
		if !allowed[key] || len(value) != 1 || len(value[0]) > 4096 {
			return false
		}
	}
	errorValue, hasError := values["error"]
	_, hasCode := values["code"]
	issuerValue, hasIssuer := values["iss"]
	_, hasErrorDescription := values["error_description"]
	_, hasErrorURI := values["error_uri"]
	if hasError {
		if errorValue[0] == "" || hasCode || (hasIssuer && issuerValue[0] == "") {
			return false
		}
		return true
	}
	if hasErrorDescription || hasErrorURI {
		return false
	}
	return hasIssuer && issuerValue[0] != "" && hasCode && values.Get("code") != ""
}

func randomToken() (string, error) {
	data := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func validToken(token string) bool {
	if len(token) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	return err == nil && len(decoded) == 32
}

func recordName(kind, secret string) string {
	digest := sha256.Sum256([]byte(kind + "\x00" + secret))
	return kind + ":" + hex.EncodeToString(digest[:])
}

func readyRecordName(did string) string     { return recordName("ready", did) }
func discardedRecordName(did string) string { return recordName("discarded", did) }
func provisioningDiscardedRecordName(did string) string {
	return recordName("discarded-provisioning", did)
}

func decodeStrictBounded(reader io.Reader, max int64, output any) error {
	data, err := io.ReadAll(io.LimitReader(reader, max+1))
	if err != nil || int64(len(data)) > max {
		return errors.New("onboardingbroker: request exceeded bound")
	}
	return decodeRecord(data, output)
}

func decodeRecord(data []byte, output any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("onboardingbroker: trailing JSON")
	}
	return nil
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func writeProblem(response http.ResponseWriter, status int, message string) {
	response.Header().Set("Content-Type", "text/plain; charset=utf-8")
	response.WriteHeader(status)
	_, _ = io.WriteString(response, message+"\n")
}

func securityHeaders(response http.ResponseWriter) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
	response.Header().Set("Referrer-Policy", "no-referrer")
	response.Header().Set("X-Content-Type-Options", "nosniff")
}

func sameOrigin(target *url.URL, rawOrigin string) bool {
	origin, err := url.Parse(rawOrigin)
	return err == nil && target != nil && strings.EqualFold(target.Scheme, origin.Scheme) && strings.EqualFold(target.Host, origin.Host)
}
