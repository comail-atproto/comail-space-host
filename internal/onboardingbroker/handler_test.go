package onboardingbroker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/auth/oauth"
	"github.com/comail-atproto/comail-space-host/internal/authvault"
	"github.com/comail-atproto/comail-space-host/internal/oauthclient"
)

const (
	testDID       = "did:plc:rfwhywgeym2ek7ioeyxkvsn6"
	testHandle    = "scott.spaces-alpha.bsky.network"
	testRelay     = "relay-server-to-server-secret"
	testReturnURL = "https://comail.at/webmail/login"
)

type fakeOAuthDriver struct {
	mu                 sync.Mutex
	events             []string
	readySessions      map[string]bool
	provisionState     string
	steadyState        string
	metadata           map[string]oauth.ClientMetadata
	checkErr           error
	retireErr          error
	retireErrs         map[string]error
	onRetire           func(string)
	retired            []string
	nextSessionID      string
	finishErr          error
	provisionErr       error
	provisionSessionID string
	retireProvisionErr error
	provisionRetired   []string
}

type provisioningQueueFailureStore struct{ RecordStore }

func (s *provisioningQueueFailureStore) CompareAndSwapRecord(
	ctx context.Context,
	name string,
	expected, replacement []byte,
	expiresAt time.Time,
) (bool, error) {
	if strings.HasPrefix(name, "discarded-provisioning:") {
		return false, errors.New("synthetic provisioning queue failure")
	}
	return s.RecordStore.CompareAndSwapRecord(ctx, name, expected, replacement, expiresAt)
}

func (d *fakeOAuthDriver) StartProvisioning(_ context.Context, account Account) (oauthclient.StartResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.events = append(d.events, "start-provision:"+account.Handle)
	return oauthclient.StartResult{AuthorizationURL: "https://spaces-alpha.host.bsky.network/oauth/authorize?request_uri=opaque-provision", State: d.provisionState}, nil
}

func (d *fakeOAuthDriver) FinishProvisioning(_ context.Context, account Account, values url.Values) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.events = append(d.events, "finish-provision:"+account.Handle+":"+values.Get("state"))
	return d.provisionSessionID, d.provisionErr
}

func (d *fakeOAuthDriver) StartSteady(_ context.Context, account Account) (oauthclient.StartResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.events = append(d.events, "start-steady:"+account.Handle)
	return oauthclient.StartResult{AuthorizationURL: "https://spaces-alpha.host.bsky.network/oauth/authorize?request_uri=opaque-steady", State: d.steadyState}, nil
}

func (d *fakeOAuthDriver) FinishSteady(_ context.Context, account Account, values url.Values) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.events = append(d.events, "finish-steady:"+account.Handle+":"+values.Get("state"))
	sessionID := d.nextSessionID
	if sessionID == "" {
		sessionID = "steady-session"
	}
	d.readySessions[sessionID] = true
	return sessionID, d.finishErr
}

func (d *fakeOAuthDriver) CheckSteady(_ context.Context, _ Account, sessionID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.checkErr != nil {
		return d.checkErr
	}
	if !d.readySessions[sessionID] {
		return ErrSteadyReauthorizationRequired
	}
	return nil
}

func (d *fakeOAuthDriver) RetireSteady(_ context.Context, _ Account, sessionID string) error {
	d.mu.Lock()
	d.retired = append(d.retired, sessionID)
	err := d.retireErr
	if candidate, ok := d.retireErrs[sessionID]; ok {
		err = candidate
	}
	if err == nil {
		delete(d.readySessions, sessionID)
	}
	hook := d.onRetire
	d.mu.Unlock()
	if hook != nil {
		hook(sessionID)
	}
	return err
}

func (d *fakeOAuthDriver) RetireProvisioning(_ context.Context, _ Account, sessionID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.provisionRetired = append(d.provisionRetired, sessionID)
	return d.retireProvisionErr
}

func (d *fakeOAuthDriver) ClientMetadata(path string) (oauth.ClientMetadata, bool) {
	metadata, ok := d.metadata[path]
	return metadata, ok
}

func TestBrokerCompletesSeparateProvisioningAndSteadyOAuthThenReportsReady(t *testing.T) {
	server, driver, vaultPath := newTestBroker(t)
	client := noRedirectClient(server.Client())
	body := "{\"version\":1,\"did\":\"" + testDID + "\",\"handle\":\"" + testHandle + "\"}"
	start := postStart(t, client, server.URL, testRelay, body)
	if start.StatusCode != http.StatusOK {
		t.Fatalf("start status = %d, body = %s", start.StatusCode, readBody(start))
	}
	var started startResponse
	decodeResponse(t, start, &started)
	if started.Version != 1 || started.Status != statusAuthorizationRequired || !strings.HasPrefix(started.AuthorizationURL, server.URL+"/onboarding/") {
		t.Fatalf("start response = %#v", started)
	}
	for _, forbidden := range []string{testDID, testHandle, testRelay} {
		if strings.Contains(started.AuthorizationURL, forbidden) {
			t.Fatalf("browser URL leaked %q", forbidden)
		}
	}

	entry := get(t, client, started.AuthorizationURL)
	if entry.StatusCode != http.StatusSeeOther || entry.Header.Get("Location") != "https://spaces-alpha.host.bsky.network/oauth/authorize?request_uri=opaque-provision" {
		t.Fatalf("entry status = %d, location = %q", entry.StatusCode, entry.Header.Get("Location"))
	}
	_ = entry.Body.Close()
	replay := get(t, client, started.AuthorizationURL)
	if replay.StatusCode != http.StatusGone {
		t.Fatalf("entry replay status = %d", replay.StatusCode)
	}
	_ = replay.Body.Close()

	provision := get(t, client, server.URL+"/oauth/provision/callback?state="+url.QueryEscape(driver.provisionState)+"&iss=https%3A%2F%2Fspaces-alpha.host.bsky.network&code=provision-code")
	if provision.StatusCode != http.StatusSeeOther || provision.Header.Get("Location") != "https://spaces-alpha.host.bsky.network/oauth/authorize?request_uri=opaque-steady" {
		t.Fatalf("provision callback = %d, location = %q", provision.StatusCode, provision.Header.Get("Location"))
	}
	_ = provision.Body.Close()

	steady := get(t, client, server.URL+"/oauth/steady/callback?state="+url.QueryEscape(driver.steadyState)+"&iss=https%3A%2F%2Fspaces-alpha.host.bsky.network&code=steady-code")
	if steady.StatusCode != http.StatusSeeOther || steady.Header.Get("Location") != testReturnURL {
		t.Fatalf("steady callback = %d, location = %q", steady.StatusCode, steady.Header.Get("Location"))
	}
	_ = steady.Body.Close()

	ready := postStart(t, client, server.URL, testRelay, body)
	var status startResponse
	decodeResponse(t, ready, &status)
	if status != (startResponse{Version: 1, Status: statusReady}) {
		t.Fatalf("ready response = %#v", status)
	}

	driver.mu.Lock()
	events := strings.Join(driver.events, "|")
	driver.mu.Unlock()
	wantEvents := "start-provision:" + testHandle + "|finish-provision:" + testHandle + ":" + driver.provisionState + "|start-steady:" + testHandle + "|finish-steady:" + testHandle + ":" + driver.steadyState
	if events != wantEvents {
		t.Fatalf("events = %s", events)
	}
	onDisk, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, plaintext := range []string{testDID, testHandle, "steady-session", driver.provisionState, driver.steadyState} {
		if bytes.Contains(onDisk, []byte(plaintext)) {
			t.Fatalf("encrypted broker store leaked %q", plaintext)
		}
	}
}

func TestBrokerStartRequiresBearerStrictJSONAndExactAllowlist(t *testing.T) {
	server, _, _ := newTestBroker(t)
	client := noRedirectClient(server.Client())
	valid := "{\"version\":1,\"did\":\"" + testDID + "\",\"handle\":\"" + testHandle + "\"}"
	tests := []struct {
		name, token, body string
		status            int
	}{
		{name: "missing bearer", body: valid, status: http.StatusUnauthorized},
		{name: "wrong bearer", token: "wrong", body: valid, status: http.StatusUnauthorized},
		{name: "unknown field", token: testRelay, body: strings.TrimSuffix(valid, "}") + ",\"pds\":\"https://evil\"}", status: http.StatusBadRequest},
		{name: "wrong version", token: testRelay, body: strings.Replace(valid, "\"version\":1", "\"version\":2", 1), status: http.StatusBadRequest},
		{name: "other did", token: testRelay, body: strings.Replace(valid, testDID, "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", 1), status: http.StatusForbidden},
		{name: "other handle", token: testRelay, body: strings.Replace(valid, testHandle, "other.spaces-alpha.bsky.network", 1), status: http.StatusForbidden},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := postStart(t, client, server.URL, test.token, test.body)
			defer response.Body.Close()
			if response.StatusCode != test.status {
				t.Fatalf("status = %d, want %d", response.StatusCode, test.status)
			}
			if response.Header.Get("Cache-Control") != "no-store" {
				t.Fatalf("cache control = %q", response.Header.Get("Cache-Control"))
			}
		})
	}
}

func TestBrokerStartTreatsHandleAsAdvisoryForExactDID(t *testing.T) {
	server, _, _ := newTestBroker(t)
	client := noRedirectClient(server.Client())
	response := postStart(t, client, server.URL, testRelay, `{"version":1,"did":"`+testDID+`","handle":""}`)
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("DID-only start status = %d, body = %s", response.StatusCode, readBody(response))
	}
}

func TestBrokerOAuthStateAndBrowserEntryAreSingleUse(t *testing.T) {
	server, driver, _ := newTestBroker(t)
	client := noRedirectClient(server.Client())
	body := "{\"version\":1,\"did\":\"" + testDID + "\",\"handle\":\"" + testHandle + "\"}"
	start := postStart(t, client, server.URL, testRelay, body)
	var started startResponse
	decodeResponse(t, start, &started)
	entry := get(t, client, started.AuthorizationURL)
	_ = entry.Body.Close()
	callbackURL := server.URL + "/oauth/provision/callback?state=" + url.QueryEscape(driver.provisionState) + "&iss=https%3A%2F%2Fspaces-alpha.host.bsky.network&code=one"
	first := get(t, client, callbackURL)
	_ = first.Body.Close()
	replay := get(t, client, callbackURL)
	defer replay.Body.Close()
	if replay.StatusCode != http.StatusBadRequest {
		t.Fatalf("OAuth state replay status = %d", replay.StatusCode)
	}
}

func TestBrokerConsumesHostedAlphaOAuthErrorCallbackWithIssuer(t *testing.T) {
	server, driver, _ := newTestBroker(t)
	client := noRedirectClient(server.Client())
	body := "{\"version\":1,\"did\":\"" + testDID + "\",\"handle\":\"" + testHandle + "\"}"
	start := postStart(t, client, server.URL, testRelay, body)
	var started startResponse
	decodeResponse(t, start, &started)
	entry := get(t, client, started.AuthorizationURL)
	_ = entry.Body.Close()

	driver.provisionErr = errors.New("authorization denied")
	callbackURL := server.URL + "/oauth/provision/callback?state=" + url.QueryEscape(driver.provisionState) +
		"&iss=https%3A%2F%2Fspaces-alpha.host.bsky.network&error=access_denied&error_description=denied"
	first := get(t, client, callbackURL)
	if first.StatusCode != http.StatusBadRequest {
		t.Fatalf("OAuth error callback status = %d, body = %s", first.StatusCode, readBody(first))
	}
	_ = first.Body.Close()
	replay := get(t, client, callbackURL)
	if replay.StatusCode != http.StatusBadRequest {
		t.Fatalf("OAuth error callback replay status = %d", replay.StatusCode)
	}
	_ = replay.Body.Close()

	driver.mu.Lock()
	events := append([]string(nil), driver.events...)
	driver.mu.Unlock()
	finishEvents := 0
	for _, event := range events {
		if strings.HasPrefix(event, "finish-provision:") {
			finishEvents++
		}
	}
	if finishEvents != 1 {
		t.Fatalf("finish provisioning events = %d, want one consumed callback; events=%v", finishEvents, events)
	}
}

func TestValidCallbackValuesRejectsAmbiguousOrUnsafeShapes(t *testing.T) {
	tests := []struct {
		name   string
		values url.Values
		valid  bool
	}{
		{name: "success", values: url.Values{"state": {"state"}, "iss": {"https://spaces-alpha.host.bsky.network"}, "code": {"code"}}, valid: true},
		{name: "error without issuer", values: url.Values{"state": {"state"}, "error": {"access_denied"}}, valid: true},
		{name: "hosted alpha error with issuer", values: url.Values{"state": {"state"}, "iss": {"https://spaces-alpha.host.bsky.network"}, "error": {"access_denied"}, "error_description": {"denied"}}, valid: true},
		{name: "code and error", values: url.Values{"state": {"state"}, "iss": {"https://spaces-alpha.host.bsky.network"}, "code": {"code"}, "error": {"access_denied"}}},
		{name: "error description without error", values: url.Values{"state": {"state"}, "iss": {"https://spaces-alpha.host.bsky.network"}, "code": {"code"}, "error_description": {"denied"}}},
		{name: "empty error", values: url.Values{"state": {"state"}, "error": {""}}},
		{name: "empty issuer", values: url.Values{"state": {"state"}, "iss": {""}, "error": {"access_denied"}}},
		{name: "duplicate issuer", values: url.Values{"state": {"state"}, "iss": {"one", "two"}, "error": {"access_denied"}}},
		{name: "unknown parameter", values: url.Values{"state": {"state"}, "error": {"access_denied"}, "unexpected": {"value"}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := validCallbackValues(test.values); got != test.valid {
				t.Fatalf("validCallbackValues() = %v, want %v", got, test.valid)
			}
		})
	}
}

func TestBrokerServesOnlyConfiguredOpaqueClientMetadata(t *testing.T) {
	server, _, _ := newTestBroker(t)
	client := noRedirectClient(server.Client())
	metadataPath := "/oauth/client/h8sKQ2eMv7/provision.json"
	response := get(t, client, server.URL+metadataPath)
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("metadata status = %d, content type = %q", response.StatusCode, response.Header.Get("Content-Type"))
	}
	var metadata oauth.ClientMetadata
	decodeResponse(t, response, &metadata)
	if metadata.ClientID != server.URL+metadataPath || strings.Contains(metadata.ClientID, testDID) || strings.Contains(metadata.ClientID, testHandle) {
		t.Fatalf("metadata = %#v", metadata)
	}
	missing := get(t, client, server.URL+"/oauth/client/not-configured.json")
	defer missing.Body.Close()
	if missing.StatusCode != http.StatusNotFound {
		t.Fatalf("missing metadata status = %d", missing.StatusCode)
	}
}

func TestBrokerRetainsReadySessionOnTransientLiveProofFailure(t *testing.T) {
	server, driver, _ := newTestBroker(t)
	client := noRedirectClient(server.Client())
	body := "{\"version\":1,\"did\":\"" + testDID + "\",\"handle\":\"" + testHandle + "\"}"
	authorizeTestBrokerOnce(t, server, driver, client, body)

	driver.checkErr = errors.New("temporary provider outage")
	transient := postStart(t, client, server.URL, testRelay, body)
	defer transient.Body.Close()
	if transient.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("transient proof status = %d", transient.StatusCode)
	}
	driver.checkErr = nil
	ready := postStart(t, client, server.URL, testRelay, body)
	var status startResponse
	decodeResponse(t, ready, &status)
	if status.Status != statusReady {
		t.Fatalf("retained ready status = %#v", status)
	}
}

func TestBrokerAtomicallyReplacesAndRetiresPriorSteadySession(t *testing.T) {
	for _, cleanupFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "cleanup succeeds", true: "cleanup retained for retry"}[cleanupFails], func(t *testing.T) {
			server, driver, _ := newTestBroker(t)
			client := noRedirectClient(server.Client())
			body := "{\"version\":1,\"did\":\"" + testDID + "\",\"handle\":\"" + testHandle + "\"}"
			authorizeTestBrokerOnce(t, server, driver, client, body)

			driver.checkErr = ErrSteadyReauthorizationRequired
			driver.nextSessionID = "steady-session-2"
			if cleanupFails {
				driver.retireErr = errors.New("revocation provider unavailable")
			}
			authorizeTestBrokerOnce(t, server, driver, client, body)

			handler := server.Config.Handler.(*Handler)
			encoded, err := handler.store.GetRecord(t.Context(), readyRecordName(testDID))
			if err != nil {
				t.Fatal(err)
			}
			var ready readyRecord
			if decodeRecord(encoded, &ready) != nil || ready.SessionID != "steady-session-2" {
				t.Fatalf("ready record = %#v", ready)
			}
			wantRetired := 0
			if cleanupFails {
				wantRetired = 1
			}
			if len(ready.RetiredSessionIDs) != wantRetired || len(driver.retired) != 1 || driver.retired[0] != "steady-session" {
				t.Fatalf("ready=%#v retire attempts=%v", ready, driver.retired)
			}
		})
	}
}

func TestBrokerRetainsFailedNewSessionUntilRevocationSucceeds(t *testing.T) {
	server, driver, _ := newTestBroker(t)
	client := noRedirectClient(server.Client())
	body := "{\"version\":1,\"did\":\"" + testDID + "\",\"handle\":\"" + testHandle + "\"}"

	start := postStart(t, client, server.URL, testRelay, body)
	var started startResponse
	decodeResponse(t, start, &started)
	entry := get(t, client, started.AuthorizationURL)
	_ = entry.Body.Close()
	provision := get(t, client, server.URL+"/oauth/provision/callback?state="+url.QueryEscape(driver.provisionState)+"&iss=https%3A%2F%2Fspaces-alpha.host.bsky.network&code=provision-code")
	_ = provision.Body.Close()

	driver.finishErr = errors.New("live proof rejected")
	driver.retireErr = errors.New("revocation provider unavailable")
	steady := get(t, client, server.URL+"/oauth/steady/callback?state="+url.QueryEscape(driver.steadyState)+"&iss=https%3A%2F%2Fspaces-alpha.host.bsky.network&code=steady-code")
	if steady.StatusCode != http.StatusBadRequest {
		t.Fatalf("steady callback status = %d", steady.StatusCode)
	}
	_ = steady.Body.Close()

	handler := server.Config.Handler.(*Handler)
	name := discardedRecordName(testDID)
	encoded, err := handler.store.GetRecord(t.Context(), name)
	if err != nil {
		t.Fatal(err)
	}
	var discarded discardedRecord
	if decodeRecord(encoded, &discarded) != nil || len(discarded.SessionIDs) != 1 || discarded.SessionIDs[0] != "steady-session" {
		t.Fatalf("discarded record = %#v", discarded)
	}

	driver.finishErr = nil
	driver.retireErr = nil
	retry := postStart(t, client, server.URL, testRelay, body)
	_ = retry.Body.Close()
	encoded, err = handler.store.GetRecord(t.Context(), name)
	if err != nil {
		t.Fatal(err)
	}
	if decodeRecord(encoded, &discarded) != nil || len(discarded.SessionIDs) != 0 {
		t.Fatalf("discarded cleanup record = %#v", discarded)
	}
	if len(driver.retired) < 2 || driver.retired[len(driver.retired)-1] != "steady-session" {
		t.Fatalf("retirement attempts = %v", driver.retired)
	}
}

func TestBrokerRetainsFailedProvisioningCleanupUntilRetrySucceeds(t *testing.T) {
	server, driver, vaultPath := newTestBroker(t)
	client := noRedirectClient(server.Client())
	body := "{\"version\":1,\"did\":\"" + testDID + "\",\"handle\":\"" + testHandle + "\"}"
	start := postStart(t, client, server.URL, testRelay, body)
	var started startResponse
	decodeResponse(t, start, &started)
	entry := get(t, client, started.AuthorizationURL)
	_ = entry.Body.Close()

	driver.provisionSessionID = "retained-provisioning-session"
	driver.provisionErr = errors.New("provisioning grant revocation unconfirmed")
	driver.retireProvisionErr = errors.New("revocation provider unavailable")
	callback := get(t, client, server.URL+"/oauth/provision/callback?state="+url.QueryEscape(driver.provisionState)+"&iss=https%3A%2F%2Fspaces-alpha.host.bsky.network&code=provision-code")
	bodyText := readBody(callback)
	_ = callback.Body.Close()
	if callback.StatusCode != http.StatusBadRequest {
		t.Fatalf("provisioning callback status=%d body=%s", callback.StatusCode, bodyText)
	}
	if strings.Contains(bodyText, driver.provisionSessionID) {
		t.Fatal("callback response leaked the opaque retained provisioning session ID")
	}

	handler := server.Config.Handler.(*Handler)
	name := provisioningDiscardedRecordName(testDID)
	encoded, err := handler.store.GetRecord(t.Context(), name)
	if err != nil {
		t.Fatal(err)
	}
	var discarded discardedRecord
	if decodeRecord(encoded, &discarded) != nil || len(discarded.SessionIDs) != 1 || discarded.SessionIDs[0] != driver.provisionSessionID {
		t.Fatalf("discarded provisioning record = %#v", discarded)
	}

	driver.provisionErr = nil
	driver.retireProvisionErr = nil
	reopened, err := authvault.Open(vaultPath, filepath.Join(filepath.Dir(vaultPath), "key"))
	if err != nil {
		t.Fatal(err)
	}
	restartedServer := httptest.NewUnstartedServer(nil)
	restartedOrigin := "http://" + restartedServer.Listener.Addr().String()
	restarted, err := New(Config{
		BrokerOrigin: restartedOrigin, RelayToken: testRelay, ReturnURL: testReturnURL, AllowHTTP: true,
		Accounts: append([]Account(nil), handler.accounts...),
	}, reopened, driver)
	if err != nil {
		t.Fatal(err)
	}
	restartedServer.Config.Handler = restarted
	restartedServer.Start()
	defer restartedServer.Close()
	retry := postStart(t, noRedirectClient(restartedServer.Client()), restartedServer.URL, testRelay, body)
	_ = retry.Body.Close()
	encoded, err = restarted.store.GetRecord(t.Context(), name)
	if err != nil {
		t.Fatal(err)
	}
	if decodeRecord(encoded, &discarded) != nil || len(discarded.SessionIDs) != 0 {
		t.Fatalf("discarded provisioning cleanup record = %#v", discarded)
	}
	driver.mu.Lock()
	retired := append([]string(nil), driver.provisionRetired...)
	driver.mu.Unlock()
	if len(retired) < 2 || retired[len(retired)-1] != driver.provisionSessionID {
		t.Fatalf("provisioning retirement attempts = %v", retired)
	}
}

func TestBrokerFailsClosedWithoutLeakingHandleWhenProvisioningQueueWriteFails(t *testing.T) {
	server, driver, _ := newTestBroker(t)
	client := noRedirectClient(server.Client())
	body := "{\"version\":1,\"did\":\"" + testDID + "\",\"handle\":\"" + testHandle + "\"}"
	start := postStart(t, client, server.URL, testRelay, body)
	var started startResponse
	decodeResponse(t, start, &started)
	entry := get(t, client, started.AuthorizationURL)
	_ = entry.Body.Close()

	handler := server.Config.Handler.(*Handler)
	handler.store = &provisioningQueueFailureStore{RecordStore: handler.store}
	driver.provisionSessionID = "must-not-leak-provisioning-session"
	driver.provisionErr = errors.New("remote revocation unconfirmed")
	callback := get(t, client, server.URL+"/oauth/provision/callback?state="+url.QueryEscape(driver.provisionState)+"&iss=https%3A%2F%2Fspaces-alpha.host.bsky.network&code=provision-code")
	bodyText := readBody(callback)
	_ = callback.Body.Close()
	if callback.StatusCode != http.StatusInternalServerError {
		t.Fatalf("queue failure status=%d body=%s", callback.StatusCode, bodyText)
	}
	if strings.Contains(bodyText, driver.provisionSessionID) {
		t.Fatal("queue failure response leaked the opaque retained provisioning session ID")
	}
}

func TestBrokerDurableAccountStateSurvivesHandleChange(t *testing.T) {
	server, driver, _ := newTestBroker(t)
	client := noRedirectClient(server.Client())
	body := `{"version":1,"did":"` + testDID + `","handle":"` + testHandle + `"}`
	authorizeTestBrokerOnce(t, server, driver, client, body)

	handler := server.Config.Handler.(*Handler)
	changedHandle := "renamed.spaces-alpha.bsky.network"
	handler.accounts[0].Handle = changedHandle
	ready := postStart(t, client, server.URL, testRelay, `{"version":1,"did":"`+testDID+`","handle":"`+changedHandle+`"}`)
	var status startResponse
	decodeResponse(t, ready, &status)
	if status != (startResponse{Version: 1, Status: statusReady}) {
		t.Fatalf("renamed account status = %#v", status)
	}

	if err := handler.enqueueDiscarded(t.Context(), handler.accounts[0], "discarded-before-handle-change"); err != nil {
		t.Fatal(err)
	}
	driver.readySessions["discarded-before-handle-change"] = true
	handler.accounts[0].Handle = "renamed-again.spaces-alpha.bsky.network"
	cleanup := postStart(t, client, server.URL, testRelay, `{"version":1,"did":"`+testDID+`","handle":"renamed-again.spaces-alpha.bsky.network"}`)
	_ = cleanup.Body.Close()
	driver.mu.Lock()
	retired := append([]string(nil), driver.retired...)
	driver.mu.Unlock()
	if !containsString(retired, "discarded-before-handle-change") {
		t.Fatalf("discarded state was stranded by handle change; retire attempts=%v", retired)
	}
}

func TestBrokerRevokeRequiresBearerStrictBoundedExactDID(t *testing.T) {
	server, _, _ := newTestBroker(t)
	client := noRedirectClient(server.Client())
	valid := `{"version":1,"did":"` + testDID + `"}`
	tests := []struct {
		name, token, body string
		status            int
	}{
		{name: "missing bearer", body: valid, status: http.StatusUnauthorized},
		{name: "wrong bearer", token: "wrong", body: valid, status: http.StatusUnauthorized},
		{name: "unknown field", token: testRelay, body: strings.TrimSuffix(valid, "}") + `,"handle":"` + testHandle + `"}`, status: http.StatusBadRequest},
		{name: "wrong version", token: testRelay, body: strings.Replace(valid, `"version":1`, `"version":2`, 1), status: http.StatusBadRequest},
		{name: "other did", token: testRelay, body: strings.Replace(valid, testDID, "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", 1), status: http.StatusForbidden},
		{name: "oversized", token: testRelay, body: valid + strings.Repeat(" ", maxRevokeBodyBytes), status: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := postRevoke(t, client, server.URL, test.token, test.body)
			defer response.Body.Close()
			if response.StatusCode != test.status {
				t.Fatalf("status = %d, want %d, body=%s", response.StatusCode, test.status, readBody(response))
			}
		})
	}
}

func TestBrokerRevokeConfirmsActiveRetiredAndDiscardedBeforeDeletingState(t *testing.T) {
	server, driver, _ := newTestBroker(t)
	client := noRedirectClient(server.Client())
	handler := server.Config.Handler.(*Handler)
	account := handler.accounts[0]
	putReadyRecord(t, handler.store, account, "active", []string{"retired-one", "retired-two"})
	putDiscardedRecord(t, handler.store, account, []string{"discarded-one", "discarded-two"})
	putProvisioningDiscardedRecord(t, handler.store, account, []string{"provisioning-one"})
	for _, sessionID := range []string{"active", "retired-one", "retired-two", "discarded-one", "discarded-two"} {
		driver.readySessions[sessionID] = true
	}

	response := postRevoke(t, client, server.URL, testRelay, `{"version":1,"did":"`+testDID+`"}`)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("revoke status=%d body=%s", response.StatusCode, readBody(response))
	}
	var result revokeResponse
	decodeResponse(t, response, &result)
	if result != (revokeResponse{Version: 1, Status: statusRevoked}) {
		t.Fatalf("revoke response=%#v", result)
	}
	for _, name := range []string{readyRecordName(testDID), discardedRecordName(testDID), provisioningDiscardedRecordName(testDID)} {
		if _, err := handler.store.GetRecord(t.Context(), name); !errors.Is(err, authvault.ErrNotFound) {
			t.Fatalf("revoked state %q remains: %v", name, err)
		}
	}
	driver.mu.Lock()
	retired := append([]string(nil), driver.retired...)
	driver.mu.Unlock()
	for _, sessionID := range []string{"active", "retired-one", "retired-two", "discarded-one", "discarded-two"} {
		if !containsString(retired, sessionID) {
			t.Fatalf("session %q was not revoked; attempts=%v", sessionID, retired)
		}
	}
	if !containsString(driver.provisionRetired, "provisioning-one") {
		t.Fatalf("provisioning session was not revoked; attempts=%v", driver.provisionRetired)
	}
}

func TestBrokerRevokeRetainsStateWhenAnyRemoteRevocationIsUnconfirmed(t *testing.T) {
	server, driver, _ := newTestBroker(t)
	client := noRedirectClient(server.Client())
	handler := server.Config.Handler.(*Handler)
	account := handler.accounts[0]
	putReadyRecord(t, handler.store, account, "active", []string{"must-retry"})
	putDiscardedRecord(t, handler.store, account, []string{"discarded-must-retry"})
	putProvisioningDiscardedRecord(t, handler.store, account, []string{"provisioning-must-retry"})
	driver.retireProvisionErr = errors.New("provider unavailable")
	driver.retireErrs = map[string]error{
		"must-retry":           errors.New("provider unavailable"),
		"discarded-must-retry": errors.New("provider unavailable"),
	}

	response := postRevoke(t, client, server.URL, testRelay, `{"version":1,"did":"`+testDID+`"}`)
	defer response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("revoke status=%d body=%s", response.StatusCode, readBody(response))
	}
	for _, name := range []string{readyRecordName(testDID), discardedRecordName(testDID), provisioningDiscardedRecordName(testDID)} {
		if _, err := handler.store.GetRecord(t.Context(), name); err != nil {
			t.Fatalf("unconfirmed state %q was deleted: %v", name, err)
		}
	}
}

func TestBrokerRevokeCASDoesNotDeleteConcurrentlyReplacedReadyState(t *testing.T) {
	server, driver, _ := newTestBroker(t)
	client := noRedirectClient(server.Client())
	handler := server.Config.Handler.(*Handler)
	account := handler.accounts[0]
	putReadyRecord(t, handler.store, account, "old-active", nil)
	driver.readySessions["old-active"] = true
	driver.readySessions["new-active"] = true
	replacement, err := json.Marshal(readyRecord{
		Version: 1, AccountFingerprint: accountFingerprint(account), SessionID: "new-active",
		RetiredSessionIDs: []string{"old-active"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	var hookErr error
	driver.onRetire = func(sessionID string) {
		if sessionID != "old-active" {
			return
		}
		once.Do(func() {
			hookErr = handler.store.SetRecord(context.Background(), readyRecordName(account.DID), replacement, time.Time{})
		})
	}

	response := postRevoke(t, client, server.URL, testRelay, `{"version":1,"did":"`+testDID+`"}`)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("revoke status=%d body=%s", response.StatusCode, readBody(response))
	}
	_ = response.Body.Close()
	if hookErr != nil {
		t.Fatalf("concurrent replacement failed: %v", hookErr)
	}
	if _, err := handler.store.GetRecord(t.Context(), readyRecordName(testDID)); !errors.Is(err, authvault.ErrNotFound) {
		t.Fatalf("concurrently replaced state remains after bounded retry: %v", err)
	}
	driver.mu.Lock()
	retired := append([]string(nil), driver.retired...)
	driver.mu.Unlock()
	if !containsString(retired, "new-active") {
		t.Fatalf("concurrent active session was lost rather than revoked; attempts=%v", retired)
	}
}

func TestBrokerFlowAccountFingerprintSurvivesConfigReorder(t *testing.T) {
	server, _, _ := newTestBroker(t)
	handler := server.Config.Handler.(*Handler)
	original := handler.accounts[0]
	other := Account{
		DID: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", Handle: "other.spaces-alpha.bsky.network",
		PDSOrigin: original.PDSOrigin, SpaceKey: original.SpaceKey,
	}
	handler.accounts = []Account{other, original}
	encoded, err := json.Marshal(flowRecord{Version: 1, AccountFingerprint: accountFingerprint(original)})
	if err != nil {
		t.Fatal(err)
	}
	_, account, err := handler.decodeFlow(encoded)
	if err != nil || account != original {
		t.Fatalf("decoded account=%#v err=%v", account, err)
	}
}

func authorizeTestBrokerOnce(
	t *testing.T,
	server *httptest.Server,
	driver *fakeOAuthDriver,
	client *http.Client,
	body string,
) {
	t.Helper()
	start := postStart(t, client, server.URL, testRelay, body)
	if start.StatusCode != http.StatusOK {
		t.Fatalf("start status = %d, body = %s", start.StatusCode, readBody(start))
	}
	var started startResponse
	decodeResponse(t, start, &started)
	if started.Status != statusAuthorizationRequired {
		t.Fatalf("start response = %#v", started)
	}
	entry := get(t, client, started.AuthorizationURL)
	if entry.StatusCode != http.StatusSeeOther {
		t.Fatalf("entry status = %d", entry.StatusCode)
	}
	_ = entry.Body.Close()
	provision := get(t, client, server.URL+"/oauth/provision/callback?state="+url.QueryEscape(driver.provisionState)+"&iss=https%3A%2F%2Fspaces-alpha.host.bsky.network&code=provision-code")
	if provision.StatusCode != http.StatusSeeOther {
		t.Fatalf("provision callback status = %d", provision.StatusCode)
	}
	_ = provision.Body.Close()
	steady := get(t, client, server.URL+"/oauth/steady/callback?state="+url.QueryEscape(driver.steadyState)+"&iss=https%3A%2F%2Fspaces-alpha.host.bsky.network&code=steady-code")
	if steady.StatusCode != http.StatusSeeOther {
		t.Fatalf("steady callback status = %d", steady.StatusCode)
	}
	_ = steady.Body.Close()
}

func newTestBroker(t *testing.T) (*httptest.Server, *fakeOAuthDriver, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	vaultPath := filepath.Join(dir, "vault")
	store, err := authvault.Create(vaultPath, filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(nil)
	origin := "http://" + server.Listener.Addr().String()
	metadataPath := "/oauth/client/h8sKQ2eMv7/provision.json"
	driver := &fakeOAuthDriver{
		readySessions: map[string]bool{}, provisionState: "oauth-state-provision", steadyState: "oauth-state-steady",
		metadata: map[string]oauth.ClientMetadata{
			metadataPath: {ClientID: origin + metadataPath, RedirectURIs: []string{origin + "/oauth/provision/callback"}},
		},
	}
	handler, err := New(Config{
		BrokerOrigin: origin, RelayToken: testRelay, ReturnURL: testReturnURL, AllowHTTP: true,
		Accounts: []Account{{DID: testDID, Handle: testHandle, PDSOrigin: "https://spaces-alpha.host.bsky.network", SpaceKey: "primary"}},
	}, store, driver)
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = handler
	server.Start()
	t.Cleanup(server.Close)
	return server, driver, vaultPath
}

func noRedirectClient(base *http.Client) *http.Client {
	copy := *base
	copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &copy
}

func postStart(t *testing.T, client *http.Client, origin, token, body string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, origin+"/v1/onboarding/start", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func postRevoke(t *testing.T, client *http.Client, origin, token, body string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, origin+"/v1/onboarding/revoke", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func putReadyRecord(t *testing.T, store RecordStore, account Account, active string, retired []string) {
	t.Helper()
	encoded, err := json.Marshal(readyRecord{
		Version: 1, AccountFingerprint: accountFingerprint(account), SessionID: active,
		RetiredSessionIDs: append([]string(nil), retired...),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetRecord(t.Context(), readyRecordName(account.DID), encoded, time.Time{}); err != nil {
		t.Fatal(err)
	}
}

func putDiscardedRecord(t *testing.T, store RecordStore, account Account, sessions []string) {
	t.Helper()
	encoded, err := json.Marshal(discardedRecord{
		Version: 1, AccountFingerprint: accountFingerprint(account), SessionIDs: append([]string(nil), sessions...),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetRecord(t.Context(), discardedRecordName(account.DID), encoded, time.Time{}); err != nil {
		t.Fatal(err)
	}
}

func putProvisioningDiscardedRecord(t *testing.T, store RecordStore, account Account, sessions []string) {
	t.Helper()
	encoded, err := json.Marshal(discardedRecord{
		Version: 1, AccountFingerprint: accountFingerprint(account), SessionIDs: append([]string(nil), sessions...),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetRecord(t.Context(), provisioningDiscardedRecordName(account.DID), encoded, time.Time{}); err != nil {
		t.Fatal(err)
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func get(t *testing.T, client *http.Client, target string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func decodeResponse(t *testing.T, response *http.Response, output any) {
	t.Helper()
	defer response.Body.Close()
	decoder := json.NewDecoder(io.LimitReader(response.Body, 64*1024))
	if err := decoder.Decode(output); err != nil {
		t.Fatal(err)
	}
}

func readBody(response *http.Response) string {
	if response == nil || response.Body == nil {
		return ""
	}
	data, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	return string(data)
}
