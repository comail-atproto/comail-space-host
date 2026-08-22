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
	mu             sync.Mutex
	events         []string
	readySessions  map[string]bool
	provisionState string
	steadyState    string
	metadata       map[string]oauth.ClientMetadata
	checkErr       error
	retireErr      error
	retired        []string
	nextSessionID  string
	finishErr      error
}

func (d *fakeOAuthDriver) StartProvisioning(_ context.Context, account Account) (oauthclient.StartResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.events = append(d.events, "start-provision:"+account.Handle)
	return oauthclient.StartResult{AuthorizationURL: "https://spaces-alpha.host.bsky.network/oauth/authorize?request_uri=opaque-provision", State: d.provisionState}, nil
}

func (d *fakeOAuthDriver) FinishProvisioning(_ context.Context, account Account, values url.Values) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.events = append(d.events, "finish-provision:"+account.Handle+":"+values.Get("state"))
	return nil
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
	defer d.mu.Unlock()
	d.retired = append(d.retired, sessionID)
	if d.retireErr != nil {
		return d.retireErr
	}
	delete(d.readySessions, sessionID)
	return nil
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
			encoded, err := handler.store.GetRecord(t.Context(), recordName("ready", testDID+"\x00"+testHandle))
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
	name := recordName("discarded", testDID+"\x00"+testHandle)
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
