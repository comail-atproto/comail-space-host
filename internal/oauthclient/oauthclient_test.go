package oauthclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/auth/oauth"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/comail-atproto/comail-space-host/internal/repository"
)

const testMemberDID = "did:plc:rfwhywgeym2ek7ioeyxkvsn6"

const testSteadySpaceScope = "space:email.atmos.mailbox?authority=did:plc:rfwhywgeym2ek7ioeyxkvsn6&skey=primary" +
	"&collection=email.atmos.folderOperation" +
	"&collection=email.atmos.folderRevision" +
	"&collection=email.atmos.message" +
	"&collection=email.atmos.messageStateOperation" +
	"&collection=email.atmos.messageStateRevision" +
	"&action=read&action=create"

const testProvisioningSpaceScope = "space:email.atmos.mailbox?authority=did:plc:rfwhywgeym2ek7ioeyxkvsn6&skey=primary" +
	"&collection=email.atmos.folderOperation" +
	"&collection=email.atmos.folderRevision" +
	"&collection=email.atmos.message" +
	"&collection=email.atmos.messageStateOperation" +
	"&collection=email.atmos.messageStateRevision" +
	"&action=read_self&manage=create"

func TestMailboxScopesAreExactAndAppendOnly(t *testing.T) {
	scopes, err := MailboxScopes(testMemberDID, "primary")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"atproto", "blob:message/rfc822", testSteadySpaceScope}
	if !reflect.DeepEqual(scopes, want) {
		t.Fatalf("scopes = %#v, want %#v", scopes, want)
	}
}

func TestProvisioningScopesAreSeparateAndCreateOnly(t *testing.T) {
	scopes, err := ProvisioningScopes(testMemberDID, "primary")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"atproto",
		testProvisioningSpaceScope,
	}
	if !reflect.DeepEqual(scopes, want) {
		t.Fatalf("scopes = %#v, want %#v", scopes, want)
	}
	if err := ValidateProvisioningGrant([]string{want[1], want[0]}, testMemberDID, "primary"); err != nil {
		t.Fatalf("exact provisioning grant rejected: %v", err)
	}
}

func TestValidateProvisioningGrantRejectsSteadyOrWidenedGrant(t *testing.T) {
	provisioning, err := ProvisioningScopes(testMemberDID, "primary")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		scopes []string
	}{
		{name: "steady grant reused", scopes: []string{"atproto", "blob:message/rfc822", testSteadySpaceScope}},
		{name: "blob write", scopes: append(append([]string{}, provisioning...), "blob:message/rfc822")},
		{name: "record create", scopes: replaceScope(provisioning, "action=read_self", "action=read_self&action=create")},
		{name: "manage update", scopes: replaceScope(provisioning, "manage=create", "manage=create&manage=update")},
		{name: "wildcard authority", scopes: replaceScope(provisioning, "authority="+testMemberDID, "authority=*")},
		{name: "wildcard key", scopes: replaceScope(provisioning, "skey=primary", "skey=*")},
		{name: "other key", scopes: replaceScope(provisioning, "skey=primary", "skey=secondary")},
		{name: "missing collection", scopes: replaceScope(provisioning, "&collection=email.atmos.folderRevision", "")},
		{name: "foreign collection", scopes: replaceScope(provisioning, "collection=email.atmos.message", "collection=app.example.message")},
		{name: "collection wildcard", scopes: replaceScope(provisioning, "collection=email.atmos.message", "collection=*")},
		{name: "duplicate collection", scopes: replaceScope(provisioning, "&action=read_self", "&collection=email.atmos.message&action=read_self")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateProvisioningGrant(test.scopes, testMemberDID, "primary"); err == nil {
				t.Fatal("expected provisioning least-privilege validation error")
			}
		})
	}
}

func TestMailboxScopesRejectInvalidExactTargets(t *testing.T) {
	tests := []struct {
		name string
		did  string
		skey string
	}{
		{name: "missing did", skey: "primary"},
		{name: "self authority", did: "self", skey: "primary"},
		{name: "wildcard authority", did: "*", skey: "primary"},
		{name: "missing key", did: testMemberDID},
		{name: "wildcard key", did: testMemberDID, skey: "*"},
		{name: "separator injection", did: testMemberDID, skey: "primary&action=delete"},
		{name: "escaped injection", did: testMemberDID, skey: "primary%26action%3Ddelete"},
		{name: "dot key", did: testMemberDID, skey: "."},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := MailboxScopes(test.did, test.skey); err == nil {
				t.Fatal("expected target validation error")
			}
		})
	}
}

func TestValidateSteadyGrantUsesCapabilitySemantics(t *testing.T) {
	granted := []string{
		"blob:message/rfc822",
		"space:email.atmos.mailbox?action=create&action=read" +
			"&collection=email.atmos.messageStateRevision" +
			"&collection=email.atmos.folderOperation" +
			"&collection=email.atmos.message" +
			"&collection=email.atmos.folderRevision" +
			"&collection=email.atmos.messageStateOperation" +
			"&skey=primary&authority=did:plc:rfwhywgeym2ek7ioeyxkvsn6",
		"atproto",
	}
	if err := ValidateSteadyGrant(granted, testMemberDID, "primary"); err != nil {
		t.Fatalf("semantically exact grant rejected: %v", err)
	}
}

func TestValidateSteadyGrantRejectsMissingOrWidenedCapabilities(t *testing.T) {
	base := []string{"atproto", "blob:message/rfc822", testSteadySpaceScope}
	tests := []struct {
		name   string
		scopes []string
	}{
		{name: "missing base scope", scopes: base[1:]},
		{name: "extra scope", scopes: append(append([]string{}, base...), "transition:generic")},
		{name: "wildcard key", scopes: replaceScope(base, "skey=primary", "skey=*")},
		{name: "self authority", scopes: replaceScope(base, "authority="+testMemberDID, "authority=self")},
		{name: "other authority", scopes: replaceScope(base, testMemberDID, "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")},
		{name: "other key", scopes: replaceScope(base, "skey=primary", "skey=secondary")},
		{name: "collection wildcard", scopes: replaceScope(base, "collection=email.atmos.message", "collection=*")},
		{name: "legacy collection", scopes: replaceScope(base, "collection=email.atmos.folderRevision", "collection=email.atmos.folder")},
		{name: "missing collection", scopes: replaceScope(base, "&collection=email.atmos.folderRevision", "")},
		{name: "update action", scopes: replaceScope(base, "&action=create", "&action=create&action=update")},
		{name: "management grant", scopes: replaceScope(base, "&action=create", "&action=create&manage=create")},
		{name: "read self", scopes: replaceScope(base, "action=read", "action=read_self")},
		{name: "unknown parameter", scopes: replaceScope(base, "&action=read", "&unknown=value&action=read")},
		{name: "duplicate authority", scopes: replaceScope(base, "&skey=primary", "&authority="+testMemberDID+"&skey=primary")},
		{name: "encoded injection", scopes: replaceScope(base, "skey=primary", "skey=primary%26manage%3Dcreate")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateSteadyGrant(test.scopes, testMemberDID, "primary"); err == nil {
				t.Fatal("expected least-privilege validation error")
			}
		})
	}
}

func replaceScope(scopes []string, old, replacement string) []string {
	result := append([]string(nil), scopes...)
	result[len(result)-1] = strings.Replace(result[len(result)-1], old, replacement, 1)
	return result
}

func TestSessionDoerFailsClosedInsteadOfRefreshingUnverifiableScope(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.Header().Set("WWW-Authenticate", `DPoP error="invalid_token"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	doer, session := newTestSessionDoer(t, server.URL)
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+"/xrpc/com.atproto.space.getDelegationToken", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := doer.Do(context.Background(), request, "com.atproto.space.getDelegationToken")
	if response != nil {
		_ = response.Body.Close()
		t.Fatal("expired access token returned a response")
	}
	if !errors.Is(err, ErrReauthorizationRequired) {
		t.Fatalf("error = %v, want ErrReauthorizationRequired", err)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want one request and no refresh retry", requests)
	}
	if session.Data.AccessToken != "opaque-access" || session.Data.RefreshToken != "must-not-refresh" {
		t.Fatal("OAuth tokens changed despite fail-closed refresh policy")
	}
}

func TestSessionDoerRejectsForeignHostOverrideBeforeAuthorization(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	doer, _ := newTestSessionDoer(t, server.URL)
	request, err := http.NewRequest(http.MethodGet, server.URL+"/xrpc/com.atproto.space.listRecords", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "foreign.example"
	if _, err := doer.Do(context.Background(), request, "com.atproto.space.listRecords"); !errors.Is(err, repository.ErrTarget) {
		t.Fatalf("host override error = %v", err)
	}
	if requests != 0 {
		t.Fatalf("authorized requests = %d", requests)
	}
}

func TestSessionDoerRejectsEndpointPathDriftBeforeAuthorization(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	doer, _ := newTestSessionDoer(t, server.URL)
	request, err := http.NewRequest(http.MethodGet, server.URL+"/xrpc/com.atproto.space.listRecords", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := doer.Do(context.Background(), request, "com.atproto.space.getDelegationToken"); !errors.Is(err, repository.ErrTarget) {
		t.Fatalf("endpoint drift error = %v", err)
	}
	if requests != 0 {
		t.Fatalf("authorized requests = %d", requests)
	}
}

func TestSessionDoerRetriesOneFreshProofForNewDPoPNonce(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requests++
		if request.Header.Get("Authorization") != "DPoP opaque-access" || request.Header.Get("DPoP") == "" {
			t.Error("request omitted OAuth DPoP headers")
		}
		if requests == 1 {
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
			w.Header().Set("DPoP-Nonce", "fresh-test-nonce")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	doer, session := newTestSessionDoer(t, server.URL)
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+"/xrpc/com.atproto.space.getDelegationToken", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := doer.Do(context.Background(), request, "com.atproto.space.getDelegationToken")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || requests != 2 {
		t.Fatalf("status = %d, requests = %d", response.StatusCode, requests)
	}
	if session.Data.DPoPHostNonce != "fresh-test-nonce" {
		t.Fatalf("persisted nonce = %q", session.Data.DPoPHostNonce)
	}
}

func TestRejectedSessionIsRevokedAndDeleted(t *testing.T) {
	revocations := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		revocations++
		if request.Method != http.MethodPost || request.URL.Path != "/oauth/revoke" || request.Header.Get("DPoP") == "" {
			t.Error("revocation request omitted its exact endpoint or DPoP proof")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	privateKey, err := atcrypto.GeneratePrivateKeyP256()
	if err != nil {
		t.Fatal(err)
	}
	scopes, err := MailboxScopes(testMemberDID, "primary")
	if err != nil {
		t.Fatal(err)
	}
	data := oauth.ClientSessionData{
		AccountDID:                   syntax.DID(testMemberDID),
		SessionID:                    "rejected-session",
		AuthServerURL:                server.URL,
		AuthServerRevocationEndpoint: server.URL + "/oauth/revoke",
		Scopes:                       scopes,
		AccessToken:                  "synthetic-access",
		RefreshToken:                 "synthetic-refresh",
		DPoPPrivateKeyMultibase:      privateKey.Multibase(),
	}
	store := &testAuthStore{session: data}
	config := oauth.NewLocalhostConfig("http://127.0.0.1:49153/oauth/callback", scopes)
	app := oauth.NewClientApp(&config, store)
	app.Client = server.Client()
	manager := &Manager{app: app}
	rejection := errors.New("synthetic grant rejection")

	got := manager.rejectSession(context.Background(), data.AccountDID, data.SessionID, nil, rejection)
	if !errors.Is(got, rejection) {
		t.Fatalf("error = %v, want rejection cause", got)
	}
	if revocations != 2 {
		t.Fatalf("revocations = %d, want access and refresh token revocation", revocations)
	}
	if !store.deleted {
		t.Fatal("rejected OAuth session remained in local storage")
	}
}

func TestSteadySessionRevokeConfirmsBothTokensBeforeLocalDeletion(t *testing.T) {
	revocations := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		revocations++
		if request.Method != http.MethodPost || request.URL.Path != "/oauth/revoke" || request.Header.Get("DPoP") == "" {
			t.Error("revocation request omitted its exact endpoint or DPoP proof")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	manager, store := newSteadyRevokeTestManager(t, server)
	if err := manager.RevokeAndDelete(context.Background(), "steady-session"); err != nil {
		t.Fatal(err)
	}
	if revocations != 2 {
		t.Fatalf("revocations = %d, want access and refresh token revocation", revocations)
	}
	if !store.deleted {
		t.Fatal("confirmed revoked session remained in local storage")
	}
}

func TestSteadySessionRevokeRetainsEncryptedSessionWhenRemoteRevocationFails(t *testing.T) {
	revocations := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		revocations++
		if revocations == 1 {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	manager, store := newSteadyRevokeTestManager(t, server)
	err := manager.RevokeAndDelete(context.Background(), "steady-session")
	if err == nil || !strings.Contains(err.Error(), "retained for retry") {
		t.Fatalf("revocation error = %v", err)
	}
	if revocations != 2 {
		t.Fatalf("revocations = %d, want both remote attempts", revocations)
	}
	if store.deleted {
		t.Fatal("session was deleted before remote revocation was confirmed")
	}
}

func TestSteadySessionRevokeValidationFailuresHaveNoSideEffects(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Manager, *testAuthStore)
	}{
		{name: "wrong origin", mutate: func(_ *Manager, store *testAuthStore) {
			store.session.HostURL = "https://wrong.example"
		}},
		{name: "wrong space grant", mutate: func(manager *Manager, _ *testAuthStore) {
			manager.spaceKey = "secondary"
		}},
		{name: "widened grant", mutate: func(_ *Manager, store *testAuthStore) {
			store.session.Scopes = append(store.session.Scopes, "transition:generic")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			revocations := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				revocations++
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			manager, store := newSteadyRevokeTestManager(t, server)
			test.mutate(manager, store)
			if err := manager.RevokeAndDelete(context.Background(), "steady-session"); err == nil {
				t.Fatal("expected exact-session validation error")
			}
			if revocations != 0 {
				t.Fatalf("validation failure attempted %d remote revocations", revocations)
			}
			if store.deleted {
				t.Fatal("validation failure deleted the encrypted retry handle")
			}
		})
	}
}

func TestSteadySessionRevokeRetainsSessionWithoutRevocationEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("missing endpoint attempted a remote request")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	manager, store := newSteadyRevokeTestManager(t, server)
	store.session.AuthServerRevocationEndpoint = ""
	if err := manager.RevokeAndDelete(context.Background(), "steady-session"); err == nil || !strings.Contains(err.Error(), "retained for retry") {
		t.Fatalf("missing-endpoint error = %v", err)
	}
	if store.deleted {
		t.Fatal("missing endpoint deleted the encrypted retry handle")
	}
}

func TestSteadySessionRevokeReportsLocalDeletionFailureAfterRemoteConfirmation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	manager, store := newSteadyRevokeTestManager(t, server)
	store.deleteErr = errors.New("synthetic delete failure")
	err := manager.RevokeAndDelete(context.Background(), "steady-session")
	if err == nil || !strings.Contains(err.Error(), "remote OAuth revocation confirmed") {
		t.Fatalf("deletion error = %v", err)
	}
	if store.deleted {
		t.Fatal("failed local deletion was reported as deleted")
	}
}

func newSteadyRevokeTestManager(t *testing.T, server *httptest.Server) (*Manager, *testAuthStore) {
	t.Helper()
	privateKey, err := atcrypto.GeneratePrivateKeyP256()
	if err != nil {
		t.Fatal(err)
	}
	scopes, err := MailboxScopes(testMemberDID, "primary")
	if err != nil {
		t.Fatal(err)
	}
	data := oauth.ClientSessionData{
		AccountDID: syntax.DID(testMemberDID), SessionID: "steady-session", HostURL: server.URL,
		AuthServerURL: server.URL, AuthServerRevocationEndpoint: server.URL + "/oauth/revoke",
		Scopes: scopes, AccessToken: "synthetic-access", RefreshToken: "synthetic-refresh",
		DPoPPrivateKeyMultibase: privateKey.Multibase(),
	}
	store := &testAuthStore{session: data}
	config := oauth.NewLocalhostConfig("http://127.0.0.1:49153/oauth/callback", scopes)
	app := oauth.NewClientApp(&config, store)
	app.Client = server.Client()
	client, origin, err := newPinnedHTTPClient(server.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	return &Manager{
		app: app, did: syntax.DID(testMemberDID), origin: origin, spaceKey: "primary",
		client: client, profile: grantSteady, allowHTTP: true,
	}, store
}

func TestProvisioningSessionDoerAcceptsOnlyProvisioningGrant(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	privateKey, _ := atcrypto.GeneratePrivateKeyP256()
	scopes, _ := ProvisioningScopes(testMemberDID, "primary")
	client, origin, err := newPinnedHTTPClient(server.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	session := &oauth.ClientSession{
		Data: &oauth.ClientSessionData{
			AccountDID: syntax.DID(testMemberDID), HostURL: origin, Scopes: scopes,
			AccessToken: "synthetic-provisioning-access",
		},
		DPoPPrivateKey: privateKey,
	}
	doer := &SessionDoer{
		session: session, client: client, origin: origin, did: testMemberDID,
		spaceKey: "primary", profile: grantProvisioning,
	}
	request, _ := http.NewRequest(http.MethodPost, server.URL+"/xrpc/com.atproto.simplespace.createSpace", strings.NewReader(`{}`))
	response, err := doer.Do(context.Background(), request, "com.atproto.simplespace.createSpace")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	steady, _ := MailboxScopes(testMemberDID, "primary")
	session.Data.Scopes = steady
	if _, err := doer.Do(context.Background(), request, "com.atproto.simplespace.createSpace"); !errors.Is(err, repository.ErrUnauthorized) {
		t.Fatalf("steady grant in provisioner error = %v", err)
	}
	if requests != 1 {
		t.Fatalf("authorized requests = %d", requests)
	}
}

func TestProvisionerRevokesAndDeletesOneTimeSessionAfterSuccess(t *testing.T) {
	revocations := 0
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/oauth/revoke":
			revocations++
			w.WriteHeader(http.StatusOK)
		case "/xrpc/com.atproto.simplespace.createSpace":
			_, _ = io.WriteString(w, `{"uri":"at://`+testMemberDID+`/space/email.atmos.mailbox/primary"}`)
		case "/xrpc/com.atproto.simplespace.getSpace":
			_, _ = io.WriteString(w, `{"uri":"at://`+testMemberDID+`/space/email.atmos.mailbox/primary","policy":{"$type":"com.atproto.simplespace.defs#memberListPolicy"},"appAccess":{"$type":"com.atproto.simplespace.defs#open"}}`)
		case "/xrpc/com.atproto.simplespace.listMembers":
			_, _ = io.WriteString(w, `{"members":[]}`)
		default:
			http.NotFound(w, request)
		}
	}))
	defer server.Close()
	privateKey, _ := atcrypto.GeneratePrivateKeyP256()
	scopes, _ := ProvisioningScopes(testMemberDID, "primary")
	data := oauth.ClientSessionData{
		AccountDID: syntax.DID(testMemberDID), SessionID: "one-time-provisioning", HostURL: server.URL,
		AuthServerURL: server.URL, AuthServerRevocationEndpoint: server.URL + "/oauth/revoke",
		Scopes: scopes, AccessToken: "synthetic-access", RefreshToken: "synthetic-refresh",
		DPoPPrivateKeyMultibase: privateKey.Multibase(),
	}
	store := &testAuthStore{session: data}
	config := oauth.NewLocalhostConfig("http://127.0.0.1:49153/oauth/callback", scopes)
	app := oauth.NewClientApp(&config, store)
	app.Client = server.Client()
	client, origin, err := newPinnedHTTPClient(server.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	manager := &Manager{
		app: app, did: syntax.DID(testMemberDID), origin: origin, spaceKey: "primary",
		client: client, profile: grantProvisioning, allowHTTP: true,
	}
	provisioner := &Provisioner{manager: manager}
	store.getErr = errors.New("synthetic immediate reload failure")
	session, err := manager.sessionFromCallbackData(&data)
	if err != nil {
		t.Fatal(err)
	}
	result, err := provisioner.complete(context.Background(), session)
	if err != nil {
		t.Fatal(err)
	}
	if result.SpaceURI != "at://"+testMemberDID+"/space/email.atmos.mailbox/primary" || !result.Created {
		t.Fatalf("result = %#v", result)
	}
	if revocations != 2 || !store.deleted {
		t.Fatalf("revocations=%d deleted=%v", revocations, store.deleted)
	}
	if store.getCalls != 0 {
		t.Fatalf("callback session reloaded from store %d times", store.getCalls)
	}
}

func TestProvisionerRetainsOneTimeSessionWhenRemoteRevocationFails(t *testing.T) {
	revocations := 0
	revocationAvailable := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/oauth/revoke":
			revocations++
			if revocationAvailable || revocations == 1 {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusServiceUnavailable)
		case "/xrpc/com.atproto.simplespace.createSpace":
			_, _ = io.WriteString(w, `{"uri":"at://`+testMemberDID+`/space/email.atmos.mailbox/primary"}`)
		case "/xrpc/com.atproto.simplespace.getSpace":
			_, _ = io.WriteString(w, `{"uri":"at://`+testMemberDID+`/space/email.atmos.mailbox/primary","policy":{"$type":"com.atproto.simplespace.defs#memberListPolicy"},"appAccess":{"$type":"com.atproto.simplespace.defs#open"}}`)
		case "/xrpc/com.atproto.simplespace.listMembers":
			_, _ = io.WriteString(w, `{"members":[]}`)
		default:
			http.NotFound(w, request)
		}
	}))
	defer server.Close()
	privateKey, _ := atcrypto.GeneratePrivateKeyP256()
	scopes, _ := ProvisioningScopes(testMemberDID, "primary")
	data := oauth.ClientSessionData{
		AccountDID: syntax.DID(testMemberDID), SessionID: "one-time-provisioning", HostURL: server.URL,
		AuthServerURL: server.URL, AuthServerRevocationEndpoint: server.URL + "/oauth/revoke",
		Scopes: scopes, AccessToken: "synthetic-access", RefreshToken: "synthetic-refresh",
		DPoPPrivateKeyMultibase: privateKey.Multibase(),
	}
	store := &testAuthStore{session: data}
	config := oauth.NewLocalhostConfig("http://127.0.0.1:49153/oauth/callback", scopes)
	app := oauth.NewClientApp(&config, store)
	app.Client = server.Client()
	client, origin, err := newPinnedHTTPClient(server.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	manager := &Manager{
		app: app, did: syntax.DID(testMemberDID), origin: origin, spaceKey: "primary",
		client: client, profile: grantProvisioning, allowHTTP: true,
	}
	provisioner := &Provisioner{manager: manager}
	session, err := manager.sessionFromCallbackData(&data)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := provisioner.completeDetailed(context.Background(), session)
	if !outcome.Result.Created {
		t.Fatalf("outcome = %#v", outcome)
	}
	if err == nil || !strings.Contains(err.Error(), "retained for retry") {
		t.Fatalf("revocation error = %v", err)
	}
	if outcome.RetainedSessionID != data.SessionID {
		t.Fatalf("retained session ID = %q, want callback session", outcome.RetainedSessionID)
	}
	if strings.Contains(err.Error(), data.SessionID) {
		t.Fatal("cleanup error leaked the opaque retained session ID")
	}
	if revocations != 2 {
		t.Fatalf("revocations = %d, want both remote attempts", revocations)
	}
	if store.deleted {
		t.Fatal("one-time provisioning session was deleted before remote revocation was confirmed")
	}

	revocationAvailable = true
	if err := provisioner.RetryCleanup(context.Background(), outcome.RetainedSessionID); err != nil {
		t.Fatalf("retry retained provisioning cleanup: %v", err)
	}
	if !store.deleted {
		t.Fatal("confirmed retry did not delete the encrypted provisioning session")
	}
}

func TestProvisionerRetryCleanupRejectsNonProvisioningGrantWithoutRevocation(t *testing.T) {
	revocations := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		revocations++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	privateKey, err := atcrypto.GeneratePrivateKeyP256()
	if err != nil {
		t.Fatal(err)
	}
	steadyScopes, err := MailboxScopes(testMemberDID, "primary")
	if err != nil {
		t.Fatal(err)
	}
	provisioningScopes, err := ProvisioningScopes(testMemberDID, "primary")
	if err != nil {
		t.Fatal(err)
	}
	data := oauth.ClientSessionData{
		AccountDID: syntax.DID(testMemberDID), SessionID: "wrong-profile-session", HostURL: server.URL,
		AuthServerURL: server.URL, AuthServerRevocationEndpoint: server.URL + "/oauth/revoke",
		Scopes: steadyScopes, AccessToken: "synthetic-access", RefreshToken: "synthetic-refresh",
		DPoPPrivateKeyMultibase: privateKey.Multibase(),
	}
	store := &testAuthStore{session: data}
	config := oauth.NewLocalhostConfig("http://127.0.0.1:49153/oauth/callback", provisioningScopes)
	app := oauth.NewClientApp(&config, store)
	app.Client = server.Client()
	client, origin, err := newPinnedHTTPClient(server.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	provisioner := &Provisioner{manager: &Manager{
		app: app, did: syntax.DID(testMemberDID), origin: origin, spaceKey: "primary",
		client: client, profile: grantProvisioning, allowHTTP: true,
	}}
	if err := provisioner.RetryCleanup(context.Background(), data.SessionID); !errors.Is(err, repository.ErrUnauthorized) {
		t.Fatalf("wrong-profile cleanup error = %v", err)
	}
	if revocations != 0 || store.deleted {
		t.Fatalf("wrong-profile cleanup had side effects: revocations=%d deleted=%v", revocations, store.deleted)
	}
}

func TestProvisionerCleansUpOneTimeSessionAfterProvisioningFailure(t *testing.T) {
	revocations := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/oauth/revoke" {
			revocations++
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	privateKey, _ := atcrypto.GeneratePrivateKeyP256()
	scopes, _ := ProvisioningScopes(testMemberDID, "primary")
	data := oauth.ClientSessionData{
		AccountDID: syntax.DID(testMemberDID), SessionID: "failed-provisioning", HostURL: server.URL,
		AuthServerURL: server.URL, AuthServerRevocationEndpoint: server.URL + "/oauth/revoke",
		Scopes: scopes, AccessToken: "synthetic-access", RefreshToken: "synthetic-refresh",
		DPoPPrivateKeyMultibase: privateKey.Multibase(),
	}
	store := &testAuthStore{session: data}
	config := oauth.NewLocalhostConfig("http://127.0.0.1:49153/oauth/callback", scopes)
	app := oauth.NewClientApp(&config, store)
	app.Client = server.Client()
	client, origin, err := newPinnedHTTPClient(server.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	provisioner := &Provisioner{manager: &Manager{
		app: app, did: syntax.DID(testMemberDID), origin: origin, spaceKey: "primary",
		client: client, profile: grantProvisioning, allowHTTP: true,
	}}
	session := &oauth.ClientSession{Data: &data, Config: &config, Client: server.Client(), DPoPPrivateKey: privateKey}
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := provisioner.complete(canceledCtx, session); err == nil {
		t.Fatal("expected provisioning failure")
	}
	if revocations != 2 || !store.deleted {
		t.Fatalf("revocations=%d deleted=%v", revocations, store.deleted)
	}
}

func newTestSessionDoer(t *testing.T, origin string) (*SessionDoer, *oauth.ClientSession) {
	t.Helper()
	privateKey, err := atcrypto.GeneratePrivateKeyP256()
	if err != nil {
		t.Fatal(err)
	}
	scopes, err := MailboxScopes(testMemberDID, "primary")
	if err != nil {
		t.Fatal(err)
	}
	client, pinnedOrigin, err := newPinnedHTTPClient(origin, true)
	if err != nil {
		t.Fatal(err)
	}
	session := &oauth.ClientSession{
		Data: &oauth.ClientSessionData{
			AccountDID:    syntax.DID(testMemberDID),
			HostURL:       pinnedOrigin,
			AuthServerURL: pinnedOrigin,
			Scopes:        scopes,
			AccessToken:   "opaque-access",
			RefreshToken:  "must-not-refresh",
		},
		DPoPPrivateKey: privateKey,
	}
	return &SessionDoer{
		session:  session,
		client:   client,
		origin:   pinnedOrigin,
		did:      testMemberDID,
		spaceKey: "primary",
	}, session
}

type testAuthStore struct {
	session   oauth.ClientSessionData
	deleted   bool
	deleteErr error
	getErr    error
	getCalls  int
}

func (s *testAuthStore) GetSession(_ context.Context, did syntax.DID, sessionID string) (*oauth.ClientSessionData, error) {
	s.getCalls++
	if s.getErr != nil {
		return nil, s.getErr
	}
	if s.deleted || did != s.session.AccountDID || sessionID != s.session.SessionID {
		return nil, errors.New("session not found")
	}
	copy := s.session
	return &copy, nil
}

func (s *testAuthStore) SaveSession(_ context.Context, session oauth.ClientSessionData) error {
	s.session = session
	return nil
}

func (s *testAuthStore) DeleteSession(_ context.Context, did syntax.DID, sessionID string) error {
	if did != s.session.AccountDID || sessionID != s.session.SessionID {
		return errors.New("wrong session deletion target")
	}
	if s.deleteErr != nil {
		return s.deleteErr
	}
	s.deleted = true
	return nil
}

func (*testAuthStore) GetAuthRequestInfo(context.Context, string) (*oauth.AuthRequestData, error) {
	return nil, errors.New("auth request not found")
}

func (*testAuthStore) SaveAuthRequestInfo(context.Context, oauth.AuthRequestData) error {
	return nil
}

func (*testAuthStore) DeleteAuthRequestInfo(context.Context, string) error {
	return nil
}

func TestPinnedHTTPClientAllowsOnlyExactLoopbackOriginAndRefusesRedirect(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			_, _ = io.WriteString(w, "ok")
		case "/redirect":
			http.Redirect(w, r, server.URL+"/ok", http.StatusFound)
		}
	}))
	defer server.Close()
	client, origin, err := newPinnedHTTPClient(server.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	if origin != server.URL {
		t.Fatalf("origin = %s", origin)
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+"/ok", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	redirect, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+"/redirect", nil)
	if _, err := client.Do(redirect); err == nil {
		t.Fatal("authenticated redirect was followed")
	}
	other, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1:1/escape", nil)
	if _, err := client.Do(other); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("wrong-origin error = %v", err)
	}
}

func TestCanonicalizeOriginNormalizesSchemeHostAndDefaultPort(t *testing.T) {
	origin, err := url.Parse("HTTPS://SPACES.EXAMPLE:443/")
	if err != nil {
		t.Fatal(err)
	}
	canonicalizeOrigin(origin)
	if got := origin.String(); got != "https://spaces.example/" {
		t.Fatalf("canonical origin = %q", got)
	}
}

func TestCanonicalizedLoopbackHTTPUsesPort80(t *testing.T) {
	origin, err := url.Parse("http://127.0.0.1:80/")
	if err != nil {
		t.Fatal(err)
	}
	canonicalizeOrigin(origin)
	if got := originDialPort(origin); got != "80" {
		t.Fatalf("canonical HTTP dial port = %q", got)
	}
}

func TestNewManagerSupportsStrictHTTPSPublicClient(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer provider.Close()
	manager, err := New(Config{
		DID:         testMemberDID,
		Handle:      "scott.spaces-alpha.bsky.network",
		Origin:      provider.URL,
		CallbackURL: "https://spaces.comail.at/oauth/steady/callback",
		ClientID:    "https://spaces.comail.at/oauth/steady/client-metadata.json",
		SpaceKey:    "primary",
		AllowHTTP:   true,
	}, &testAuthStore{})
	if err != nil {
		t.Fatal(err)
	}
	if manager.app.Config.ClientID != "https://spaces.comail.at/oauth/steady/client-metadata.json" {
		t.Fatalf("client ID = %q", manager.app.Config.ClientID)
	}
	if manager.app.Config.CallbackURL != "https://spaces.comail.at/oauth/steady/callback" {
		t.Fatalf("callback = %q", manager.app.Config.CallbackURL)
	}
	metadata := manager.ClientMetadata()
	if metadata.ClientID != manager.app.Config.ClientID || len(metadata.RedirectURIs) != 1 || metadata.RedirectURIs[0] != manager.app.Config.CallbackURL {
		t.Fatalf("metadata = %#v", metadata)
	}
}

func TestNewManagerRejectsUnsafePublicClientMetadata(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer provider.Close()
	tests := []Config{
		{CallbackURL: "https://spaces.comail.at/oauth/callback", ClientID: "http://spaces.comail.at/metadata"},
		{CallbackURL: "https://spaces.comail.at/oauth/callback", ClientID: "https://other.example/metadata"},
		{CallbackURL: "https://127.0.0.1/oauth/callback", ClientID: "https://127.0.0.1/metadata"},
		{CallbackURL: "https://spaces.comail.at/oauth/callback?did=secret", ClientID: "https://spaces.comail.at/metadata"},
		{CallbackURL: "https://spaces.comail.at/oauth/callback", ClientID: ""},
	}
	for index, configured := range tests {
		configured.DID = testMemberDID
		configured.Handle = "scott.spaces-alpha.bsky.network"
		configured.Origin = provider.URL
		configured.SpaceKey = "primary"
		configured.AllowHTTP = true
		if _, err := New(configured, &testAuthStore{}); err == nil {
			t.Fatalf("case %d accepted unsafe public client", index)
		}
	}
}

func TestTrackingAuthStoreCapturesStatePerStartContext(t *testing.T) {
	base := &testAuthStore{}
	store := trackingAuthStore{ClientAuthStore: base}
	capture := make(chan string, 1)
	ctx := context.WithValue(context.Background(), authStateCaptureKey{}, capture)
	if err := store.SaveAuthRequestInfo(ctx, oauth.AuthRequestData{State: "opaque-oauth-state"}); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-capture:
		if got != "opaque-oauth-state" {
			t.Fatalf("captured state = %q", got)
		}
	default:
		t.Fatal("OAuth state was not captured")
	}
}
