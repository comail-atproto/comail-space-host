package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/comail-atproto/comail-space-host/internal/providers/happyview"
	"github.com/comail-atproto/comail-space-host/internal/shadowagent"
)

func TestWriteIdentityDocumentContainsOnlyMatchingPublicIdentity(t *testing.T) {
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := writeIdentityDocument(&output, "did:web:inbox.comail.at:mailbox-adapter", keyPath); err != nil {
		t.Fatal(err)
	}
	value := output.String()
	if !strings.Contains(value, `"id":"did:web:inbox.comail.at:mailbox-adapter"`) || strings.Contains(value, "PRIVATE KEY") {
		t.Fatalf("unexpected identity document: %s", value)
	}
}

func TestLoadConfigRequiresCertifiedProviderAndSeparateSecrets(t *testing.T) {
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPath := filepath.Join(dir, "key.pem")
	tokenPath := filepath.Join(dir, "relay-token")
	evidencePath := filepath.Join(dir, "evidence.json")
	_ = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
	_ = os.WriteFile(tokenPath, []byte("relay-token-secret"), 0o600)
	_ = os.WriteFile(evidencePath, []byte(`{}`), 0o600)
	configPath := filepath.Join(dir, "config.json")
	configJSON := `{
		"listen":"127.0.0.1:39094",
		"providerOrigin":"https://inbox.comail.at/spaces",
		"serviceIssuerDid":"did:web:inbox.comail.at:mailbox-adapter",
		"serviceAudience":"did:web:inbox.comail.at#mailbox",
		"serviceKeyFile":` + quote(keyPath) + `,
		"relayTokenFile":` + quote(tokenPath) + `,
		"authorityCertificateSha256":"` + strings.Repeat("a", 64) + `",
		"evidenceFile":` + quote(evidencePath) + `
	}`
	if err := os.WriteFile(configPath, []byte(configJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := loadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if config.AuthorityCertificateSHA256 != strings.Repeat("a", 64) || config.EvidenceFile != evidencePath {
		t.Fatalf("config=%#v", config)
	}
	config.EvidenceFile = "relative"
	if err := validateConfig(config); err == nil {
		t.Fatal("relative provider evidence was accepted")
	}
}

func TestValidateConfigRejectsPublicListenerAndNonHTTPSProvider(t *testing.T) {
	base := config{
		Listen: "127.0.0.1:39094", ProviderOrigin: "https://inbox.comail.at/spaces",
		ServiceIssuerDID: "did:web:inbox.comail.at:mailbox-adapter", ServiceAudience: "did:web:inbox.comail.at#mailbox",
		ServiceKeyFile: "/run/credentials/key", RelayTokenFile: "/run/credentials/token",
		AuthorityCertificateSHA256: strings.Repeat("a", 64), EvidenceFile: "/run/credentials/evidence",
	}
	badListener := base
	badListener.Listen = "0.0.0.0:39094"
	if validateConfig(badListener) == nil {
		t.Fatal("public listener accepted")
	}
	badOrigin := base
	badOrigin.ProviderOrigin = "http://inbox.comail.at/spaces"
	if validateConfig(badOrigin) == nil {
		t.Fatal("non-HTTPS provider accepted")
	}
}

func TestValidateConfigAcceptsCertifiedProviderWithoutStaticMailboxes(t *testing.T) {
	configured := config{
		Listen: "127.0.0.1:39094", ProviderOrigin: "https://inbox.comail.at/spaces",
		ServiceIssuerDID: "did:web:inbox.comail.at:mailbox-adapter", ServiceAudience: "did:web:inbox.comail.at#mailbox",
		ServiceKeyFile: "/run/credentials/key", RelayTokenFile: "/run/credentials/token",
		AuthorityCertificateSHA256: strings.Repeat("a", 64), EvidenceFile: "/run/credentials/provider-evidence",
		ShutdownSeconds: 10,
	}
	if err := validateConfig(configured); err != nil {
		t.Fatal(err)
	}
}

func TestReadOwnerSecretAcceptsOnlyExactSystemdCredentialShape(t *testing.T) {
	credentialDirectory := filepath.Join(t.TempDir(), "service-visible")
	if err := os.Mkdir(credentialDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(credentialDirectory, "relay-token")
	if err := os.WriteFile(tokenPath, []byte("relay-token-secret\n"), 0o440); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CREDENTIALS_DIRECTORY", credentialDirectory)
	if token, err := readOwnerSecret(tokenPath); err != nil || token != "relay-token-secret" {
		t.Fatalf("read systemd relay token: token=%q err=%v", token, err)
	}

	t.Setenv("CREDENTIALS_DIRECTORY", "")
	if _, err := readOwnerSecret(tokenPath); err == nil {
		t.Fatal("accepted group-readable relay token outside CREDENTIALS_DIRECTORY")
	}
}

type reusableHappyViewDoer struct {
	status      int
	body        string
	membersBody string
	calls       int
}

func (d *reusableHappyViewDoer) Do(_ context.Context, request *http.Request, endpoint string) (*http.Response, error) {
	d.calls++
	status := d.status
	body := d.body
	if endpoint == "com.atproto.simplespace.listMembers" {
		status = http.StatusOK
		body = d.membersBody
	} else if endpoint != "com.atproto.space.getSpace" {
		return nil, context.Canceled
	}
	return &http.Response{
		StatusCode: status, Body: io.NopCloser(strings.NewReader(body)),
		Header: make(http.Header), Request: request,
	}, nil
}

func TestHappyViewMailboxResolverPinsCertifiedTargetAndRechecksGrant(t *testing.T) {
	const did = "did:plc:dynamicmailboxowner"
	const serviceDID = "did:web:inbox.comail.at:mailbox-adapter"
	certificate := strings.Repeat("a", 64)
	spaceURI := "at://" + did + "/space/email.atmos.mailbox/default"
	doer := &reusableHappyViewDoer{status: http.StatusOK, body: `{
		"uri":"` + spaceURI + `",
		"space":{
			"did":"` + did + `","authority_did":"` + did + `","creator_did":"` + did + `",
			"type":"email.atmos.mailbox","skey":"default","mint_policy":"member-list","app_access":{"type":"open"},
			"config":{"membership_public":false,"records_public":false,"allowedCollections":["email.atmos.folder","email.atmos.message","email.atmos.messageState","email.atmos.blobChunk","email.atmos.blobManifest","email.atmos.blobIndex"]}
		}
	}`, membersBody: `{"members":[{"did":"` + did + `","access":"write"},{"did":"` + serviceDID + `","access":"write"}]}`}
	resolver, err := newHappyViewMailboxResolver("https://inbox.comail.at/spaces", serviceDID, "relay-token", certificate, doer)
	if err != nil {
		t.Fatal(err)
	}
	target := shadowagent.RouteTarget{
		ProviderID: "happyview@" + happyview.CertifiedEpoch,
		Origin:     "https://inbox.comail.at/spaces", SpaceURI: spaceURI, RepoDID: did,
		Epoch: happyview.CertifiedEpoch, AuthorityCertificateSHA256: certificate,
	}
	handler, err := resolver(t.Context(), target)
	if err != nil || handler == nil || doer.calls != 2 {
		t.Fatalf("handler=%T calls=%d error=%v", handler, doer.calls, err)
	}

	mux, err := shadowagent.NewResolvingMultiplexer("relay-token", resolver)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"version":1,"target":{"providerId":"` + target.ProviderID + `","origin":"` + target.Origin + `","spaceUri":"` + target.SpaceURI + `","repoDid":"` + target.RepoDID + `","epoch":"` + target.Epoch + `","authorityCertificateSha256":"` + certificate + `"}}`
	request := httptest.NewRequest(http.MethodPost, "/v1/capabilities", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer relay-token")
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusOK || doer.calls != 4 {
		t.Fatalf("status=%d calls=%d body=%s", response.Code, doer.calls, response.Body.String())
	}

	wrong := target
	wrong.AuthorityCertificateSHA256 = strings.Repeat("b", 64)
	if _, err := resolver(t.Context(), wrong); err == nil || doer.calls != 4 {
		t.Fatalf("certificate mismatch reached provider: calls=%d error=%v", doer.calls, err)
	}
	doer.status = http.StatusForbidden
	if _, err := resolver(t.Context(), target); err == nil || doer.calls != 5 {
		t.Fatalf("revoked grant result: calls=%d error=%v", doer.calls, err)
	}
	doer.status = http.StatusOK
	doer.membersBody = `{"members":[{"did":"` + did + `","access":"write"},{"did":"` + serviceDID + `","access":"read"}]}`
	if _, err := resolver(t.Context(), target); err == nil || doer.calls != 7 {
		t.Fatalf("downgraded grant result: calls=%d error=%v", doer.calls, err)
	}
}

func quote(value string) string { return `"` + value + `"` }
