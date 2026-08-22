package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testAccountDID = "did:plc:rfwhywgeym2ek7ioeyxkvsn6"

func TestLoadConfigRequiresExplicitEnableAndStrictExactTargets(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "broker.json")
	configured := validTestConfig()
	data, err := json.Marshal(configured)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Enabled || len(loaded.Accounts) != 1 || loaded.Accounts[0].DID != configured.Accounts[0].DID {
		t.Fatalf("loaded config = %#v", loaded)
	}

	configured.Enabled = false
	if err := validateConfig(configured); err == nil {
		t.Fatal("default-off config was accepted without explicit enable")
	}
	configured = validTestConfig()
	configured.Listen = "0.0.0.0:39095"
	if err := validateConfig(configured); err == nil {
		t.Fatal("public listener was accepted")
	}
	configured = validTestConfig()
	configured.BrokerOrigin = "http://spaces.comail.at"
	if err := validateConfig(configured); err == nil {
		t.Fatal("non-HTTPS broker origin was accepted")
	}
	configured = validTestConfig()
	configured.Accounts[0].PDSOrigin = "https://other.example"
	if err := validateConfig(configured); err == nil {
		t.Fatal("PDS and space-host origin drift was accepted")
	}
}

func TestLoadConfigRejectsUnknownFieldsAndRelativeSecretPaths(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "broker.json")
	data, _ := json.Marshal(validTestConfig())
	data = append(data[:len(data)-1], []byte(",\"surprise\":true}")...)
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(configPath); err == nil {
		t.Fatal("unknown config field was accepted")
	}
	configured := validTestConfig()
	configured.RelayTokenFile = "relative"
	if err := validateConfig(configured); err == nil {
		t.Fatal("relative secret path was accepted")
	}
}

func TestRootHandlerExposesOnlyHealthAndBrokerRoutes(t *testing.T) {
	broker := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v1/onboarding/start" {
			response.WriteHeader(http.StatusTeapot)
			return
		}
		http.NotFound(response, request)
	})
	handler := newRootHandler(broker)

	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if health.Code != http.StatusOK || health.Body.String() != "{\"ok\":true}" || health.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("health response: status=%d body=%q headers=%v", health.Code, health.Body.String(), health.Header())
	}
	postHealth := httptest.NewRecorder()
	handler.ServeHTTP(postHealth, httptest.NewRequest(http.MethodPost, "/healthz", nil))
	if postHealth.Code != http.StatusNotFound {
		t.Fatalf("POST health status = %d", postHealth.Code)
	}
	forwarded := httptest.NewRecorder()
	handler.ServeHTTP(forwarded, httptest.NewRequest(http.MethodPost, "/v1/onboarding/start", nil))
	if forwarded.Code != http.StatusTeapot {
		t.Fatalf("broker route status = %d", forwarded.Code)
	}
}

func TestReadOwnerSecretRejectsWhitespaceAndShortBearer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "relay-token")
	if err := os.WriteFile(path, []byte(strings.Repeat("a", 32)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	secret, err := readOwnerSecret(path)
	if err != nil || secret != strings.Repeat("a", 32) {
		t.Fatalf("secret=%q err=%v", secret, err)
	}
	if err := os.WriteFile(path, []byte("too-short\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readOwnerSecret(path); err == nil {
		t.Fatal("short bearer was accepted")
	}
}

func TestOpenOrCreateVaultIsIdempotentAndRejectsPartialState(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	vaultPath := filepath.Join(dir, "oauth.vault")
	keyPath := filepath.Join(dir, "oauth.key")
	created, err := openOrCreateVault(vaultPath, keyPath)
	if err != nil || created == nil {
		t.Fatalf("create vault: store=%T err=%v", created, err)
	}
	reopened, err := openOrCreateVault(vaultPath, keyPath)
	if err != nil || reopened == nil {
		t.Fatalf("reopen vault: store=%T err=%v", reopened, err)
	}
	for _, path := range []string{vaultPath, keyPath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("state file %s: mode=%v", path, info.Mode().Perm())
		}
	}

	partialDir := t.TempDir()
	if err := os.Chmod(partialDir, 0o700); err != nil {
		t.Fatal(err)
	}
	partialVault := filepath.Join(partialDir, "oauth.vault")
	if err := os.WriteFile(partialVault, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openOrCreateVault(partialVault, filepath.Join(partialDir, "missing.key")); err == nil {
		t.Fatal("partial vault state was accepted or overwritten")
	}
}

func validTestConfig() config {
	return config{
		Enabled:             true,
		Listen:              "127.0.0.1:39095",
		BrokerOrigin:        "https://spaces.comail.at",
		ReturnURL:           "https://comail.at/webmail/login",
		RelayTokenFile:      "/run/credentials/relay-token",
		VaultFile:           "/var/lib/comail-spaces-broker/oauth.vault",
		VaultKeyFile:        "/run/credentials/oauth-vault-key",
		PLCOrigin:           "https://plc.directory",
		ProofTimeoutSeconds: 30,
		ShutdownSeconds:     10,
		Accounts: []accountConfig{{
			DID: testAccountDID, Handle: "scott.spaces-alpha.bsky.network",
			PDSOrigin: "https://spaces-alpha.host.bsky.network", SpaceHostOrigin: "https://spaces-alpha.host.bsky.network",
			SpaceKey: "primary", ProvisioningMetadataPath: "/oauth/client/a8KzP2/provision.json",
			SteadyMetadataPath: "/oauth/client/a8KzP2/steady.json",
		}},
	}
}
