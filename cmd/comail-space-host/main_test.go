package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigRequiresExactUniqueMailboxesAndSeparateSecrets(t *testing.T) {
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
		"providerOrigin":"https://spaces.inbox.comail.at",
		"serviceIssuerDid":"did:web:mailbox-adapter.comail.at",
		"serviceAudience":"did:web:spaces.inbox.comail.at#mailbox",
		"serviceKeyFile":` + quote(keyPath) + `,
		"relayTokenFile":` + quote(tokenPath) + `,
		"mailboxes":[{"did":"did:plc:alpha","spaceKey":"default","authorityCertificateSha256":"` + strings.Repeat("a", 64) + `","evidenceFile":` + quote(evidencePath) + `}]
	}`
	if err := os.WriteFile(configPath, []byte(configJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := loadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Mailboxes) != 1 || config.Mailboxes[0].DID != "did:plc:alpha" {
		t.Fatalf("config=%#v", config)
	}
	config.Mailboxes = append(config.Mailboxes, config.Mailboxes[0])
	if err := validateConfig(config); err == nil {
		t.Fatal("duplicate mailbox was accepted")
	}
}

func TestValidateConfigRejectsPublicListenerAndNonHTTPSProvider(t *testing.T) {
	base := config{
		Listen: "127.0.0.1:39094", ProviderOrigin: "https://spaces.inbox.comail.at",
		ServiceIssuerDID: "did:web:mailbox-adapter.comail.at", ServiceAudience: "did:web:spaces.inbox.comail.at#mailbox",
		ServiceKeyFile: "/run/credentials/key", RelayTokenFile: "/run/credentials/token",
		Mailboxes: []mailboxConfig{{DID: "did:plc:alpha", SpaceKey: "default", AuthorityCertificateSHA256: strings.Repeat("a", 64), EvidenceFile: "/run/credentials/evidence"}},
	}
	badListener := base
	badListener.Listen = "0.0.0.0:39094"
	if validateConfig(badListener) == nil {
		t.Fatal("public listener accepted")
	}
	badOrigin := base
	badOrigin.ProviderOrigin = "http://spaces.inbox.comail.at"
	if validateConfig(badOrigin) == nil {
		t.Fatal("non-HTTPS provider accepted")
	}
}

func quote(value string) string { return `"` + value + `"` }
