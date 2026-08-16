package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateOptionsRequiresExactLoopbackAndPinnedTarget(t *testing.T) {
	valid := options{
		Listen: "127.0.0.1:39094", Provider: "happyview", Origin: "http://127.0.0.1:39090",
		BasePath: "/comail-pds-lab", PublicHost: "little-mac.lobster-hake.ts.net",
		DID: "did:plc:comailpdsshadowsynthetic", SpaceKey: "default",
		CookieFile: "/private/cookie", TokenFile: "/private/token", Commit: true,
		AuthorityCertificateSHA256: strings.Repeat("a", 64),
	}
	if err := validateOptions(valid); err != nil {
		t.Fatalf("valid options: %v", err)
	}
	for _, mutate := range []func(*options){
		func(value *options) { value.Listen = "0.0.0.0:39094" },
		func(value *options) { value.Provider = "unknown" },
		func(value *options) { value.DID = "not-a-did" },
		func(value *options) { value.SpaceKey = "../other" },
		func(value *options) { value.PublicHost = "bad.example/path" },
		func(value *options) { value.CookieFile = "relative" },
		func(value *options) { value.Commit = false },
		func(value *options) { value.AuthorityCertificateSHA256 = "not-a-digest" },
	} {
		invalid := valid
		mutate(&invalid)
		if err := validateOptions(invalid); err == nil {
			t.Fatalf("invalid options were accepted: %#v", invalid)
		}
	}
}

func TestReadOwnerSecretRejectsBroadFile(t *testing.T) {
	root := t.TempDir()
	private := filepath.Join(root, "private")
	if err := os.WriteFile(private, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if value, err := readOwnerSecret(private); err != nil || value != "secret" {
		t.Fatalf("private secret value=%q err=%v", value, err)
	}
	broad := filepath.Join(root, "broad")
	if err := os.WriteFile(broad, []byte("secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readOwnerSecret(broad); err == nil {
		t.Fatal("broad secret file was accepted")
	}
}
