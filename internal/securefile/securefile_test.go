// SPDX-License-Identifier: AGPL-3.0-or-later

package securefile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadAcceptsPrivateFileAndSystemdCredential(t *testing.T) {
	privatePath := writeFile(t, t.TempDir(), "private", 0o600)
	if got, err := Read(privatePath, 32); err != nil || string(got) != "secret" {
		t.Fatalf("read private file: got=%q err=%v", got, err)
	}

	credentialDirectory := filepath.Join(t.TempDir(), "service-visible")
	if err := os.Mkdir(credentialDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	credentialPath := writeFile(t, credentialDirectory, "relay-token", 0o440)
	t.Setenv("CREDENTIALS_DIRECTORY", credentialDirectory)
	if got, err := Read(credentialPath, 32); err != nil || string(got) != "secret" {
		t.Fatalf("read systemd credential: got=%q err=%v", got, err)
	}
}

func TestReadRejectsBroadOrMisplacedFiles(t *testing.T) {
	credentialDirectory := t.TempDir()
	t.Setenv("CREDENTIALS_DIRECTORY", credentialDirectory)

	outside := writeFile(t, t.TempDir(), "outside", 0o440)
	if _, err := Read(outside, 32); err == nil {
		t.Fatal("accepted group-readable file outside CREDENTIALS_DIRECTORY")
	}

	nestedDirectory := filepath.Join(credentialDirectory, "nested")
	if err := os.Mkdir(nestedDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	nested := writeFile(t, nestedDirectory, "nested", 0o440)
	if _, err := Read(nested, 32); err == nil {
		t.Fatal("accepted nested file below CREDENTIALS_DIRECTORY")
	}

	broad := writeFile(t, credentialDirectory, "broad", 0o444)
	if _, err := Read(broad, 32); err == nil {
		t.Fatal("accepted world-readable credential")
	}

	target := writeFile(t, credentialDirectory, "target", 0o600)
	symlink := filepath.Join(credentialDirectory, "symlink")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(symlink, 32); err == nil {
		t.Fatal("accepted symlink")
	}
}

func TestReadEnforcesSizeBound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bounded")
	if err := os.WriteFile(path, []byte("too-large"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path, 3); err == nil {
		t.Fatal("accepted file above size bound")
	}
}

func writeFile(t *testing.T, directory, name string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte("secret"), mode); err != nil {
		t.Fatal(err)
	}
	return path
}
