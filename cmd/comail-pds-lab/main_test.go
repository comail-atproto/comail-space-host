package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/comail-atproto/comail-space-host/internal/oauthclient"
)

func TestUsageAdvertisesOneTimeOAuthProvisioning(t *testing.T) {
	text := usage()
	if !strings.Contains(text, "oauth-provision") || !strings.Contains(text, "one-time") {
		t.Fatalf("usage omitted one-time OAuth provisioning: %q", text)
	}
}

func TestOAuthCallbackGateSerializesAndRetriesOnlyInvalidCallbacks(t *testing.T) {
	var gate oauthCallbackGate
	if !gate.begin() || gate.begin() {
		t.Fatal("callback gate did not serialize processing")
	}
	gate.finish(oauthclient.ErrInvalidCallback)
	if !gate.begin() {
		t.Fatal("invalid callback incorrectly terminated the listener")
	}
	gate.finish(errors.New("terminal validated callback failure"))
	if gate.begin() {
		t.Fatal("terminal callback failure allowed another token exchange")
	}
}

func TestOAuthCallbackGateNeverReopensAcrossTerminalFinishRace(t *testing.T) {
	for range 1000 {
		var gate oauthCallbackGate
		if !gate.begin() {
			t.Fatal("initial callback was not admitted")
		}
		start := make(chan struct{})
		admitted := make(chan bool, 1)
		finished := make(chan struct{})
		go func() {
			<-start
			gate.finish(nil)
			close(finished)
		}()
		go func() {
			<-start
			admitted <- gate.begin()
		}()
		close(start)
		if <-admitted {
			t.Fatal("callback was admitted during terminal transition")
		}
		<-finished
		if gate.begin() {
			t.Fatal("callback gate reopened after terminal completion")
		}
	}
}

func TestHappyViewProofRequiresExplicitProviderAndCommit(t *testing.T) {
	valid := happyViewProofOptions{
		Provider:   "happyview",
		Commit:     true,
		Archive:    filepath.Join(t.TempDir(), "archive.sqlite"),
		Origin:     "http://127.0.0.1:39090",
		DID:        "did:plc:test",
		SpaceKey:   "primary",
		Epoch:      happyViewCertifiedEpoch,
		CookieFile: filepath.Join(t.TempDir(), "cookie"),
		WorkDir:    filepath.Join(t.TempDir(), "new-proof"),
	}
	missingProvider := valid
	missingProvider.Provider = ""
	if err := validateHappyViewProofOptions(missingProvider); !errors.Is(err, errHappyViewWriteConfirmation) {
		t.Fatalf("provider error = %v", err)
	}
	dry := valid
	dry.Commit = false
	if err := validateHappyViewProofOptions(dry); !errors.Is(err, errHappyViewWriteConfirmation) {
		t.Fatalf("commit error = %v", err)
	}
}

func TestHappyViewProofRequiresExactlyOneClosedSource(t *testing.T) {
	valid := happyViewProofOptions{
		Provider:   "happyview",
		Commit:     true,
		Archive:    filepath.Join(t.TempDir(), "archive.sqlite"),
		Origin:     "http://127.0.0.1:39090",
		DID:        "did:plc:test",
		SpaceKey:   "primary",
		Epoch:      happyViewCertifiedEpoch,
		CookieFile: filepath.Join(t.TempDir(), "cookie"),
		WorkDir:    filepath.Join(t.TempDir(), "new-proof"),
	}
	missing := valid
	missing.Archive = ""
	if err := validateHappyViewProofOptions(missing); err == nil {
		t.Fatal("accepted missing source")
	}
	both := valid
	both.Snapshot = filepath.Join(t.TempDir(), "snapshot.sqlite")
	if err := validateHappyViewProofOptions(both); err == nil {
		t.Fatal("accepted both archive and snapshot")
	}
	snapshot := valid
	snapshot.Archive = ""
	snapshot.Snapshot = filepath.Join(t.TempDir(), "snapshot.sqlite")
	if err := validateHappyViewProofOptions(snapshot); err != nil {
		t.Fatalf("rejected one closed snapshot: %v", err)
	}
}

func TestHappyViewCaptureHandlerStoresOnlyExpectedCookie(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "cookie")
	result := make(chan error, 1)
	handler := happyViewCaptureHandler("one-time", out, result)

	wrong := httptest.NewRequest(http.MethodGet, "/capture/wrong", nil)
	wrong.AddCookie(&http.Cookie{Name: "happyview_session", Value: "signed-value"})
	wrongResponse := httptest.NewRecorder()
	handler.ServeHTTP(wrongResponse, wrong)
	if wrongResponse.Code != http.StatusNotFound {
		t.Fatalf("wrong nonce status = %d", wrongResponse.Code)
	}
	if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("wrong nonce wrote a cookie")
	}

	request := httptest.NewRequest(http.MethodGet, "/capture/one-time", nil)
	request.AddCookie(&http.Cookie{Name: "happyview_session", Value: "signed-value"})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "happyview_session=signed-value\n" {
		t.Fatalf("stored cookie = %q", data)
	}
	info, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("cookie mode = %o", info.Mode().Perm())
	}
}

func TestHappyViewProofPinsLoopbackOriginAndEpoch(t *testing.T) {
	valid := happyViewProofOptions{
		Provider:   "happyview",
		Commit:     true,
		Archive:    filepath.Join(t.TempDir(), "archive.sqlite"),
		Origin:     "http://127.0.0.1:39090",
		DID:        "did:plc:test",
		SpaceKey:   "primary",
		Epoch:      happyViewCertifiedEpoch,
		CookieFile: filepath.Join(t.TempDir(), "cookie"),
		WorkDir:    filepath.Join(t.TempDir(), "new-proof"),
	}
	remote := valid
	remote.Origin = "https://happyview.example.test"
	if err := validateHappyViewProofOptions(remote); err == nil {
		t.Fatal("accepted non-loopback lab origin")
	}
	wrongEpoch := valid
	wrongEpoch.Epoch = "moving-main"
	if err := validateHappyViewProofOptions(wrongEpoch); err == nil {
		t.Fatal("accepted uncertified HappyView epoch")
	}
}

func TestHappyViewAuthorityCertificationRequiresDedicatedSpaceAndWriteConfirmation(t *testing.T) {
	valid := happyViewAuthorityOptions{
		Provider: "happyview", Commit: true, Origin: "http://127.0.0.1:39090",
		BasePath: "/comail-pds-lab", PublicHost: "happyview.example.test",
		DID: "did:plc:test", SpaceKey: "comail-cert-example", Epoch: happyViewCertifiedEpoch,
		CookieFile: filepath.Join(t.TempDir(), "cookie"), WorkDir: filepath.Join(t.TempDir(), "new-cert"),
	}
	if err := validateHappyViewAuthorityOptions(valid); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*happyViewAuthorityOptions){
		"no commit":     func(value *happyViewAuthorityOptions) { value.Commit = false },
		"real mailbox":  func(value *happyViewAuthorityOptions) { value.SpaceKey = "primary" },
		"remote origin": func(value *happyViewAuthorityOptions) { value.Origin = "https://example.test" },
		"moving epoch":  func(value *happyViewAuthorityOptions) { value.Epoch = "main" },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := valid
			mutate(&invalid)
			if err := validateHappyViewAuthorityOptions(invalid); err == nil {
				t.Fatal("accepted unsafe authority certification options")
			}
		})
	}
}
