package contracts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLexiconsAreValidAndIDsMatchPaths(t *testing.T) {
	root := filepath.Join("..", "..", "lexicons", "email", "atmos")
	want := map[string]string{
		"message.json":      "email.atmos.message",
		"messageState.json": "email.atmos.messageState",
		"folder.json":       "email.atmos.folder",
	}
	for name, wantID := range want {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Lexicon int                        `json:"lexicon"`
			ID      string                     `json:"id"`
			Defs    map[string]json.RawMessage `json:"defs"`
		}
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if doc.Lexicon != 1 || doc.ID != wantID || len(doc.Defs["main"]) == 0 {
			t.Fatalf("%s: lexicon=%d id=%q main=%t", name, doc.Lexicon, doc.ID, len(doc.Defs["main"]) > 0)
		}
	}
}

func TestRskyFailedCertificateMatchesPinnedEpoch(t *testing.T) {
	lock, err := os.ReadFile(filepath.Join("..", "..", "providers", "rsky.lock"))
	if err != nil {
		t.Fatal(err)
	}
	var commit string
	for _, line := range strings.Split(string(lock), "\n") {
		if strings.HasPrefix(line, "commit=") {
			commit = strings.TrimPrefix(line, "commit=")
		}
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "providers", "rsky-certification.json"))
	if err != nil {
		t.Fatal(err)
	}
	var certificate struct {
		Epoch  string `json:"epoch"`
		Passed bool   `json:"passed"`
		Checks struct {
			Atomic string `json:"blobVerifiedBeforeRecordCommit"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(data, &certificate); err != nil {
		t.Fatal(err)
	}
	if commit == "" || certificate.Epoch != commit || certificate.Passed || certificate.Checks.Atomic != "fail" {
		t.Fatalf("rsky failed certificate does not bind the pinned unsafe epoch: %#v commit=%q", certificate, commit)
	}
}
