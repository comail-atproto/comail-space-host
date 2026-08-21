package contracts

import (
	"crypto/sha256"
	"encoding/hex"
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
		"blobChunk.json":    "email.atmos.blobChunk",
		"blobManifest.json": "email.atmos.blobManifest",
		"blobIndex.json":    "email.atmos.blobIndex",
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

func TestRskyLabPatchCertificateMatchesPinnedEpoch(t *testing.T) {
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
		Epoch       string `json:"epoch"`
		Passed      bool   `json:"passed"`
		Patch       string `json:"patch"`
		PatchSHA256 string `json:"patchSHA256"`
		Scope       string `json:"scope"`
		Checks      struct {
			Atomic string `json:"blobVerifiedBeforeRecordCommit"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(data, &certificate); err != nil {
		t.Fatal(err)
	}
	if commit == "" || certificate.Epoch != commit || !certificate.Passed || certificate.Checks.Atomic != "pass with lab patch" || !strings.Contains(certificate.Scope, "isolated lab") {
		t.Fatalf("rsky lab certificate does not bind the patched pinned epoch: %#v commit=%q", certificate, commit)
	}
	patchPath := filepath.Join("..", "..", certificate.Patch)
	patchBytes, err := os.ReadFile(patchPath)
	if err != nil {
		t.Fatalf("certified patch is missing: %v", err)
	}
	hash := sha256.Sum256(patchBytes)
	if hex.EncodeToString(hash[:]) != certificate.PatchSHA256 {
		t.Fatal("certified patch hash does not match")
	}
}

func TestHappyViewCertificateMatchesPinnedEpoch(t *testing.T) {
	lock, err := os.ReadFile(filepath.Join("..", "..", "providers", "happyview.lock"))
	if err != nil {
		t.Fatal(err)
	}
	var commit string
	for _, line := range strings.Split(string(lock), "\n") {
		if strings.HasPrefix(line, "commit=") {
			commit = strings.TrimPrefix(line, "commit=")
		}
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "providers", "happyview-certification.json"))
	if err != nil {
		t.Fatal(err)
	}
	var certificate struct {
		Epoch  string `json:"epoch"`
		Passed bool   `json:"passed"`
		Scope  string `json:"scope"`
		Checks struct {
			Upstream      string `json:"upstreamSpaceAuthAndRecordTests"`
			Private       string `json:"privateNonMemberRead"`
			Chunks        string `json:"comailPrivateChunkRoundTrip"`
			Live          string `json:"liveSyntheticMigrationAndRebuild"`
			LiveDeny      string `json:"liveSyntheticNonMemberRead"`
			SourceVersion string `json:"liveSourceVersionReplacement"`
		} `json:"checks"`
		Limitations struct {
			NativeBlob string `json:"nativeBlobAuthority"`
		} `json:"limitations"`
	}
	if err := json.Unmarshal(data, &certificate); err != nil {
		t.Fatal(err)
	}
	if commit == "" || certificate.Epoch != commit || !certificate.Passed ||
		certificate.Checks.Upstream != "31/31 pass" || certificate.Checks.Private != "pass" ||
		certificate.Checks.Chunks != "pass" || certificate.Checks.Live != "pass" || certificate.Checks.LiveDeny != "pass" || certificate.Checks.SourceVersion != "pass" ||
		!strings.Contains(certificate.Scope, "isolated") ||
		!strings.Contains(certificate.Limitations.NativeBlob, "not certified") {
		t.Fatalf("HappyView certificate does not bind the isolated pinned epoch: %#v commit=%q", certificate, commit)
	}
}

func TestOfficialSpacesAlphaAssessmentPinsExactFailClosedBuild(t *testing.T) {
	lock, err := os.ReadFile(filepath.Join("..", "..", "providers", "official-spaces-alpha.lock"))
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(lock), "\n") {
		key, value, found := strings.Cut(line, "=")
		if found {
			fields[key] = value
		}
	}
	if fields["repository"] != "https://github.com/bluesky-social/atproto.git" ||
		fields["proposal"] != "https://github.com/bluesky-social/proposals/tree/main/0016-permissioned-data" ||
		fields["proposal_commit"] != "54c9cf5153d668c4f4fb4438529967412e861775" ||
		fields["pull_request"] != "https://github.com/bluesky-social/atproto/pull/5187" ||
		fields["commit"] != "89deb9faca20e56fa2a262fe9746ed52bc1095ba" ||
		fields["reference_app"] != "https://github.com/bluesky-social/bulletin.git" ||
		fields["reference_app_commit"] != "ccca73d212167e20da56db4691ba7c94e9ad5ccc" ||
		fields["docker_image"] != "ghcr.io/bluesky-social/atproto:pds-spaces-alpha" ||
		fields["docker_digest"] != "sha256:9641f3d5c4ce2bffeee3cd740284c7fc445ef4b4e2ba73f01bf19a59923d0dd4" ||
		fields["sdk_snapshot"] != "0.0.0-spaces-alpha-20260818163953" ||
		fields["oauth_scopes_snapshot"] != "0.0.0-spaces-alpha-20260818163953" {
		t.Fatalf("official alpha lock is incomplete or drifted: %#v", fields)
	}

	data, err := os.ReadFile(filepath.Join("..", "..", "providers", "official-spaces-alpha-assessment.json"))
	if err != nil {
		t.Fatal(err)
	}
	var assessment struct {
		Epoch         string `json:"epoch"`
		Image         string `json:"image"`
		ImageConfig   string `json:"imageConfig"`
		Platform      string `json:"platform"`
		Passed        bool   `json:"passed"`
		Scope         string `json:"scope"`
		ReferencePins struct {
			ProposalCommit     string `json:"proposalCommit"`
			ReferenceAppCommit string `json:"referenceAppCommit"`
			SDKSnapshot        string `json:"sdkSnapshot"`
			ExecutedByProof    bool   `json:"executedByProof"`
		} `json:"referencePins"`
		Checks struct {
			Addressing         string `json:"officialAddressingAndMethods"`
			AtomicWrites       string `json:"atomicApplyWrites"`
			Prepare            string `json:"syntheticPrepare"`
			Idempotency        string `json:"idempotencyRerun"`
			ByteReadback       string `json:"canonicalByteReadback"`
			DPoP               string `json:"delegationAndDpop"`
			Replay             string `json:"delegationReplay"`
			WrongBinding       string `json:"wrongKeyAndSpace"`
			SchemaValidation   string `json:"mailboxLexiconValidation"`
			OAuthGrant         string `json:"narrowOAuthGrant"`
			StaleSwap          string `json:"staleCompareAndSwap"`
			AuthorityAdmission string `json:"authorityAdmission"`
			Activation         string `json:"activation"`
		} `json:"checks"`
		Limitations struct {
			Production string `json:"production"`
			Mutable    string `json:"mutableState"`
			OAuth      string `json:"oauth"`
			Schema     string `json:"schema"`
		} `json:"limitations"`
	}
	if err := json.Unmarshal(data, &assessment); err != nil {
		t.Fatal(err)
	}
	if assessment.Epoch != fields["commit"] ||
		assessment.Image != fields["docker_image"]+"@"+fields["docker_digest"] ||
		assessment.ImageConfig != fields["docker_config"] || assessment.Platform != fields["docker_platform"] ||
		assessment.ReferencePins.ProposalCommit != fields["proposal_commit"] ||
		assessment.ReferencePins.ReferenceAppCommit != fields["reference_app_commit"] ||
		assessment.ReferencePins.SDKSnapshot != fields["sdk_snapshot"] || assessment.ReferencePins.ExecutedByProof ||
		assessment.Passed || assessment.Checks.Addressing != "pass" ||
		assessment.Checks.AtomicWrites != "pass: failing two-write batch rolled back its valid create" ||
		assessment.Checks.Prepare != "pass: captured=99 skipped=0 verified=99" ||
		assessment.Checks.Idempotency != "pass: captured=0 skipped=99 verified=99" ||
		assessment.Checks.ByteReadback != "pass: 99/99 exact RFC 5322 blobs" ||
		assessment.Checks.DPoP != "pass" || !strings.Contains(assessment.Checks.Replay, "JwtReplayed") ||
		!strings.Contains(assessment.Checks.WrongBinding, "DpopKeyMismatch") ||
		!strings.Contains(assessment.Checks.WrongBinding, "InvalidCredential") ||
		!strings.Contains(assessment.Checks.WrongBinding, "InvalidDelegationToken") ||
		!strings.HasPrefix(assessment.Checks.SchemaValidation, "not attempted:") ||
		!strings.HasPrefix(assessment.Checks.OAuthGrant, "not attempted:") ||
		!strings.HasPrefix(assessment.Checks.StaleSwap, "fail:") ||
		assessment.Checks.AuthorityAdmission != "fail-closed" || assessment.Checks.Activation != "not attempted" ||
		!strings.Contains(assessment.Scope, "synthetic") || !strings.Contains(assessment.Limitations.Production, "Stalwart") ||
		!strings.Contains(assessment.Limitations.Mutable, "compare-and-swap") ||
		!strings.Contains(assessment.Limitations.OAuth, "legacy access JWT") ||
		!strings.Contains(assessment.Limitations.Schema, "validate=false") {
		t.Fatalf("official alpha assessment does not preserve the fail-closed boundary: %#v", assessment)
	}

	wrapper, err := os.ReadFile(filepath.Join("..", "..", "scripts", "test-official-spaces-alpha.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"lock_value docker_digest",
		"lock_value docker_platform",
		"docker image inspect --format '{{.Descriptor.digest}}' \"${image}\"",
		"pulled image manifest does not match lock",
		"pulled image platform does not match lock",
		"pulled image source revision does not match lock",
		"committed assessment does not match this exact proof run",
		"comail.proof.run",
	} {
		if !strings.Contains(string(wrapper), required) {
			t.Fatalf("official alpha wrapper is not bound to its lock/assessment: missing %q", required)
		}
	}
}
