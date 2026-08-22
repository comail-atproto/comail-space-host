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
		"message.json":               "email.atmos.message",
		"messageState.json":          "email.atmos.messageState",
		"messageStateRevision.json":  "email.atmos.messageStateRevision",
		"messageStateOperation.json": "email.atmos.messageStateOperation",
		"folder.json":                "email.atmos.folder",
		"folderRevision.json":        "email.atmos.folderRevision",
		"folderOperation.json":       "email.atmos.folderOperation",
		"blobChunk.json":             "email.atmos.blobChunk",
		"blobManifest.json":          "email.atmos.blobManifest",
		"blobIndex.json":             "email.atmos.blobIndex",
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

func TestMailboxSpaceV3ContractIsExactAppendOnlyAuthority(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "contracts", "mailbox-space-v3.json"))
	if err != nil {
		t.Fatal(err)
	}
	var contract struct {
		SpaceType               string   `json:"spaceType"`
		Version                 int      `json:"version"`
		AuthorityModel          string   `json:"authorityModel"`
		RequiredWriteValidation bool     `json:"requiredWriteValidation"`
		WriterActions           []string `json:"writerActions"`
		Collections             []struct {
			NSID      string `json:"nsid"`
			Authority string `json:"authority"`
		} `json:"collections"`
		Recovery struct {
			SourceAuthentication []string `json:"sourceAuthentication"`
			BlobRead             string   `json:"blobRead"`
			RequiresStableState  bool     `json:"requiresStableState"`
			OfflineCARAuthority  bool     `json:"offlineCarIsAuthority"`
		} `json:"recovery"`
	}
	if err := json.Unmarshal(data, &contract); err != nil {
		t.Fatal(err)
	}
	wantCollections := []string{
		"email.atmos.message",
		"email.atmos.messageStateRevision",
		"email.atmos.messageStateOperation",
		"email.atmos.folderRevision",
		"email.atmos.folderOperation",
	}
	if contract.SpaceType != "email.atmos.mailbox" || contract.Version != 3 ||
		contract.AuthorityModel != "append-only" || !contract.RequiredWriteValidation ||
		len(contract.WriterActions) != 1 || contract.WriterActions[0] != "create" ||
		len(contract.Collections) != len(wantCollections) {
		t.Fatalf("mailbox v3 contract widened or drifted: %#v", contract)
	}
	for index, want := range wantCollections {
		if contract.Collections[index].NSID != want || contract.Collections[index].Authority != "immutable-create-only" {
			t.Fatalf("mailbox v3 collection %d = %#v, want %q create-only", index, contract.Collections[index], want)
		}
	}
	if strings.Join(contract.Recovery.SourceAuthentication, ",") != "getLatestCommit,getRepo,getLatestCommit" ||
		contract.Recovery.BlobRead != "getBlob" || !contract.Recovery.RequiresStableState || contract.Recovery.OfflineCARAuthority {
		t.Fatalf("mailbox v3 recovery boundary drifted: %#v", contract.Recovery)
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

func TestOfficialSpacesAlphaMailboxValidationPinsExactIsolatedBuild(t *testing.T) {
	root := filepath.Join("..", "..")
	lockData, err := os.ReadFile(filepath.Join(root, "providers", "official-spaces-alpha-mailbox-validation.lock"))
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(lockData), "\n") {
		key, value, found := strings.Cut(line, "=")
		if found {
			fields[key] = value
		}
	}
	if fields["base_commit"] != "89deb9faca20e56fa2a262fe9746ed52bc1095ba" ||
		fields["base_image"] != "ghcr.io/bluesky-social/atproto:pds-spaces-alpha" ||
		fields["base_digest"] != "sha256:9641f3d5c4ce2bffeee3cd740284c7fc445ef4b4e2ba73f01bf19a59923d0dd4" ||
		fields["platform"] != "linux/amd64" ||
		fields["base_prepare_sha256"] != "625c47436ba5b551e24538dbafc7e28a10597f1d0c7609d8d7b08124c72f4746" ||
		fields["patched_prepare_sha256"] != "3514e51518ff93e3f7d6e1d3533e064c77c79d4b0e82475ec5b1392eaa4cfa32" ||
		fields["installer"] != "scripts/testdata/install-official-spaces-alpha-schemas.mjs" ||
		fields["recipe"] != "scripts/testdata/official-spaces-alpha-schemas.Dockerfile" ||
		fields["wrapper"] != "scripts/test-official-spaces-alpha-mailbox.sh" ||
		fields["proof_source"] != "scripts/testdata/official-spaces-alpha-mailbox-proof/main.go" ||
		fields["container_runner"] != "scripts/testdata/official-spaces-alpha-run-with-plc.sh" ||
		fields["plc_mock"] != "scripts/testdata/official-spaces-alpha-plc-mock.mjs" ||
		fields["tls_proxy"] != "scripts/testdata/official-spaces-alpha-tls-proxy.mjs" {
		t.Fatalf("isolated mailbox-validation lock drifted: %#v", fields)
	}
	for _, key := range []string{"installer", "recipe", "wrapper", "proof_source", "container_runner", "plc_mock", "tls_proxy"} {
		assertPinnedFile(t, root, fields[key], fields[key+"_sha256"])
	}
	for _, key := range []string{"schema_message", "schema_message_state_revision", "schema_message_state_operation", "schema_folder_revision", "schema_folder_operation"} {
		assertPinnedFile(t, root, fields[key+"_path"], fields[key+"_sha256"])
	}

	assessmentData, err := os.ReadFile(filepath.Join(root, "providers", "official-spaces-alpha-mailbox-validation-assessment.json"))
	if err != nil {
		t.Fatal(err)
	}
	var assessment struct {
		Version int    `json:"version"`
		Passed  bool   `json:"passed"`
		Scope   string `json:"scope"`
		Pins    struct {
			BaseCommit      string `json:"baseCommit"`
			BaseImage       string `json:"baseImage"`
			Platform        string `json:"platform"`
			PatchedPrepare  string `json:"patchedPrepareSHA256"`
			InstallerSHA    string `json:"installerSHA256"`
			RecipeSHA       string `json:"recipeSHA256"`
			SchemaBundleSHA string `json:"schemaBundleSHA256"`
		} `json:"pins"`
		Checks struct {
			BaseRejectsStrict   string `json:"unmodifiedBaseRejectsStrictSchemas"`
			Validation          string `json:"mailboxLexiconValidation"`
			ValidationFailures  string `json:"failClosedValidation"`
			Atomic              string `json:"atomicApplyWrites"`
			Prepare             string `json:"syntheticPrepare"`
			Idempotency         string `json:"idempotencyRerun"`
			Recovery            string `json:"sourceAuthenticatedRecovery"`
			Projection          string `json:"freshProjectionRebuild"`
			DPoP                string `json:"delegationAndDpop"`
			HostedAcceptance    bool   `json:"hostedBlueskyAcceptance"`
			AuthorityCertified  bool   `json:"authorityCertified"`
			ActivationAttempted bool   `json:"activationAttempted"`
		} `json:"checks"`
		Limitations struct {
			Schemas string `json:"schemas"`
			OAuth   string `json:"oauth"`
			Mail    string `json:"mail"`
		} `json:"limitations"`
	}
	if err := json.Unmarshal(assessmentData, &assessment); err != nil {
		t.Fatal(err)
	}
	if assessment.Version != 1 || !assessment.Passed ||
		assessment.Pins.BaseCommit != fields["base_commit"] ||
		assessment.Pins.BaseImage != fields["base_image"]+"@"+fields["base_digest"] ||
		assessment.Pins.Platform != fields["platform"] ||
		assessment.Pins.PatchedPrepare != fields["patched_prepare_sha256"] ||
		assessment.Pins.InstallerSHA != fields["installer_sha256"] ||
		assessment.Pins.RecipeSHA != fields["recipe_sha256"] ||
		assessment.Pins.SchemaBundleSHA != fields["schema_bundle_sha256"] ||
		!strings.HasPrefix(assessment.Checks.BaseRejectsStrict, "pass:") ||
		assessment.Checks.Validation != "pass: all 311 create receipts returned validationStatus=valid across the exact five schemas" ||
		!strings.Contains(assessment.Checks.ValidationFailures, "invalid known-schema") ||
		!strings.Contains(assessment.Checks.ValidationFailures, "unknown-schema") ||
		!strings.HasPrefix(assessment.Checks.Atomic, "pass:") ||
		assessment.Checks.Prepare != "pass: captured=99 skipped=0 verified=99" ||
		assessment.Checks.Idempotency != "pass: captured=0 skipped=99 verified=99" ||
		!strings.Contains(assessment.Checks.Recovery, "signed stable CAR") ||
		!strings.Contains(assessment.Checks.Projection, "fresh SQLite projections committed with mode 0600") ||
		assessment.Checks.DPoP != "pass" || assessment.Checks.HostedAcceptance ||
		assessment.Checks.AuthorityCertified || assessment.Checks.ActivationAttempted ||
		!strings.Contains(assessment.Scope, "synthetic") ||
		!strings.Contains(assessment.Limitations.Schemas, "not published") ||
		!strings.Contains(assessment.Limitations.OAuth, "legacy access JWT") ||
		!strings.Contains(assessment.Limitations.Mail, "no real mail") {
		t.Fatalf("isolated mailbox-validation assessment overclaims or drifted: %#v", assessment)
	}

	wrapper, err := os.ReadFile(filepath.Join(root, "scripts", "test-official-spaces-alpha-mailbox.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"unmodifiedBaseRejectsStrictSchemas",
		"schemaValidationAttempted == true",
		"sourceAuthenticatedRecovery",
		"freshProjectionRebuild",
		"committed assessment does not match this exact proof run",
		"comail.proof.run",
	} {
		if !strings.Contains(string(wrapper), required) {
			t.Fatalf("isolated mailbox-validation wrapper is incomplete: missing %q", required)
		}
	}
}

func assertPinnedFile(t *testing.T, root, path, want string) {
	t.Helper()
	if path == "" || want == "" {
		t.Fatalf("pinned path or digest is empty: path=%q digest=%q", path, want)
	}
	data, err := os.ReadFile(filepath.Join(root, path))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("%s SHA-256 = %s, want %s", path, got, want)
	}
}
