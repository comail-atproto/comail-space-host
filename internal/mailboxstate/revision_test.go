package mailboxstate

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	testRepoDID   = "did:plc:rfwhywgeym2ek7ioeyxkvsn6"
	testLogicalID = "sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testVersion   = "sha256-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testFolder    = "folder-cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	testFolderB   = "folder-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
)

func TestReduceRevisionsIsPermutationInvariantAndComposesConcurrentFields(t *testing.T) {
	root := testRevision(t, "initial", nil, 1)
	root.Record.Version = testVersion
	root.Record.MailboxIDs = []string{testFolder}
	root = sealRevision(t, root)
	seen := testRevision(t, "seen", []string{root.RKey}, 2)
	seen.Record.Keywords = []KeywordAssignment{{Name: "$seen", Present: true}}
	seen = sealRevision(t, seen)
	flagged := testRevision(t, "flagged", []string{root.RKey}, 2)
	flagged.Record.Keywords = []KeywordAssignment{{Name: "$flagged", Present: true}}
	flagged = sealRevision(t, flagged)
	inventory := testInventory(root, seen, flagged)

	want, err := Reduce(testRepoDID, testLogicalID, []StateRevision{root, seen, flagged}, inventory)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(want.Keywords, []string{"$flagged", "$seen"}) {
		t.Fatalf("keywords = %#v", want.Keywords)
	}
	if len(want.Heads) != 2 || want.HeadsDigest == "" || want.StateDigest == "" {
		t.Fatalf("reduced heads/digests = %#v", want)
	}

	permutations := [][]StateRevision{
		{root, flagged, seen},
		{seen, root, flagged},
		{seen, flagged, root},
		{flagged, root, seen},
		{flagged, seen, root},
	}
	for _, input := range permutations {
		got, err := Reduce(testRepoDID, testLogicalID, input, inventory)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("input order changed reduction:\n got %#v\nwant %#v", got, want)
		}
	}
}

func TestReduceRevisionsUsesCausalityThenOperationKeyForConflicts(t *testing.T) {
	root := testRevision(t, "initial", nil, 1)
	root.Record.Version = testVersion
	root.Record.MailboxIDs = []string{testFolder}
	root = sealRevision(t, root)
	a := testRevision(t, "concurrent-a", []string{root.RKey}, 2)
	a.Record.Keywords = []KeywordAssignment{{Name: "$seen", Present: true}}
	a = sealRevision(t, a)
	b := testRevision(t, "concurrent-b", []string{root.RKey}, 2)
	b.Record.Keywords = []KeywordAssignment{{Name: "$seen", Present: false}}
	b = sealRevision(t, b)

	winner := b
	state, err := Reduce(testRepoDID, testLogicalID, []StateRevision{root, a, b}, testInventory(root, a, b))
	if err != nil {
		t.Fatal(err)
	}
	if got := slices.Contains(state.Keywords, "$seen"); got != winner.Record.Keywords[0].Present {
		t.Fatalf("concurrent winner = %t, want %t from %s", got, winner.Record.Keywords[0].Present, winner.RKey)
	}

	descendant := testRevision(t, "descendant", []string{a.RKey, b.RKey}, 3)
	descendant.Record.Keywords = []KeywordAssignment{{Name: "$seen", Present: true}}
	descendant = sealRevision(t, descendant)
	state, err = Reduce(testRepoDID, testLogicalID, []StateRevision{root, a, b, descendant}, testInventory(root, a, b, descendant))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(state.Keywords, "$seen") {
		t.Fatal("causally newer assignment did not beat concurrent ancestors")
	}
}

func TestReduceRevisionsRejectsInvalidCausalHistory(t *testing.T) {
	root := testRevision(t, "initial", nil, 1)
	root.Record.Version = testVersion
	root.Record.MailboxIDs = []string{testFolder}
	root = sealRevision(t, root)
	missing := testRevision(t, "missing", []string{"state-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, 2)
	missing.Record.Keywords = []KeywordAssignment{{Name: "$seen", Present: true}}
	missing = sealRevision(t, missing)
	gap := testRevision(t, "gap", []string{root.RKey}, 3)
	gap.Record.Keywords = []KeywordAssignment{{Name: "$seen", Present: true}}
	gap = sealRevision(t, gap)
	cross := testRevision(t, "cross", []string{root.RKey}, 2)
	cross.Record.LogicalMessageID = "sha256-dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	cross.Record.Keywords = []KeywordAssignment{{Name: "$seen", Present: true}}
	cross = sealRevisionFor(t, testRepoDID, cross)

	for name, input := range map[string][]StateRevision{
		"missing parent": {root, missing},
		"revision gap":   {root, gap},
		"cross message":  {root, cross},
		"duplicate":      {root, root},
	} {
		if _, err := Reduce(testRepoDID, testLogicalID, input, testInventory(input...)); err == nil {
			t.Errorf("%s history was accepted", name)
		}
	}
}

func TestReduceRevisionsMakesTombstoneIrreversible(t *testing.T) {
	root := testRevision(t, "initial", nil, 1)
	root.Record.Version = testVersion
	root.Record.MailboxIDs = []string{testFolder}
	root = sealRevision(t, root)
	tombstone := testRevision(t, "tombstone", []string{root.RKey}, 2)
	tombstone.Record.Tombstone = true
	tombstone = sealRevision(t, tombstone)
	staleLive := testRevision(t, "stale-live", []string{root.RKey}, 2)
	staleLive.Record.Keywords = []KeywordAssignment{{Name: "$seen", Present: true}}
	staleLive = sealRevision(t, staleLive)
	laterLive := testRevision(t, "later-live", []string{staleLive.RKey, tombstone.RKey}, 3)
	laterLive.Record.Keywords = []KeywordAssignment{{Name: "$flagged", Present: true}}
	laterLive = sealRevision(t, laterLive)

	if _, err := Reduce(testRepoDID, testLogicalID, []StateRevision{root, laterLive, staleLive, tombstone}, testInventory(root, laterLive, staleLive, tombstone)); err == nil {
		t.Fatal("mutation causally after a tombstone was accepted")
	}

	deletePending := true
	concurrentDelete := testRevision(t, "delete-pending", []string{root.RKey}, 2)
	concurrentDelete.Record.DeletePending = &deletePending
	concurrentDelete = sealRevision(t, concurrentDelete)
	state, err := Reduce(testRepoDID, testLogicalID, []StateRevision{root, tombstone, concurrentDelete}, testInventory(root, tombstone, concurrentDelete))
	if err != nil {
		t.Fatal(err)
	}
	if !state.Tombstone || state.DeletePending {
		t.Fatalf("tombstoned state retained live delete-pending assignment: %#v", state)
	}
}

func TestVerifyRevisionRetryDistinguishesExactReplayFromCollision(t *testing.T) {
	revision := testRevision(t, "retry", nil, 1)
	revision.Record.Version = testVersion
	revision.Record.MailboxIDs = []string{testFolder}
	revision = sealRevision(t, revision)
	if err := VerifyRevisionRetry(testRepoDID, revision, revision); err != nil {
		t.Fatalf("exact retry: %v", err)
	}
	collision := revision
	collision.Record.CreatedAt = time.Date(2026, 8, 20, 1, 2, 4, 0, time.UTC).Format(time.RFC3339Nano)
	collision = sealRevision(t, collision)
	if err := VerifyRevisionRetry(testRepoDID, revision, collision); err != nil {
		t.Fatalf("semantic retry with new server time: %v", err)
	}
	expectedClaim := testOperationClaim(t, revision)
	collisionClaim := testOperationClaim(t, collision)
	if expectedClaim.RKey != collisionClaim.RKey {
		t.Fatal("same operation did not collide at the deterministic claim key")
	}
	if err := VerifyOperationClaimRetry(expectedClaim, collisionClaim); !errors.Is(err, ErrOperationCollision) {
		t.Fatalf("operation claim collision error = %v", err)
	}
	collision.Record.Keywords = []KeywordAssignment{{Name: "$seen", Present: true}}
	collision = sealRevision(t, collision)
	if err := VerifyRevisionRetry(testRepoDID, revision, collision); !errors.Is(err, ErrOperationCollision) {
		t.Fatalf("changed semantic payload error = %v", err)
	}
	if _, err := Reduce(testRepoDID, testLogicalID, []StateRevision{revision, collision}, testInventory(revision, collision)); !errors.Is(err, ErrIncompleteSnapshot) {
		t.Fatalf("poisoned duplicate operation error = %v", err)
	}
}

func TestReduceRevisionsRejectsTamperingAndIncompleteSnapshot(t *testing.T) {
	root := testRevision(t, "initial", nil, 1)
	root.Record.Version = testVersion
	root.Record.MailboxIDs = []string{testFolder}
	root = sealRevision(t, root)
	tombstone := testRevision(t, "tombstone", []string{root.RKey}, 2)
	tombstone.Record.Tombstone = true
	tombstone = sealRevision(t, tombstone)

	tampered := tombstone
	tampered.Record.Tombstone = false
	tampered.Record.Keywords = []KeywordAssignment{{Name: "$seen", Present: true}}
	if _, err := Reduce(testRepoDID, testLogicalID, []StateRevision{root, tampered}, testInventory(root, tampered)); err == nil {
		t.Fatal("payload rewritten under an existing revision rkey was accepted")
	}
	omittedHead := testInventory(root, tombstone)
	if _, err := Reduce(testRepoDID, testLogicalID, []StateRevision{root}, omittedHead); !errors.Is(err, ErrIncompleteSnapshot) {
		t.Fatalf("omitted current head error = %v", err)
	}
	if _, err := Reduce(testRepoDID, testLogicalID, []StateRevision{root}, VerifiedSnapshot{}); !errors.Is(err, ErrIncompleteSnapshot) {
		t.Fatalf("unverified snapshot error = %v", err)
	}
}

func TestReduceRevisionsBindsVersionsAndLiveFoldersToResource(t *testing.T) {
	root := testRevision(t, "initial", nil, 1)
	root.Record.Version = testVersion
	root.Record.MailboxIDs = []string{testFolder}
	root = sealRevision(t, root)

	foreignVersion := testInventory(root)
	foreignVersion.versions[testVersion] = "sha256-ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	foreignVersion.seal = foreignVersion.snapshotSeal()
	if _, err := Reduce(testRepoDID, testLogicalID, []StateRevision{root}, foreignVersion); !errors.Is(err, ErrInvalidReference) {
		t.Fatalf("cross-message version error = %v", err)
	}

	deletedFolder := testInventory(root)
	reference := deletedFolder.folders[testFolder]
	reference.tombstone = true
	deletedFolder.folders[testFolder] = reference
	deletedFolder.seal = deletedFolder.snapshotSeal()
	if _, err := Reduce(testRepoDID, testLogicalID, []StateRevision{root}, deletedFolder); !errors.Is(err, ErrInvalidReference) {
		t.Fatalf("deleted-folder reference error = %v", err)
	}

	malformedFolderDigest := testInventory(root)
	reference = malformedFolderDigest.folders[testFolder]
	reference.stateDigest = "not-a-digest"
	malformedFolderDigest.folders[testFolder] = reference
	malformedFolderDigest.seal = malformedFolderDigest.snapshotSeal()
	if _, err := Reduce(testRepoDID, testLogicalID, []StateRevision{root}, malformedFolderDigest); !errors.Is(err, ErrInvalidReference) {
		t.Fatalf("malformed folder-state digest error = %v", err)
	}
}

func TestMessageStateIdentifiersRequireCanonicalSHA256AndRepositoryDID(t *testing.T) {
	revision := testRevision(t, "initial", nil, 1)
	revision.Record.Version = testVersion
	revision.Record.MailboxIDs = []string{testFolder}

	for _, logicalID := range []string{
		"sha256-short",
		"sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"blake3-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	} {
		revision.Record.LogicalMessageID = logicalID
		if _, err := StateRevisionRKey(testRepoDID, revision.Record); !errors.Is(err, ErrInvalidRevision) {
			t.Errorf("StateRevisionRKey logical ID %q error = %v", logicalID, err)
		}
		if _, err := OperationClaimRKey(testRepoDID, logicalID, "initial"); !errors.Is(err, ErrInvalidRevision) {
			t.Errorf("OperationClaimRKey logical ID %q error = %v", logicalID, err)
		}
	}

	revision.Record.LogicalMessageID = testLogicalID
	for _, repoDID := range []string{"did:", "did:PLC:rfwhywgeym2ek7ioeyxkvsn6", "not-a-did"} {
		if _, err := StateRevisionRKey(repoDID, revision.Record); !errors.Is(err, ErrInvalidRevision) {
			t.Errorf("StateRevisionRKey(%q) error = %v", repoDID, err)
		}
	}

	invalidVersion := revision
	invalidVersion.Record.Version = "sha256-" + strings.Repeat("A", 64)
	invalidVersion = sealRevision(t, invalidVersion)
	versionInventory := testInventory(invalidVersion)
	versionInventory.versions[invalidVersion.Record.Version] = testLogicalID
	versionInventory.seal = versionInventory.snapshotSeal()
	if _, err := Reduce(testRepoDID, testLogicalID, []StateRevision{invalidVersion}, versionInventory); !errors.Is(err, ErrInvalidRevision) {
		t.Errorf("noncanonical version error = %v", err)
	}

	invalidFolder := revision
	invalidFolder.Record.MailboxIDs = []string{"folder-short"}
	invalidFolder = sealRevision(t, invalidFolder)
	folderInventory := testInventory(invalidFolder)
	folderInventory.folders[invalidFolder.Record.MailboxIDs[0]] = verifiedFolderReference{stateDigest: digestBytes([]byte("invalid-folder"))}
	folderInventory.seal = folderInventory.snapshotSeal()
	if _, err := Reduce(testRepoDID, testLogicalID, []StateRevision{invalidFolder}, folderInventory); !errors.Is(err, ErrInvalidRevision) {
		t.Errorf("noncanonical folder ID error = %v", err)
	}
}

func TestReduceRevisionsAllowsHistoricalReferenceToDeletedFolderAfterMove(t *testing.T) {
	root := testRevision(t, "initial", nil, 1)
	root.Record.Version = testVersion
	root.Record.MailboxIDs = []string{testFolder}
	root = sealRevision(t, root)
	move := testRevision(t, "move", []string{root.RKey}, 2)
	move.Record.MailboxIDs = []string{testFolderB}
	move = sealRevision(t, move)

	inventory := testInventory(root, move)
	inventory.folders[testFolder] = verifiedFolderReference{
		stateDigest: "sha256-" + strings.Repeat("e", 64),
		tombstone:   true,
	}
	inventory.folders[testFolderB] = verifiedFolderReference{
		stateDigest: "sha256-" + strings.Repeat("f", 64),
	}
	inventory.seal = inventory.snapshotSeal()

	state, err := Reduce(testRepoDID, testLogicalID, []StateRevision{root, move}, inventory)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(state.MailboxIDs, []string{testFolderB}) {
		t.Fatalf("mailboxes = %#v", state.MailboxIDs)
	}
}

func TestReduceRevisionsRequiresWireSafeEmptyParentsAndBoundsHistory(t *testing.T) {
	root := testRevision(t, "initial", nil, 1)
	root.Record.Version = testVersion
	root.Record.MailboxIDs = []string{testFolder}
	root.Record.Parents = nil
	root = sealRevision(t, root)
	if _, err := Reduce(testRepoDID, testLogicalID, []StateRevision{root}, testInventory(root)); err == nil {
		t.Fatal("null root parents were accepted")
	}

	overflow := make([]StateRevision, maxRevisionCount+1)
	if _, err := Reduce(testRepoDID, testLogicalID, overflow, VerifiedSnapshot{}); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("revision-count limit error = %v", err)
	}
	tooHigh := testRevision(t, "too-high", nil, maxPortableRevision+1)
	tooHigh.Record.Version = testVersion
	tooHigh.Record.MailboxIDs = []string{testFolder}
	tooHigh = sealRevision(t, tooHigh)
	if _, err := Reduce(testRepoDID, testLogicalID, []StateRevision{tooHigh}, testInventory(tooHigh)); !errors.Is(err, ErrInvalidRevision) {
		t.Fatalf("non-portable revision error = %v", err)
	}
}

func TestRevisionCommitmentHasCrossImplementationGoldenVector(t *testing.T) {
	deletePending := true
	longKeyword := strings.Repeat("x", 130) + "<&雪"
	record := RevisionRecord{
		Type: MessageStateRevisionCollection, LogicalMessageID: testLogicalID,
		OperationID: "interop-<>&-雪", Parents: []string{
			"state-1111111111111111111111111111111111111111111111111111111111111111",
			"state-2222222222222222222222222222222222222222222222222222222222222222",
		},
		Revision: 3, Version: testVersion, MailboxIDs: []string{"Custom <雪>", testFolder},
		Keywords:      []KeywordAssignment{{Name: "$seen", Present: true}, {Name: longKeyword, Present: false}},
		DeletePending: &deletePending, Merge: false, CreatedAt: "2026-08-20T01:02:03.456Z",
	}
	encoded, err := CanonicalRevisionBytes(record)
	if err != nil {
		t.Fatal(err)
	}
	const wantHex = "636f6d61696c2d6d6573736167652d73746174652d7265766973696f6e2d63616e6f6e6963616c2d76310020656d61696c2e61746d6f732e6d65737361676553746174655265766973696f6e477368613235362d616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161610f696e7465726f702d3c3e262de99baa024673746174652d313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131314673746174652d3232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323203477368613235362d6262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626201020c437573746f6d203ce99baa3e47666f6c6465722d636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363630205247365656e018701787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878783c26e99baa0002000018323032362d30382d32305430313a30323a30332e3435365a"
	if got := hex.EncodeToString(encoded); got != wantHex {
		t.Fatalf("canonical revision bytes = %s", got)
	}
	const wantRKey = "state-a8a3aa84c8de120991dedc8ed7289191f44680894cadb8cc6bbcd7b82d0d1e0c"
	if got, err := StateRevisionRKey(testRepoDID, record); err != nil || got != wantRKey {
		t.Fatalf("revision rkey = %q, err=%v", got, err)
	}
}

func TestRevisionCanonicalizationUsesUnsignedUTF8ByteOrder(t *testing.T) {
	root := testRevision(t, "utf8-order", nil, 1)
	root.Record.Version = testVersion
	root.Record.MailboxIDs = []string{testFolder}
	// U+E000 sorts before U+10000 by unsigned UTF-8 bytes. JavaScript's
	// default UTF-16 code-unit order is the reverse, so this is an interop
	// sentinel rather than an incidental Go string-order test.
	root.Record.Keywords = []KeywordAssignment{
		{Name: "\uE000", Present: true},
		{Name: "\U00010000", Present: true},
	}
	root = sealRevision(t, root)
	if _, err := Reduce(testRepoDID, testLogicalID, []StateRevision{root}, testInventory(root)); err != nil {
		t.Fatalf("UTF-8 byte order rejected: %v", err)
	}

	reversed := root
	reversed.Record.Keywords[0], reversed.Record.Keywords[1] = reversed.Record.Keywords[1], reversed.Record.Keywords[0]
	reversed = sealRevision(t, reversed)
	if _, err := Reduce(testRepoDID, testLogicalID, []StateRevision{reversed}, testInventory(reversed)); err == nil {
		t.Fatal("UTF-16-style keyword order was accepted")
	}

	invalid := root.Record
	invalid.OperationID = string([]byte{0xff})
	if _, err := CanonicalRevisionBytes(invalid); err == nil {
		t.Fatal("ill-formed UTF-8 was accepted by canonical encoder")
	}
}

func TestDecodeRevisionRecordRejectsUnknownAndTrailingWireData(t *testing.T) {
	revision := testRevision(t, "strict-decode", nil, 1)
	revision.Record.Version = testVersion
	revision.Record.MailboxIDs = []string{testFolder}
	encoded, err := json.Marshal(revision.Record)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeRevisionRecord(encoded); err != nil {
		t.Fatalf("strict valid decode: %v", err)
	}
	unknown := append(append([]byte(nil), encoded[:len(encoded)-1]...), []byte(`,"unexpected":true}`)...)
	if _, err := DecodeRevisionRecord(unknown); err == nil {
		t.Fatal("unknown wire field was accepted")
	}
	if _, err := DecodeRevisionRecord(append(encoded, []byte(" {}")...)); err == nil {
		t.Fatal("trailing wire value was accepted")
	}
}

func TestConcurrentWinnerDoesNotDependOnCreatedAt(t *testing.T) {
	root := testRevision(t, "initial", nil, 1)
	root.Record.Version = testVersion
	root.Record.MailboxIDs = []string{testFolder}
	root = sealRevision(t, root)
	a := testRevision(t, "concurrent-a", []string{root.RKey}, 2)
	a.Record.CreatedAt = "2099-01-01T00:00:00Z"
	a.Record.Keywords = []KeywordAssignment{{Name: "$seen", Present: true}}
	a = sealRevision(t, a)
	b := testRevision(t, "concurrent-b", []string{root.RKey}, 2)
	b.Record.CreatedAt = "2000-01-01T00:00:00Z"
	b.Record.Keywords = []KeywordAssignment{{Name: "$seen", Present: false}}
	b = sealRevision(t, b)
	first, err := Reduce(testRepoDID, testLogicalID, []StateRevision{root, a, b}, testInventory(root, a, b))
	if err != nil {
		t.Fatal(err)
	}

	a.Record.CreatedAt, b.Record.CreatedAt = b.Record.CreatedAt, a.Record.CreatedAt
	a, b = sealRevision(t, a), sealRevision(t, b)
	second, err := Reduce(testRepoDID, testLogicalID, []StateRevision{root, a, b}, testInventory(root, a, b))
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(first.Keywords, "$seen") != slices.Contains(second.Keywords, "$seen") {
		t.Fatal("client time changed the concurrent field winner")
	}
}

func testRevision(t *testing.T, operationID string, parents []string, revision uint64) StateRevision {
	t.Helper()
	record := RevisionRecord{
		Type:             MessageStateRevisionCollection,
		LogicalMessageID: testLogicalID,
		OperationID:      operationID,
		Parents:          append([]string{}, parents...),
		Revision:         revision,
		CreatedAt:        time.Date(2026, 8, 20, 1, 2, 3, 0, time.UTC).Format(time.RFC3339Nano),
	}
	slices.Sort(record.Parents)
	return StateRevision{Record: record}
}

func sealRevision(t *testing.T, revision StateRevision) StateRevision {
	t.Helper()
	return sealRevisionFor(t, testRepoDID, revision)
}

func sealRevisionFor(t *testing.T, repoDID string, revision StateRevision) StateRevision {
	t.Helper()
	rkey, err := StateRevisionRKey(repoDID, revision.Record)
	if err != nil {
		t.Fatal(err)
	}
	revision.RKey = rkey
	return revision
}

func testOperationClaim(t *testing.T, revision StateRevision) OperationClaim {
	t.Helper()
	claim, err := NewOperationClaim(testRepoDID, revision)
	if err != nil {
		t.Fatal(err)
	}
	return claim
}

func testInventory(revisions ...StateRevision) VerifiedSnapshot {
	claims := make(map[string]string, len(revisions))
	for _, revision := range revisions {
		claim, err := NewOperationClaim(testRepoDID, revision)
		if err != nil {
			continue
		}
		claims[claim.RKey] = claim.Record.RevisionRKey
	}
	inventory := VerifiedSnapshot{
		snapshotID: "bafy-synthetic-verified-commit", logicalMessageID: testLogicalID,
		revisionCount: len(revisions), operationClaims: claims,
		versions: map[string]string{testVersion: testLogicalID},
		folders: map[string]verifiedFolderReference{
			testFolder: {stateDigest: "sha256-" + strings.Repeat("d", 64)},
		},
	}
	inventory.seal = inventory.snapshotSeal()
	return inventory
}
