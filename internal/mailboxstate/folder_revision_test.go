package mailboxstate

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

const testFolderID = "folder-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestReduceFolderRevisionsIsPermutationInvariant(t *testing.T) {
	root := testFolderRevision(t, testFolderID, "initial", nil, 1)
	root.Record.Name = "Projects"
	root = sealFolderRevision(t, root)
	a := testFolderRevision(t, testFolderID, "rename-a", []string{root.RKey}, 2)
	a.Record.Name = "Alpha"
	a = sealFolderRevision(t, a)
	b := testFolderRevision(t, testFolderID, "rename-b", []string{root.RKey}, 2)
	b.Record.Name = "Beta"
	b = sealFolderRevision(t, b)
	snapshot := testFolderInventory(root, a, b)

	want, err := ReduceFolder(testRepoDID, testFolderID, []FolderStateRevision{root, a, b}, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if want.Name != "Beta" || len(want.Heads) != 2 || want.HeadsDigest == "" || want.StateDigest == "" {
		t.Fatalf("reduced folder = %#v", want)
	}
	for _, input := range [][]FolderStateRevision{{root, b, a}, {a, root, b}, {b, a, root}} {
		got, err := ReduceFolder(testRepoDID, testFolderID, input, snapshot)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("input order changed folder reduction:\n got %#v\nwant %#v", got, want)
		}
	}
}

func TestReduceFolderRevisionsProtectsStandardRoles(t *testing.T) {
	standardID, err := StandardFolderID(testRepoDID, "inbox")
	if err != nil {
		t.Fatal(err)
	}
	root := testFolderRevision(t, standardID, "initial", nil, 1)
	root.Record.Name, root.Record.Role = "Inbox", "inbox"
	root = sealFolderRevision(t, root)
	if state, err := ReduceFolder(testRepoDID, standardID, []FolderStateRevision{root}, testFolderInventory(root)); err != nil || state.Role != "inbox" {
		t.Fatalf("canonical inbox = %#v, err=%v", state, err)
	}

	tombstone := testFolderRevision(t, standardID, "delete-inbox", []string{root.RKey}, 2)
	tombstone.Record.Tombstone = true
	tombstone = sealFolderRevision(t, tombstone)
	if _, err := ReduceFolder(testRepoDID, standardID, []FolderStateRevision{root, tombstone}, testFolderInventory(root, tombstone)); err == nil {
		t.Fatal("standard inbox folder was tombstoned")
	}

	wrongRole := root
	wrongRole.Record.Role = "sent"
	wrongRole = sealFolderRevision(t, wrongRole)
	if _, err := ReduceFolder(testRepoDID, standardID, []FolderStateRevision{wrongRole}, testFolderInventory(wrongRole)); err == nil {
		t.Fatal("standard role identity was rebound")
	}
	rename := testFolderRevision(t, standardID, "rename-inbox", []string{root.RKey}, 2)
	rename.Record.Name = "Inbox renamed"
	rename = sealFolderRevision(t, rename)
	if _, err := ReduceFolder(testRepoDID, standardID, []FolderStateRevision{root, rename}, testFolderInventory(root, rename)); err == nil {
		t.Fatal("standard role folder was renamed")
	}
}

func TestValidateFolderSetRejectsDuplicateAndReservedLiveNames(t *testing.T) {
	standard := testReducedStandardFolders(t)
	custom := ReducedFolderState{
		FolderID: testFolderID, SnapshotID: "bafy-synthetic-folder-set", Name: "Projects",
	}
	custom.StateDigest = digestReducedFolderState(custom)
	valid := append(append([]ReducedFolderState{}, standard...), custom)
	if err := ValidateFolderSet(testRepoDID, valid, testFolderSetInventory(valid...)); err != nil {
		t.Fatalf("valid complete folder set: %v", err)
	}
	tampered := append([]ReducedFolderState{}, valid...)
	tampered[len(tampered)-1].Name = "Tampered unique name"
	if err := ValidateFolderSet(testRepoDID, tampered, testFolderSetInventory(valid...)); !errors.Is(err, ErrInvalidReference) {
		t.Fatalf("tampered reduced folder error = %v", err)
	}

	duplicate := custom
	duplicate.FolderID = testFolderB
	duplicate.Name = "projects"
	duplicate.StateDigest = digestReducedFolderState(duplicate)
	duplicates := append(append([]ReducedFolderState{}, valid...), duplicate)
	if err := ValidateFolderSet(testRepoDID, duplicates, testFolderSetInventory(duplicates...)); !errors.Is(err, ErrFolderNameCollision) {
		t.Fatalf("duplicate live name error = %v", err)
	}

	reserved := custom
	reserved.Name = "INBOX"
	reserved.StateDigest = digestReducedFolderState(reserved)
	reservedSet := append(append([]ReducedFolderState{}, standard...), reserved)
	if err := ValidateFolderSet(testRepoDID, reservedSet, testFolderSetInventory(reservedSet...)); !errors.Is(err, ErrFolderNameCollision) {
		t.Fatalf("reserved custom name error = %v", err)
	}

	tombstonedDuplicate := duplicate
	tombstonedDuplicate.Tombstone = true
	tombstonedDuplicate.StateDigest = digestReducedFolderState(tombstonedDuplicate)
	withDeleted := append(append([]ReducedFolderState{}, valid...), tombstonedDuplicate)
	if err := ValidateFolderSet(testRepoDID, withDeleted, testFolderSetInventory(withDeleted...)); err != nil {
		t.Fatalf("tombstoned duplicate name affected live projection: %v", err)
	}

	complete := testFolderSetInventory(valid...)
	if err := ValidateFolderSet(testRepoDID, standard, complete); !errors.Is(err, ErrIncompleteSnapshot) {
		t.Fatalf("incomplete folder set error = %v", err)
	}
}

func TestFolderCommitmentsRejectMalformedRepositoryDID(t *testing.T) {
	record := testFolderRevision(t, testFolderID, "initial", nil, 1).Record
	record.Name = "Projects"
	for _, repoDID := range []string{"did:", "did:PLC:rfwhywgeym2ek7ioeyxkvsn6", "not-a-did"} {
		if _, err := FolderRevisionRKey(repoDID, record); !errors.Is(err, ErrInvalidRevision) {
			t.Errorf("FolderRevisionRKey(%q) error = %v", repoDID, err)
		}
		if _, err := StandardFolderID(repoDID, "inbox"); !errors.Is(err, ErrInvalidRevision) {
			t.Errorf("StandardFolderID(%q) error = %v", repoDID, err)
		}
	}
	invalidFolder := record
	invalidFolder.FolderID = "folder-short"
	if _, err := FolderRevisionRKey(testRepoDID, invalidFolder); !errors.Is(err, ErrInvalidRevision) {
		t.Errorf("malformed folder ID revision error = %v", err)
	}
	if _, err := FolderOperationClaimRKey(testRepoDID, invalidFolder.FolderID, "initial"); !errors.Is(err, ErrInvalidRevision) {
		t.Errorf("malformed folder ID claim error = %v", err)
	}
}

func TestStandardFolderIdentityGoldenVector(t *testing.T) {
	got, err := StandardFolderID(testRepoDID, "inbox")
	if err != nil {
		t.Fatal(err)
	}
	const want = "folder-5767260bf0bcae17656695c629d07e65ecd1dc0716140f7121499d389d2c2d72"
	if got != want {
		t.Fatalf("standard folder ID = %q", got)
	}
	if _, err := StandardFolderID(testRepoDID, "unknown"); err == nil {
		t.Fatal("unknown standard role was accepted")
	}
}

func TestReduceFolderAllowsConcurrentInitializationRoots(t *testing.T) {
	first := testFolderRevision(t, testFolderID, "root-a", nil, 1)
	first.Record.Name = "Alpha"
	first = sealFolderRevision(t, first)
	second := testFolderRevision(t, testFolderID, "root-b", nil, 1)
	second.Record.Name = "Beta"
	second = sealFolderRevision(t, second)
	state, err := ReduceFolder(testRepoDID, testFolderID, []FolderStateRevision{first, second}, testFolderInventory(first, second))
	if err != nil {
		t.Fatal(err)
	}
	if state.Name != "Beta" || len(state.Heads) != 2 {
		t.Fatalf("concurrent roots = %#v", state)
	}
}

func TestReduceFolderRevisionsMakesCustomDeletionIrreversible(t *testing.T) {
	root := testFolderRevision(t, testFolderID, "initial", nil, 1)
	root.Record.Name = "Projects"
	root = sealFolderRevision(t, root)
	tombstone := testFolderRevision(t, testFolderID, "delete", []string{root.RKey}, 2)
	tombstone.Record.Tombstone = true
	tombstone = sealFolderRevision(t, tombstone)
	staleRename := testFolderRevision(t, testFolderID, "stale-rename", []string{root.RKey}, 2)
	staleRename.Record.Name = "Projects 2"
	staleRename = sealFolderRevision(t, staleRename)
	state, err := ReduceFolder(testRepoDID, testFolderID, []FolderStateRevision{root, staleRename, tombstone}, testFolderInventory(root, staleRename, tombstone))
	if err != nil {
		t.Fatal(err)
	}
	if !state.Tombstone {
		t.Fatal("concurrent folder tombstone was lost")
	}

	resurrect := testFolderRevision(t, testFolderID, "resurrect", []string{staleRename.RKey, tombstone.RKey}, 3)
	resurrect.Record.Name = "Back"
	resurrect = sealFolderRevision(t, resurrect)
	if _, err := ReduceFolder(testRepoDID, testFolderID, []FolderStateRevision{root, staleRename, tombstone, resurrect}, testFolderInventory(root, staleRename, tombstone, resurrect)); err == nil {
		t.Fatal("rename causally after folder tombstone was accepted")
	}
}

func TestFolderOperationClaimRejectsChangedPayloadRetry(t *testing.T) {
	revision := testFolderRevision(t, testFolderID, "retry", nil, 1)
	revision.Record.Name = "Projects"
	revision = sealFolderRevision(t, revision)
	claim, err := NewFolderOperationClaim(testRepoDID, revision)
	if err != nil {
		t.Fatal(err)
	}
	collision := revision
	collision.Record.Name = "Other"
	collision = sealFolderRevision(t, collision)
	collisionClaim, err := NewFolderOperationClaim(testRepoDID, collision)
	if err != nil {
		t.Fatal(err)
	}
	if claim.RKey != collisionClaim.RKey {
		t.Fatal("same operation did not collide at one folder claim key")
	}
	if err := VerifyFolderOperationClaimRetry(claim, collisionClaim); !errors.Is(err, ErrOperationCollision) {
		t.Fatalf("claim collision error = %v", err)
	}
	retry := revision
	retry.Record.CreatedAt = time.Date(2026, 8, 20, 1, 2, 4, 0, time.UTC).Format(time.RFC3339Nano)
	retry = sealFolderRevision(t, retry)
	if err := VerifyFolderRevisionRetry(testRepoDID, revision, retry); err != nil {
		t.Fatalf("semantic retry with new server time: %v", err)
	}
	if err := VerifyFolderRevisionRetry(testRepoDID, revision, collision); !errors.Is(err, ErrOperationCollision) {
		t.Fatalf("changed folder retry error = %v", err)
	}
}

func TestReduceFolderRequiresOpaqueCompleteSnapshot(t *testing.T) {
	root := testFolderRevision(t, testFolderID, "initial", nil, 1)
	root.Record.Name = "Projects"
	root = sealFolderRevision(t, root)
	rename := testFolderRevision(t, testFolderID, "rename", []string{root.RKey}, 2)
	rename.Record.Name = "Renamed"
	rename = sealFolderRevision(t, rename)
	if _, err := ReduceFolder(testRepoDID, testFolderID, []FolderStateRevision{root}, testFolderInventory(root, rename)); !errors.Is(err, ErrIncompleteSnapshot) {
		t.Fatalf("truncated folder snapshot error = %v", err)
	}
	if _, err := ReduceFolder(testRepoDID, testFolderID, []FolderStateRevision{root}, VerifiedFolderSnapshot{}); !errors.Is(err, ErrIncompleteSnapshot) {
		t.Fatalf("unverified folder snapshot error = %v", err)
	}
	nullParents := root
	nullParents.Record.Parents = nil
	nullParents = sealFolderRevision(t, nullParents)
	if _, err := ReduceFolder(testRepoDID, testFolderID, []FolderStateRevision{nullParents}, testFolderInventory(nullParents)); err == nil {
		t.Fatal("null folder root parents were accepted")
	}
	tooHigh := root
	tooHigh.Record.Revision = maxPortableRevision + 1
	tooHigh = sealFolderRevision(t, tooHigh)
	if _, err := ReduceFolder(testRepoDID, testFolderID, []FolderStateRevision{tooHigh}, testFolderInventory(tooHigh)); !errors.Is(err, ErrInvalidRevision) {
		t.Fatalf("non-portable folder revision error = %v", err)
	}
}

func TestFolderRevisionCommitmentGoldenVector(t *testing.T) {
	record := FolderRevisionRecord{
		Type: FolderRevisionCollection, FolderID: testFolderID,
		OperationID: "rename-<>&-雪", Parents: []string{
			"folder-state-1111111111111111111111111111111111111111111111111111111111111111",
			"folder-state-2222222222222222222222222222222222222222222222222222222222222222",
		},
		Revision: 3, Name: strings.Repeat("x", 130) + "<&雪", CreatedAt: "2026-08-20T01:02:03.456Z",
	}
	encoded, err := CanonicalFolderRevisionBytes(record)
	if err != nil {
		t.Fatal(err)
	}
	const wantHex = "636f6d61696c2d666f6c6465722d73746174652d7265766973696f6e2d63616e6f6e6963616c2d7631001a656d61696c2e61746d6f732e666f6c6465725265766973696f6e47666f6c6465722d616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161610e72656e616d652d3c3e262de99baa024d666f6c6465722d73746174652d313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131314d666f6c6465722d73746174652d32323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232038701787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878783c26e99baa00000018323032362d30382d32305430313a30323a30332e3435365a"
	if got := hex.EncodeToString(encoded); got != wantHex {
		t.Fatalf("canonical folder bytes = %s", got)
	}
	const wantRKey = "folder-state-32fb3e1334c9874f0fedf386094a139aed51f1a192ffff9ea3767e9e5b64ff22"
	if got, err := FolderRevisionRKey(testRepoDID, record); err != nil || got != wantRKey {
		t.Fatalf("folder revision rkey=%q err=%v", got, err)
	}
	const wantClaimRKey = "folder-operation-02f5bda182ca3379fc47a3f38ef9e521317531a1c81c62d359d5b5a2538c978f"
	if got, err := FolderOperationClaimRKey(testRepoDID, record.FolderID, record.OperationID); err != nil || got != wantClaimRKey {
		t.Fatalf("folder claim rkey=%q err=%v", got, err)
	}
}

func TestDecodeFolderRevisionRejectsUnknownWireField(t *testing.T) {
	record := FolderRevisionRecord{
		Type: FolderRevisionCollection, FolderID: testFolderID, OperationID: "decode",
		Parents: []string{}, Revision: 1, Name: "Projects", CreatedAt: time.Date(2026, 8, 20, 1, 2, 3, 0, time.UTC).Format(time.RFC3339Nano),
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeFolderRevisionRecord(encoded); err != nil {
		t.Fatal(err)
	}
	unknown := append(append([]byte(nil), encoded[:len(encoded)-1]...), []byte(`,"unexpected":true}`)...)
	if _, err := DecodeFolderRevisionRecord(unknown); err == nil {
		t.Fatal("unknown folder revision field was accepted")
	}
	invalid := record
	invalid.Name = string([]byte{0xff})
	if _, err := CanonicalFolderRevisionBytes(invalid); err == nil {
		t.Fatal("invalid UTF-8 folder name was accepted")
	}
	claim := FolderOperationClaimRecord{
		Type: FolderOperationCollection, FolderID: testFolderID,
		OperationID: "decode", RevisionRKey: "folder-state-" + strings.Repeat("a", 64),
	}
	claimJSON, err := json.Marshal(claim)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeFolderOperationClaimRecord(claimJSON); err != nil {
		t.Fatal(err)
	}
	claimUnknown := append(append([]byte(nil), claimJSON[:len(claimJSON)-1]...), []byte(`,"unexpected":true}`)...)
	if _, err := DecodeFolderOperationClaimRecord(claimUnknown); err == nil {
		t.Fatal("unknown folder claim field was accepted")
	}
}

func testFolderRevision(t *testing.T, folderID, operationID string, parents []string, revision uint64) FolderStateRevision {
	t.Helper()
	return FolderStateRevision{Record: FolderRevisionRecord{
		Type: FolderRevisionCollection, FolderID: folderID, OperationID: operationID,
		Parents: append([]string{}, parents...), Revision: revision,
		CreatedAt: time.Date(2026, 8, 20, 1, 2, 3, 0, time.UTC).Format(time.RFC3339Nano),
	}}
}

func sealFolderRevision(t *testing.T, revision FolderStateRevision) FolderStateRevision {
	t.Helper()
	rkey, err := FolderRevisionRKey(testRepoDID, revision.Record)
	if err != nil {
		t.Fatal(err)
	}
	revision.RKey = rkey
	return revision
}

func testFolderInventory(revisions ...FolderStateRevision) VerifiedFolderSnapshot {
	claims := make(map[string]string, len(revisions))
	for _, revision := range revisions {
		claim, err := NewFolderOperationClaim(testRepoDID, revision)
		if err == nil {
			claims[claim.RKey] = claim.Record.RevisionRKey
		}
	}
	snapshot := VerifiedFolderSnapshot{
		snapshotID: "bafy-synthetic-folder-commit", revisionCount: len(revisions), operationClaims: claims,
	}
	if len(revisions) > 0 {
		snapshot.folderID = revisions[0].Record.FolderID
	}
	snapshot.seal = snapshot.snapshotSeal()
	return snapshot
}

func testReducedStandardFolders(t *testing.T) []ReducedFolderState {
	t.Helper()
	roles := []string{"archive", "drafts", "important", "inbox", "junk", "sent", "trash"}
	states := make([]ReducedFolderState, 0, len(roles))
	for _, role := range roles {
		folderID, err := StandardFolderID(testRepoDID, role)
		if err != nil {
			t.Fatal(err)
		}
		state := ReducedFolderState{
			FolderID: folderID, SnapshotID: "bafy-synthetic-folder-set", Name: standardFolderNames[role], Role: role,
		}
		state.StateDigest = digestReducedFolderState(state)
		states = append(states, state)
	}
	return states
}

func testFolderSetInventory(states ...ReducedFolderState) VerifiedFolderSetSnapshot {
	digests := make(map[string]string, len(states))
	for _, state := range states {
		digests[state.FolderID] = state.StateDigest
	}
	snapshot := VerifiedFolderSetSnapshot{
		snapshotID: "bafy-synthetic-folder-set", repoDID: testRepoDID,
		folderCount: len(states), stateDigests: digests,
	}
	snapshot.seal = snapshot.snapshotSeal()
	return snapshot
}
