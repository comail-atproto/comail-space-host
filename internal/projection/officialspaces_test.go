package projection

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/comail-atproto/comail-space-host/internal/mailbox"
	"github.com/comail-atproto/comail-space-host/internal/mailboxstate"
	"github.com/comail-atproto/comail-space-host/internal/providers/officialspaces"
)

const (
	testOfficialRepoDID  = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb"
	testOfficialSnapshot = "sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

var _ func(context.Context, *mailboxstate.ContentVerifiedSource, string) (Report, error) = RebuildOfficial

type fakeOfficialContentSource struct {
	summary   mailboxstate.ContentVerificationSummary
	folders   []mailboxstate.ReducedFolderState
	states    []mailboxstate.ReducedState
	messages  []fakeOfficialMessage
	failAfter int
	valid     bool
}

type fakeOfficialMessage struct {
	version mailboxstate.MessageVersion
	raw     []byte
}

func (source *fakeOfficialContentSource) Summary() mailboxstate.ContentVerificationSummary {
	return source.summary
}

func (source *fakeOfficialContentSource) Folders() []mailboxstate.ReducedFolderState {
	return append([]mailboxstate.ReducedFolderState(nil), source.folders...)
}

func (source *fakeOfficialContentSource) MessageStates() []mailboxstate.ReducedState {
	return append([]mailboxstate.ReducedState(nil), source.states...)
}

func (source *fakeOfficialContentSource) VisitMessages(ctx context.Context, visit func(mailboxstate.MessageVersion, []byte) error) error {
	for index, message := range source.messages {
		if err := ctx.Err(); err != nil {
			return err
		}
		if source.failAfter > 0 && index == source.failAfter {
			return errors.New("synthetic visit failure")
		}
		if err := visit(message.version, append([]byte(nil), message.raw...)); err != nil {
			return err
		}
	}
	return nil
}

func (source *fakeOfficialContentSource) ValidateSeal() error {
	if !source.valid {
		return mailboxstate.ErrContentVerification
	}
	return nil
}

func TestRebuildOfficialSpacesProjectsSelectedV3State(t *testing.T) {
	source, live, _, inboxID, archiveID := officialProjectionFixture(t)
	destination := filepath.Join(t.TempDir(), "fresh", "mailbox.sqlite")

	report, err := rebuildOfficialSpaces(context.Background(), source, destination)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed() || report.Version != 3 || report.Folders != 2 || report.Messages != 1 ||
		report.States != 1 || report.Tombstones != 1 || report.TotalBytes != int64(len(live.raw)) {
		t.Fatalf("report=%+v", report)
	}
	if report.Target.ProviderOrigin != source.summary.Target.Origin || report.Target.SpaceURI != source.summary.Target.SpaceURI ||
		report.Target.RepoDID != source.summary.Target.RepoDID || report.Target.Epoch != source.summary.Target.Epoch {
		t.Fatalf("report target=%+v", report.Target)
	}
	info, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("projection mode=%o", info.Mode().Perm())
	}

	db := openOfficialProjection(t, destination)
	defer db.Close()
	var messages, folders, memberships int
	if err := db.QueryRow(`SELECT COUNT(*) FROM messages`).Scan(&messages); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM folders`).Scan(&folders); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM message_mailboxes`).Scan(&memberships); err != nil {
		t.Fatal(err)
	}
	if messages != 1 || folders != 2 || memberships != 2 {
		t.Fatalf("messages=%d folders=%d memberships=%d", messages, folders, memberships)
	}
	rows, err := db.Query(`SELECT f.rkey, mm.uid, mm.uid_validity
FROM message_mailboxes mm JOIN folders f ON f.name=mm.mailbox
WHERE mm.rkey=? ORDER BY f.rkey`, live.version.RKey)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	wantValidity := map[string]uint32{
		inboxID:   mailbox.StableFolderUIDValidity(testOfficialRepoDID, inboxID),
		archiveID: mailbox.StableFolderUIDValidity(testOfficialRepoDID, archiveID),
	}
	seen := 0
	for rows.Next() {
		var folderID string
		var uid, uidValidity uint32
		if err := rows.Scan(&folderID, &uid, &uidValidity); err != nil {
			t.Fatal(err)
		}
		if uid != 1 || uidValidity != wantValidity[folderID] {
			t.Fatalf("folder=%s uid=%d uidValidity=%d", folderID, uid, uidValidity)
		}
		seen++
	}
	if err := rows.Err(); err != nil || seen != 2 {
		t.Fatalf("memberships seen=%d error=%v", seen, err)
	}
}

func TestRebuildOfficialSpacesManifestIgnoresInventoryOrder(t *testing.T) {
	first, _, _, _, _ := officialProjectionFixture(t)
	second, _, _, _, _ := officialProjectionFixture(t)
	reverseOfficialFixture(second)

	firstReport, err := rebuildOfficialSpaces(context.Background(), first, filepath.Join(t.TempDir(), "one.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	secondReport, err := rebuildOfficialSpaces(context.Background(), second, filepath.Join(t.TempDir(), "two.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	if firstReport.ManifestSHA256 == "" || firstReport.ManifestSHA256 != secondReport.ManifestSHA256 {
		t.Fatalf("manifest one=%q two=%q", firstReport.ManifestSHA256, secondReport.ManifestSHA256)
	}
}

func TestRebuildOfficialSpacesOmitsTombstonesAndSupersededVersions(t *testing.T) {
	source, live, superseded, _, _ := officialProjectionFixture(t)
	destination := filepath.Join(t.TempDir(), "mailbox.sqlite")
	report, err := rebuildOfficialSpaces(context.Background(), source, destination)
	if err != nil {
		t.Fatal(err)
	}
	db := openOfficialProjection(t, destination)
	defer db.Close()
	for _, rkey := range []string{superseded.version.RKey, source.messages[2].version.RKey} {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM messages WHERE rkey=?`, rkey).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("omitted version %s was projected", rkey)
		}
	}
	var selected int
	if err := db.QueryRow(`SELECT COUNT(*) FROM messages WHERE rkey=?`, live.version.RKey).Scan(&selected); err != nil {
		t.Fatal(err)
	}
	var tombstonedFolder int
	if err := db.QueryRow(`SELECT COUNT(*) FROM folders WHERE rkey=?`, source.folders[2].FolderID).Scan(&tombstonedFolder); err != nil {
		t.Fatal(err)
	}
	if selected != 1 || tombstonedFolder != 0 || report.Tombstones != 1 {
		t.Fatalf("selected=%d tombstonedFolder=%d report=%+v", selected, tombstonedFolder, report)
	}
}

func TestRebuildOfficialSpacesRefusesExistingDestination(t *testing.T) {
	source, _, _, _, _ := officialProjectionFixture(t)
	destination := filepath.Join(t.TempDir(), "existing.sqlite")
	before := []byte("keep existing destination")
	if err := os.WriteFile(destination, before, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := rebuildOfficialSpaces(context.Background(), source, destination); !errors.Is(err, os.ErrExist) {
		t.Fatalf("error=%v", err)
	}
	after, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("existing destination changed")
	}
}

func TestRebuildOfficialSpacesRefusesAndPreservesExistingSidecars(t *testing.T) {
	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		t.Run(suffix, func(t *testing.T) {
			source, _, _, _, _ := officialProjectionFixture(t)
			destination := filepath.Join(t.TempDir(), "mailbox.sqlite")
			sidecar := destination + suffix
			before := []byte("pre-existing sidecar")
			if err := os.WriteFile(sidecar, before, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := rebuildOfficialSpaces(context.Background(), source, destination); !errors.Is(err, os.ErrExist) {
				t.Fatalf("error=%v", err)
			}
			after, err := os.ReadFile(sidecar)
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != string(before) {
				t.Fatal("pre-existing sidecar changed")
			}
			if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("destination was created: %v", err)
			}
		})
	}
}

func TestRebuildOfficialSpacesDeletesPartialDestinationOnFailure(t *testing.T) {
	source, _, _, _, _ := officialProjectionFixture(t)
	source.failAfter = 2
	destination := filepath.Join(t.TempDir(), "partial.sqlite")
	if _, err := rebuildOfficialSpaces(context.Background(), source, destination); err == nil {
		t.Fatal("synthetic visit failure was accepted")
	}
	for _, suffix := range []string{"", "-journal", "-wal", "-shm"} {
		if _, err := os.Lstat(destination + suffix); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("partial artifact %q remains: %v", destination+suffix, err)
		}
	}
}

func officialProjectionFixture(t *testing.T) (*fakeOfficialContentSource, fakeOfficialMessage, fakeOfficialMessage, string, string) {
	t.Helper()
	inboxID, err := mailboxstate.StandardFolderID(testOfficialRepoDID, "inbox")
	if err != nil {
		t.Fatal(err)
	}
	archiveID, err := mailboxstate.StandardFolderID(testOfficialRepoDID, "archive")
	if err != nil {
		t.Fatal(err)
	}
	tombstonedID := "folder-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	folders := []mailboxstate.ReducedFolderState{
		{FolderID: inboxID, SnapshotID: testOfficialSnapshot, Name: "Inbox", Role: "inbox", Height: 1, StateDigest: testDigest('1')},
		{FolderID: archiveID, SnapshotID: testOfficialSnapshot, Name: "Archive", Role: "archive", Height: 2, StateDigest: testDigest('2')},
		{FolderID: tombstonedID, SnapshotID: testOfficialSnapshot, Name: "Old", Tombstone: true, Height: 3, StateDigest: testDigest('3')},
	}
	superseded := newFakeOfficialMessage(t, "draft:one", "old body")
	live := newFakeOfficialMessage(t, "draft:one", "new body")
	tombstoned := newFakeOfficialMessage(t, "message:deleted", "deleted body")
	states := []mailboxstate.ReducedState{
		{
			LogicalMessageID: live.version.Record.LogicalMessageID, SnapshotID: testOfficialSnapshot,
			Version: live.version.RKey, MailboxIDs: []string{inboxID, archiveID}, Keywords: []string{"$flagged", "$seen"},
			DeletePending: true, Height: 4, StateDigest: testDigest('4'),
		},
		{
			LogicalMessageID: tombstoned.version.Record.LogicalMessageID, SnapshotID: testOfficialSnapshot,
			Version: tombstoned.version.RKey, MailboxIDs: []string{tombstonedID}, Tombstone: true,
			Height: 5, StateDigest: testDigest('5'),
		},
	}
	source := &fakeOfficialContentSource{
		valid: true,
		summary: mailboxstate.ContentVerificationSummary{
			Target: officialspaces.Target{
				Origin:   "https://spaces.example",
				SpaceURI: "at://did:plc:aaaaaaaaaaaaaaaaaaaaaaaa/space/email.atmos.mailbox/primary",
				RepoDID:  testOfficialRepoDID, Epoch: officialspaces.PinnedEpoch,
			},
			Revision: "3jzfcijpj2z2a", SnapshotID: testOfficialSnapshot,
			MessageVersions: 3, UniqueBlobs: 3,
			TotalBytes:     int64(len(superseded.raw) + len(live.raw) + len(tombstoned.raw)),
			ManifestSHA256: testDigest('f'),
		},
		folders: folders, states: states,
		messages: []fakeOfficialMessage{superseded, live, tombstoned},
	}
	return source, live, superseded, inboxID, archiveID
}

func newFakeOfficialMessage(t *testing.T, sourceKey, body string) fakeOfficialMessage {
	t.Helper()
	raw := []byte("From: sender@example.invalid\r\nTo: member@example.invalid\r\nSubject: synthetic\r\n\r\n" + body + "\r\n")
	pair, err := mailbox.NewMessagePair(mailbox.ImportedMessage{
		RecipientDID: testOfficialRepoDID, SourceKey: sourceKey, Raw: raw, Mailbox: "Inbox",
	}, mailbox.BlobRef{
		Type: "blob", Ref: mailbox.CIDLink{Link: "bafk-synthetic-" + body},
		MIMEType: mailbox.MessageMIMEType, Size: int64(len(raw)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return fakeOfficialMessage{version: mailboxstate.MessageVersion{RKey: pair.RKey, CID: "bafy-synthetic-record", Record: pair.Message}, raw: raw}
}

func reverseOfficialFixture(source *fakeOfficialContentSource) {
	for left, right := 0, len(source.folders)-1; left < right; left, right = left+1, right-1 {
		source.folders[left], source.folders[right] = source.folders[right], source.folders[left]
	}
	for left, right := 0, len(source.states)-1; left < right; left, right = left+1, right-1 {
		source.states[left], source.states[right] = source.states[right], source.states[left]
	}
	for left, right := 0, len(source.messages)-1; left < right; left, right = left+1, right-1 {
		source.messages[left], source.messages[right] = source.messages[right], source.messages[left]
	}
}

func testDigest(value byte) string {
	result := make([]byte, 64)
	for index := range result {
		result[index] = value
	}
	return "sha256-" + string(result)
}

func openOfficialProjection(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&immutable=1")
	if err != nil {
		t.Fatal(err)
	}
	return db
}
