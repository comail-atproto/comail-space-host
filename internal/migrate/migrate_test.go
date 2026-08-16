package migrate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/comail-atproto/comail-pds-lab/internal/mailbox"
	"github.com/comail-atproto/comail-pds-lab/internal/memory"
	"github.com/comail-atproto/comail-pds-lab/internal/repository"
	"github.com/comail-atproto/comail-pds-lab/internal/sqliteimport"

	_ "modernc.org/sqlite"
)

const testDID = "did:plc:migrationtest"

func migrationFixture(t *testing.T) *sqliteimport.Snapshot {
	t.Helper()
	path := filepath.Join(t.TempDir(), "migration.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	schema := `
CREATE TABLE spaces (space_id INTEGER PRIMARY KEY, owner TEXT, type TEXT, key TEXT, user TEXT, modseq INTEGER);
CREATE TABLE collections (coll_id INTEGER PRIMARY KEY, space_id INTEGER, name TEXT, uid_validity INTEGER, next_uid INTEGER);
CREATE TABLE messages (coll_id INTEGER, rkey TEXT, uid INTEGER, modseq INTEGER, deleted INTEGER, raw BLOB, message_id TEXT, subject TEXT, from_addr TEXT, to_json TEXT, date INTEGER, blobs_json TEXT, flags_json TEXT, in_reply_to TEXT, references_ids TEXT, PRIMARY KEY(coll_id,rkey));`
	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO spaces VALUES(1,?,?,?,?,12)`, testDID, mailbox.MailboxSpaceType, "primary", testDID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO collections VALUES(10,1,'INBOX',101,2),(11,1,'Archive',102,1)`); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		collID int
		rkey   string
		uid    int
		modseq int
		raw    []byte
		flags  string
	}{
		{10, "old-a", 1, 10, []byte("Message-ID: <a@example.com>\r\nSubject: alpha\r\n\r\nfirst synthetic body\r\n"), `{"Seen":true}`},
		{10, "old-b", 2, 11, []byte("Message-ID: <b@example.com>\r\nSubject: beta\r\n\r\nsecond synthetic body\r\n"), `{"Flagged":true}`},
		{11, "old-c", 1, 12, []byte("Message-ID: <c@example.com>\r\nSubject: gamma\r\n\r\nthird synthetic body\r\n"), `{}`},
	}
	for _, row := range rows {
		if _, err := db.Exec(`INSERT INTO messages VALUES(?,?,?,?,0,?,?,?,?,?,?,?,?,?,?)`, row.collID, row.rkey, row.uid, row.modseq, row.raw, strings.TrimPrefix(row.rkey, "old-")+"@example.com", "synthetic", "sender@example.com", `[]`, time.Unix(1_700_000_000, 0).Unix(), `[]`, row.flags, "", ""); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	snapshot, err := sqliteimport.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = snapshot.Close() })
	return snapshot
}

func TestDryRunDoesNotCreateProviderStateOrLeakContent(t *testing.T) {
	ctx := context.Background()
	snapshot := migrationFixture(t)
	backend := memory.NewBackend()
	repo := backend.OwnerSession(testDID)
	report, err := Run(ctx, snapshot, repo, Options{RecipientDID: testDID, SpaceKey: "primary"})
	if err != nil {
		t.Fatal(err)
	}
	if !report.DryRun || report.SourceMessages != 3 || report.CreatedMessages != 0 || len(report.Fingerprints) != 3 {
		t.Fatalf("report = %#v", report)
	}
	if _, err := repo.EnsureMailbox(ctx, testDID, "primary"); err != nil {
		t.Fatal(err)
	}
	// EnsureMailbox above creates the first provider state. Before it, Run must
	// not have done so; a dry-run report therefore carries no target URI.
	if report.Target.SpaceURI != "" {
		t.Fatalf("dry run wrote/discovered target: %#v", report.Target)
	}
	b, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"alpha", "sender@example.com", "synthetic body", "Message-ID"} {
		if strings.Contains(string(b), secret) {
			t.Fatalf("redacted report leaked %q: %s", secret, b)
		}
	}
}

func TestCommitMigratesAndVerifiesIdempotently(t *testing.T) {
	ctx := context.Background()
	snapshot := migrationFixture(t)
	repo := memory.NewBackend().OwnerSession(testDID)
	opts := Options{RecipientDID: testDID, SpaceKey: "primary", Commit: true}
	first, err := Run(ctx, snapshot, repo, opts)
	if err != nil {
		t.Fatal(err)
	}
	if first.CreatedMessages != 3 || first.ExistingMessages != 0 || first.CreatedFolders != 2 || !first.Verification.Passed() {
		t.Fatalf("first report = %#v", first)
	}
	second, err := Run(ctx, snapshot, repo, opts)
	if err != nil {
		t.Fatal(err)
	}
	if second.CreatedMessages != 0 || second.ExistingMessages != 3 || second.ExistingFolders != 2 || !second.Verification.Passed() {
		t.Fatalf("second report = %#v", second)
	}
	messageRecords, err := repo.ListRecords(ctx, first.Target, mailbox.MessageCollection)
	if err != nil {
		t.Fatal(err)
	}
	stateRecords, err := repo.ListRecords(ctx, first.Target, mailbox.MessageStateCollection)
	if err != nil {
		t.Fatal(err)
	}
	if len(messageRecords) != 3 || len(stateRecords) != 3 {
		t.Fatalf("destination counts messages=%d states=%d", len(messageRecords), len(stateRecords))
	}
}

type failOnceRepository struct {
	repository.Repository
	failAt int
	calls  int
	failed bool
}

func (f *failOnceRepository) ApplyWrites(ctx context.Context, target repository.Target, writes []repository.Write) (repository.Commit, error) {
	f.calls++
	if !f.failed && f.calls == f.failAt {
		f.failed = true
		return repository.Commit{}, errors.New("synthetic provider interruption")
	}
	return f.Repository.ApplyWrites(ctx, target, writes)
}

func TestInterruptedMigrationResumesWithoutDuplicates(t *testing.T) {
	ctx := context.Background()
	snapshot := migrationFixture(t)
	base := memory.NewBackend().OwnerSession(testDID)
	flaky := &failOnceRepository{Repository: base, failAt: 3}
	opts := Options{RecipientDID: testDID, SpaceKey: "primary", Commit: true}
	if _, err := Run(ctx, snapshot, flaky, opts); err == nil {
		t.Fatal("interrupted migration unexpectedly succeeded")
	}
	report, err := Run(ctx, snapshot, base, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Verification.Passed() {
		t.Fatalf("recovery mismatches = %#v", report.Verification.Mismatches)
	}
	records, err := base.ListRecords(ctx, report.Target, mailbox.MessageCollection)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 3 {
		t.Fatalf("message count after resume = %d", len(records))
	}
}

func TestExistingRecordWithWrongBytesFailsClosed(t *testing.T) {
	ctx := context.Background()
	snapshot := migrationFixture(t)
	repo := memory.NewBackend().OwnerSession(testDID)
	target, err := repo.EnsureMailbox(ctx, testDID, "primary")
	if err != nil {
		t.Fatal(err)
	}
	// Seed a record under a source fingerprint but with a mismatching declared
	// hash. Run must inspect it, not treat ErrExists as proof of idempotency.
	var first sqliteimport.SourceMessage
	inv, err := snapshot.Inspect(ctx, testDID, "primary")
	if err != nil {
		t.Fatal(err)
	}
	if err := snapshot.Stream(ctx, inv.Space, func(src sqliteimport.SourceMessage) error {
		if first.LegacyRKey == "" {
			first = src
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	blob, err := repo.UploadBlob(ctx, target, first.Imported.Raw, mailbox.MessageMIMEType)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := mailbox.NewMessagePair(first.Imported, blob)
	if err != nil {
		t.Fatal(err)
	}
	pair.Message.SHA256 = strings.Repeat("0", 64)
	if _, err := repo.ApplyWrites(ctx, target, []repository.Write{{Action: repository.Create, Collection: mailbox.MessageCollection, RKey: pair.RKey, Value: pair.Message}}); err != nil {
		t.Fatal(err)
	}
	_, err = Run(ctx, snapshot, repo, Options{RecipientDID: testDID, SpaceKey: "primary", Commit: true})
	if !errors.Is(err, mailbox.ErrIntegrity) {
		t.Fatalf("migration error = %v", err)
	}
}

func TestWriteReportUsesExclusivePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence", "report.json")
	report := Report{Version: 1, DryRun: true, Provider: "memory-v1"}
	if err := WriteReport(path, report); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("report mode = %o", got)
	}
	if err := WriteReport(path, report); err == nil {
		t.Fatal("existing evidence was overwritten")
	}
}

func ExampleReport() {
	report := Report{Version: 1, DryRun: true, Provider: "memory-v1", SourceMessages: 3}
	fmt.Printf("dry-run=%t source=%d provider=%s\n", report.DryRun, report.SourceMessages, report.Provider)
	// Output: dry-run=true source=3 provider=memory-v1
}
