// SPDX-License-Identifier: AGPL-3.0-or-later

package authorityv3

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/comail-atproto/comail-space-host/internal/mailbox"
	"github.com/comail-atproto/comail-space-host/internal/mailboxstate"
	"github.com/comail-atproto/comail-space-host/internal/providers/officialspaces"
	"github.com/comail-atproto/comail-space-host/internal/repository"
)

func TestOfficialEngineStoresMemberAuthoredMessageAfterStandardFolderInitialization(t *testing.T) {
	target := testOfficialEngineTarget()
	raw := []byte("Message-ID: <engine-store@test>\r\nSubject: engine\r\n\r\nbody")
	fingerprint := sourceFingerprint(target.RepoDID, "", raw)
	inboxID, err := mailboxstate.StandardFolderID(target.RepoDID, "inbox")
	if err != nil {
		t.Fatal(err)
	}
	base := testEngineSnapshot(target, "sha256-"+strings.Repeat("1", 64))
	final := testEngineSnapshot(target, "sha256-"+strings.Repeat("2", 64))
	final.Messages = []MessageVersion{{
		URI:  target.SpaceURI + "/" + target.RepoDID + "/" + mailbox.MessageCollection + "/" + fingerprint,
		RKey: fingerprint, Fingerprint: fingerprint, LogicalMessageID: fingerprint,
		SHA256: rawSHA256(raw), Size: int64(len(raw)), Raw: append([]byte(nil), raw...),
	}}
	final.States = []MessageState{{
		LogicalMessageID: fingerprint, SnapshotID: final.SnapshotID, Version: fingerprint,
		MailboxIDs: []string{inboxID}, Keywords: []string{"$seen"},
		Heads: []string{"state-" + strings.Repeat("3", 64)}, Height: 1, RevisionCount: 1,
	}}

	writer := newFakeOfficialWriter(target)
	writer.upload = mailbox.BlobRef{
		Type: "blob", Ref: mailbox.CIDLink{Link: "bafkreiengine"},
		MIMEType: mailbox.MessageMIMEType, Size: int64(len(raw)),
	}
	reads := 0
	engine, err := newOfficialEngine(writer, target, func(context.Context) (Snapshot, error) {
		reads++
		if reads <= 2 {
			return base, nil
		}
		return final, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	engine.now = func() time.Time { return time.Unix(10, 0).UTC() }

	receipt, err := engine.Store(t.Context(), StoreInput{
		RecipientDID: target.RepoDID, Raw: raw,
		Placement: Placement{
			Folders:  []FolderSelection{{SourceKey: "role:inbox", Name: "Inbox", Role: "inbox"}},
			Keywords: []string{"$seen"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Target != target || receipt.Fingerprint != fingerprint || !receipt.Verified || reads != 3 {
		t.Fatalf("receipt=%+v reads=%d", receipt, reads)
	}
	if len(writer.batches) != 2 || len(writer.batches[0]) != 14 || len(writer.batches[1]) != 3 {
		t.Fatalf("batch sizes=%v", writer.batchSizes())
	}
	messageCreate, revisionCreate, claimCreate := writer.batches[1][0], writer.batches[1][1], writer.batches[1][2]
	if messageCreate.Collection != mailbox.MessageCollection || messageCreate.RKey != fingerprint ||
		revisionCreate.Collection != mailbox.MessageStateRevisionCollection ||
		claimCreate.Collection != mailbox.MessageStateOperationCollection {
		t.Fatalf("message batch=%+v", writer.batches[1])
	}
	revision, err := mailboxstate.DecodeRevisionRecord(revisionCreate.Value)
	if err != nil {
		t.Fatal(err)
	}
	if revision.LogicalMessageID != fingerprint || revision.OperationID != "initial" || revision.Revision != 1 ||
		len(revision.Parents) != 0 || len(revision.MailboxIDs) != 1 || revision.MailboxIDs[0] != inboxID ||
		len(revision.Keywords) != 1 || revision.Keywords[0].Name != "$seen" || !revision.Keywords[0].Present {
		t.Fatalf("initial revision=%+v", revision)
	}
	capabilities, err := engine.Capabilities(t.Context())
	if err != nil || !capabilities.supports(target) {
		t.Fatalf("capabilities=%+v error=%v", capabilities, err)
	}
}

func TestOfficialEngineAppendsCompleteStateFromExactCausalHeads(t *testing.T) {
	target := testOfficialEngineTarget()
	inboxID, _ := mailboxstate.StandardFolderID(target.RepoDID, "inbox")
	archiveID, _ := mailboxstate.StandardFolderID(target.RepoDID, "archive")
	mailboxIDs := []string{archiveID, inboxID}
	if mailboxIDs[0] > mailboxIDs[1] {
		mailboxIDs[0], mailboxIDs[1] = mailboxIDs[1], mailboxIDs[0]
	}
	version := "sha256-" + strings.Repeat("4", 64)
	logicalID := "sha256-" + strings.Repeat("5", 64)
	current := testEngineSnapshot(target, "sha256-"+strings.Repeat("6", 64))
	current.Folders = []FolderState{{FolderID: inboxID}, {FolderID: archiveID}}
	current.Messages = []MessageVersion{{RKey: version, LogicalMessageID: logicalID}}
	current.States = []MessageState{{
		LogicalMessageID: logicalID, SnapshotID: current.SnapshotID, Version: version,
		MailboxIDs: []string{inboxID}, Keywords: []string{"$flagged", "$seen"},
		Heads:       []string{"state-" + strings.Repeat("7", 64), "state-" + strings.Repeat("8", 64)},
		HeadsDigest: "sha256-" + strings.Repeat("9", 64), StateDigest: "sha256-" + strings.Repeat("a", 64),
		Height: 2, RevisionCount: 3,
	}}
	mutation := StateMutation{
		SnapshotID: current.SnapshotID, LogicalMessageID: logicalID, OperationID: "jmap-state-2",
		ExpectedHeads:       append([]string(nil), current.States[0].Heads...),
		ExpectedHeadsDigest: current.States[0].HeadsDigest, ExpectedStateDigest: current.States[0].StateDigest,
		ExpectedHeight: 2, ExpectedRevisionCount: 3, Version: version,
		MailboxIDs: mailboxIDs, Keywords: []string{"$answered", "$seen"}, DeletePending: true,
	}
	final := testEngineSnapshot(target, "sha256-"+strings.Repeat("b", 64))
	final.Folders = current.Folders
	final.Messages = current.Messages
	final.States = []MessageState{{
		LogicalMessageID: logicalID, SnapshotID: final.SnapshotID, Version: version,
		MailboxIDs: mailboxIDs, Keywords: mutation.Keywords, DeletePending: true,
		Heads: []string{"state-" + strings.Repeat("c", 64)}, Height: 3, RevisionCount: 4,
	}}
	writer := newFakeOfficialWriter(target)
	reads := 0
	engine, err := newOfficialEngine(writer, target, func(context.Context) (Snapshot, error) {
		reads++
		if reads == 1 {
			return current, nil
		}
		return final, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	engine.now = func() time.Time { return time.Unix(20, 0).UTC() }

	state, err := engine.AppendState(t.Context(), mutation)
	if err != nil || state.SnapshotID != final.SnapshotID {
		t.Fatalf("state=%+v error=%v", state, err)
	}
	if len(writer.batches) != 1 || len(writer.batches[0]) != 2 {
		t.Fatalf("batch sizes=%v", writer.batchSizes())
	}
	revision, err := mailboxstate.DecodeRevisionRecord(writer.batches[0][0].Value)
	if err != nil {
		t.Fatal(err)
	}
	if revision.OperationID != mutation.OperationID || revision.Revision != 3 ||
		!equalStrings(revision.Parents, mutation.ExpectedHeads) || !equalStrings(revision.MailboxIDs, mailboxIDs) ||
		revision.DeletePending == nil || !*revision.DeletePending {
		t.Fatalf("state revision=%+v", revision)
	}
	wantKeywords := []mailboxstate.KeywordAssignment{
		{Name: "$answered", Present: true}, {Name: "$flagged", Present: false}, {Name: "$seen", Present: true},
	}
	if len(revision.Keywords) != len(wantKeywords) {
		t.Fatalf("keyword assignments=%+v", revision.Keywords)
	}
	for index := range wantKeywords {
		if revision.Keywords[index] != wantKeywords[index] {
			t.Fatalf("keyword assignments=%+v", revision.Keywords)
		}
	}

	stale := mutation
	stale.ExpectedStateDigest = "sha256-" + strings.Repeat("f", 64)
	readerCalls := 0
	conflictEngine, _ := newOfficialEngine(newFakeOfficialWriter(target), target, func(context.Context) (Snapshot, error) {
		readerCalls++
		return current, nil
	})
	if _, err := conflictEngine.AppendState(t.Context(), stale); !errors.Is(err, ErrConflict) || readerCalls != 1 {
		t.Fatalf("stale append error=%v reads=%d", err, readerCalls)
	}
}

func TestOfficialEngineRejectsStateChangesAfterTombstoneBeforeWrite(t *testing.T) {
	target := testOfficialEngineTarget()
	inboxID, _ := mailboxstate.StandardFolderID(target.RepoDID, "inbox")
	version := "sha256-" + strings.Repeat("4", 64)
	logicalID := "sha256-" + strings.Repeat("5", 64)
	current := testEngineSnapshot(target, "sha256-"+strings.Repeat("6", 64))
	current.Folders = []FolderState{{FolderID: inboxID}}
	current.Messages = []MessageVersion{{RKey: version, LogicalMessageID: logicalID}}
	current.States = []MessageState{{
		LogicalMessageID: logicalID, SnapshotID: current.SnapshotID, Version: version,
		MailboxIDs: []string{inboxID}, Keywords: []string{"$seen"}, Tombstone: true,
		Heads:       []string{"state-" + strings.Repeat("7", 64)},
		HeadsDigest: "sha256-" + strings.Repeat("8", 64), StateDigest: "sha256-" + strings.Repeat("9", 64),
		Height: 2, RevisionCount: 2,
	}}
	base := StateMutation{
		SnapshotID: current.SnapshotID, LogicalMessageID: logicalID, OperationID: "after-delete",
		ExpectedHeads:       append([]string(nil), current.States[0].Heads...),
		ExpectedHeadsDigest: current.States[0].HeadsDigest, ExpectedStateDigest: current.States[0].StateDigest,
		ExpectedHeight: 2, ExpectedRevisionCount: 2, Version: version,
		MailboxIDs: []string{inboxID}, Keywords: []string{"$seen"},
	}
	for _, test := range []struct {
		name   string
		mutate func(*StateMutation)
	}{
		{name: "live resurrection"},
		{name: "repeat tombstone", mutate: func(mutation *StateMutation) { mutation.Tombstone = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			writer := newFakeOfficialWriter(target)
			engine, err := newOfficialEngine(writer, target, func(context.Context) (Snapshot, error) { return current, nil })
			if err != nil {
				t.Fatal(err)
			}
			mutation := base
			if test.mutate != nil {
				test.mutate(&mutation)
			}
			if _, err := engine.AppendState(t.Context(), mutation); !errors.Is(err, ErrConflict) {
				t.Fatalf("AppendState error = %v", err)
			}
			if len(writer.batches) != 0 {
				t.Fatalf("rejected mutation wrote batches %v", writer.batchSizes())
			}
		})
	}
}

func TestOfficialEnginePreflightsCanonicalTombstoneBeforeWrite(t *testing.T) {
	target := testOfficialEngineTarget()
	inboxID, _ := mailboxstate.StandardFolderID(target.RepoDID, "inbox")
	version := "sha256-" + strings.Repeat("4", 64)
	logicalID := "sha256-" + strings.Repeat("5", 64)
	current := testEngineSnapshot(target, "sha256-"+strings.Repeat("6", 64))
	current.Folders = []FolderState{{FolderID: inboxID}}
	current.Messages = []MessageVersion{{RKey: version, LogicalMessageID: logicalID}}
	current.States = []MessageState{{
		LogicalMessageID: logicalID, SnapshotID: current.SnapshotID, Version: version,
		MailboxIDs: []string{inboxID}, Keywords: []string{"$seen"}, DeletePending: true,
		Heads:       []string{"state-" + strings.Repeat("7", 64)},
		HeadsDigest: "sha256-" + strings.Repeat("8", 64), StateDigest: "sha256-" + strings.Repeat("9", 64),
		Height: 2, RevisionCount: 2,
	}}
	base := StateMutation{
		SnapshotID: current.SnapshotID, LogicalMessageID: logicalID, OperationID: "delete",
		ExpectedHeads:       append([]string(nil), current.States[0].Heads...),
		ExpectedHeadsDigest: current.States[0].HeadsDigest, ExpectedStateDigest: current.States[0].StateDigest,
		ExpectedHeight: 2, ExpectedRevisionCount: 2, Version: version,
		MailboxIDs: []string{inboxID}, Keywords: []string{"$seen"}, Tombstone: true,
	}
	for _, test := range []struct {
		name   string
		mutate func(*StateMutation)
	}{
		{name: "changed version", mutate: func(mutation *StateMutation) { mutation.Version = "sha256-" + strings.Repeat("a", 64) }},
		{name: "changed folders", mutate: func(mutation *StateMutation) { mutation.MailboxIDs = nil }},
		{name: "changed keywords", mutate: func(mutation *StateMutation) { mutation.Keywords = nil }},
		{name: "retained delete pending", mutate: func(mutation *StateMutation) { mutation.DeletePending = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			writer := newFakeOfficialWriter(target)
			engine, _ := newOfficialEngine(writer, target, func(context.Context) (Snapshot, error) { return current, nil })
			mutation := base
			test.mutate(&mutation)
			if _, err := engine.AppendState(t.Context(), mutation); !errors.Is(err, ErrConflict) {
				t.Fatalf("AppendState error = %v", err)
			}
			if len(writer.batches) != 0 {
				t.Fatalf("rejected tombstone wrote batches %v", writer.batchSizes())
			}
		})
	}
}

func TestOfficialEngineAppendsCanonicalTombstone(t *testing.T) {
	target := testOfficialEngineTarget()
	inboxID, _ := mailboxstate.StandardFolderID(target.RepoDID, "inbox")
	version := "sha256-" + strings.Repeat("4", 64)
	logicalID := "sha256-" + strings.Repeat("5", 64)
	current := testEngineSnapshot(target, "sha256-"+strings.Repeat("6", 64))
	current.Folders = []FolderState{{FolderID: inboxID}}
	current.Messages = []MessageVersion{{RKey: version, LogicalMessageID: logicalID}}
	current.States = []MessageState{{
		LogicalMessageID: logicalID, SnapshotID: current.SnapshotID, Version: version,
		MailboxIDs: []string{inboxID}, Keywords: []string{"$seen"}, DeletePending: true,
		Heads:       []string{"state-" + strings.Repeat("7", 64)},
		HeadsDigest: "sha256-" + strings.Repeat("8", 64), StateDigest: "sha256-" + strings.Repeat("9", 64),
		Height: 2, RevisionCount: 2,
	}}
	mutation := StateMutation{
		SnapshotID: current.SnapshotID, LogicalMessageID: logicalID, OperationID: "delete",
		ExpectedHeads:       append([]string(nil), current.States[0].Heads...),
		ExpectedHeadsDigest: current.States[0].HeadsDigest, ExpectedStateDigest: current.States[0].StateDigest,
		ExpectedHeight: 2, ExpectedRevisionCount: 2, Version: version,
		MailboxIDs: []string{inboxID}, Keywords: []string{"$seen"}, Tombstone: true,
	}
	final := testEngineSnapshot(target, "sha256-"+strings.Repeat("a", 64))
	final.Folders = current.Folders
	final.Messages = current.Messages
	final.States = []MessageState{{
		LogicalMessageID: logicalID, SnapshotID: final.SnapshotID, Version: version,
		MailboxIDs: []string{inboxID}, Keywords: []string{"$seen"}, Tombstone: true,
		Heads: []string{"state-" + strings.Repeat("b", 64)}, Height: 3, RevisionCount: 3,
	}}
	reads := 0
	writer := newFakeOfficialWriter(target)
	engine, err := newOfficialEngine(writer, target, func(context.Context) (Snapshot, error) {
		reads++
		if reads == 1 {
			return current, nil
		}
		return final, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	state, err := engine.AppendState(t.Context(), mutation)
	if err != nil || !state.Tombstone || state.DeletePending {
		t.Fatalf("state=%+v error=%v", state, err)
	}
	if got := writer.batchSizes(); len(got) != 1 || got[0] != 2 {
		t.Fatalf("canonical tombstone batches=%v", got)
	}
	revision, err := mailboxstate.DecodeRevisionRecord(writer.batches[0][0].Value)
	if err != nil {
		t.Fatal(err)
	}
	if !revision.Tombstone || revision.Version != "" || revision.MailboxIDs != nil || revision.DeletePending != nil || len(revision.Keywords) != 0 {
		t.Fatalf("tombstone revision=%+v", revision)
	}
}

func TestOfficialEngineRejectsMissingCustomFolderBeforeMessageWrite(t *testing.T) {
	target := testOfficialEngineTarget()
	current := testEngineSnapshot(target, "sha256-"+strings.Repeat("6", 64))
	writer := newFakeOfficialWriter(target)
	engine, err := newOfficialEngine(writer, target, func(context.Context) (Snapshot, error) { return current, nil })
	if err != nil {
		t.Fatal(err)
	}
	_, err = engine.Store(t.Context(), StoreInput{
		RecipientDID: target.RepoDID,
		Raw:          []byte("Message-ID: <custom@test>\r\n\r\nbody"),
		Placement: Placement{Folders: []FolderSelection{{
			SourceKey: "jmap-mailbox-1", Name: "Projects",
		}}},
	})
	if !errors.Is(err, mailbox.ErrInvalidRecord) {
		t.Fatalf("Store error = %v", err)
	}
	if got := writer.batchSizes(); len(got) != 1 || got[0] != 14 {
		t.Fatalf("missing custom folder wrote unexpected batches %v", got)
	}
}

func TestOfficialEngineRejectsNewVersionAfterTombstoneBeforeBlobOrMessageWrite(t *testing.T) {
	target := testOfficialEngineTarget()
	inboxID, _ := mailboxstate.StandardFolderID(target.RepoDID, "inbox")
	oldRaw := []byte("Message-ID: <draft@test>\r\nSubject: old\r\n\r\nold")
	newRaw := []byte("Message-ID: <draft@test>\r\nSubject: new\r\n\r\nnew")
	sourceKey := "jmap-message-1"
	oldFingerprint := sourceFingerprint(target.RepoDID, sourceKey, oldRaw)
	newFingerprint := sourceFingerprint(target.RepoDID, sourceKey, newRaw)
	logicalID := mailbox.LogicalMessageID(target.RepoDID, sourceKey, newFingerprint)
	current := testEngineSnapshot(target, "sha256-"+strings.Repeat("6", 64))
	current.Messages = []MessageVersion{{RKey: oldFingerprint, LogicalMessageID: logicalID, Raw: oldRaw}}
	current.States = []MessageState{{
		LogicalMessageID: logicalID, SnapshotID: current.SnapshotID, Version: oldFingerprint,
		MailboxIDs: []string{inboxID}, Tombstone: true,
		Heads: []string{"state-" + strings.Repeat("7", 64)}, Height: 2, RevisionCount: 2,
	}}
	writer := newFakeOfficialWriter(target)
	engine, err := newOfficialEngine(writer, target, func(context.Context) (Snapshot, error) { return current, nil })
	if err != nil {
		t.Fatal(err)
	}
	_, err = engine.Store(t.Context(), StoreInput{
		RecipientDID: target.RepoDID, Raw: newRaw,
		Placement: Placement{SourceKey: sourceKey, Folders: []FolderSelection{{
			SourceKey: "role:inbox", Name: "Inbox", Role: "inbox",
		}}},
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("Store error = %v", err)
	}
	if writer.uploadCalls != 0 {
		t.Fatalf("rejected source version uploaded %d blobs", writer.uploadCalls)
	}
	if got := writer.batchSizes(); len(got) != 1 || got[0] != 14 {
		t.Fatalf("rejected source version wrote unexpected batches %v", got)
	}
}

func TestOfficialEngineRejectsUnpinnedOrMismatchedTarget(t *testing.T) {
	target := testOfficialEngineTarget()
	writer := newFakeOfficialWriter(target)
	wrong := target
	wrong.AuthorityCertificateGeneration = "legacy-v2"
	if _, err := newOfficialEngine(writer, wrong, nil); err == nil {
		t.Fatal("legacy generation was accepted")
	}
	wrong = target
	wrong.SpaceURI += "-other"
	if _, err := newOfficialEngine(writer, wrong, nil); !errors.Is(err, repository.ErrTarget) {
		t.Fatalf("mismatched target error=%v", err)
	}
}

type fakeOfficialWriter struct {
	target      officialspaces.Target
	records     map[string]officialspaces.UnverifiedRecord
	batches     [][]officialspaces.Create
	upload      mailbox.BlobRef
	uploadCalls int
}

func newFakeOfficialWriter(target Target) *fakeOfficialWriter {
	return &fakeOfficialWriter{
		target:  officialspaces.Target{Origin: target.Origin, SpaceURI: target.SpaceURI, RepoDID: target.RepoDID, Epoch: target.Epoch},
		records: make(map[string]officialspaces.UnverifiedRecord),
	}
}

func (*fakeOfficialWriter) TransportID() string {
	return "official-spaces-transport@" + officialspaces.PinnedEpoch
}

func (writer *fakeOfficialWriter) Target() officialspaces.Target { return writer.target }

func (writer *fakeOfficialWriter) UploadMessageBlob(context.Context, []byte) (mailbox.BlobRef, error) {
	writer.uploadCalls++
	return writer.upload, nil
}

func (writer *fakeOfficialWriter) CreateBatch(_ context.Context, creates []officialspaces.Create) ([]officialspaces.CreateResult, error) {
	batch := make([]officialspaces.Create, len(creates))
	copy(batch, creates)
	writer.batches = append(writer.batches, batch)
	results := make([]officialspaces.CreateResult, len(creates))
	for index, create := range creates {
		key := create.Collection + "\x00" + create.RKey
		if _, exists := writer.records[key]; exists {
			return nil, repository.ErrExists
		}
		writer.records[key] = officialspaces.UnverifiedRecord{
			Collection: create.Collection, RKey: create.RKey, Value: append(json.RawMessage(nil), create.Value...),
		}
		results[index] = officialspaces.CreateResult{URI: "at://synthetic/" + create.Collection + "/" + create.RKey}
	}
	return results, nil
}

func (writer *fakeOfficialWriter) InspectRecord(_ context.Context, collection, rkey string) (officialspaces.UnverifiedRecord, error) {
	record, exists := writer.records[collection+"\x00"+rkey]
	if !exists {
		return officialspaces.UnverifiedRecord{}, repository.ErrNotFound
	}
	return record, nil
}

func (writer *fakeOfficialWriter) batchSizes() []int {
	result := make([]int, len(writer.batches))
	for index, batch := range writer.batches {
		result[index] = len(batch)
	}
	return result
}

func testOfficialEngineTarget() Target {
	return Target{
		ProviderID: "official-spaces-transport@" + officialspaces.PinnedEpoch,
		Origin:     "https://spaces.example", SpaceURI: "at://did:plc:aaaaaaaaaaaaaaaaaaaaaaaa/space/email.atmos.mailbox/primary",
		RepoDID: "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb", Epoch: officialspaces.PinnedEpoch,
		AuthorityCertificateSHA256: strings.Repeat("d", 64), AuthorityCertificateGeneration: AuthorityGeneration,
	}
}

func testEngineSnapshot(target Target, snapshotID string) Snapshot {
	snapshot := Snapshot{
		Version: ProtocolVersion, Target: target, Revision: "3jzfcijpj2z2a",
		SnapshotID: snapshotID, ManifestSHA256: "sha256-" + strings.Repeat("e", 64),
	}
	for _, standard := range standardFolders {
		folderID, _ := mailboxstate.StandardFolderID(target.RepoDID, standard.Role)
		snapshot.Folders = append(snapshot.Folders, FolderState{FolderID: folderID, Name: standard.Name, Role: standard.Role})
	}
	return snapshot
}

var _ officialWriter = (*fakeOfficialWriter)(nil)
