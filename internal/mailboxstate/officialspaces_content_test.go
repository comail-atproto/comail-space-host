package mailboxstate

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/comail-atproto/comail-space-host/internal/mailbox"
	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"
)

func TestReadOfficialSpacesRecoverySourceFetchesEachUniqueBlobAndSealsContent(t *testing.T) {
	inventory, blobs := validContentInventory(t)
	client, credentials := newSyntheticAuthenticatedClient(t, inventory, blobs)

	content, err := ReadOfficialSpacesRecoverySource(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	if credentials.acquired != 2 || credentials.closed != 2 || credentials.blobGets != 1 {
		t.Fatalf("acquired=%d closed=%d blobGets=%d", credentials.acquired, credentials.closed, credentials.blobGets)
	}
	if err := content.ValidateSeal(); err != nil {
		t.Fatal(err)
	}
	summary := content.Summary()
	if summary.Target != inventory.target || summary.Revision != inventory.revision || summary.MessageVersions != 2 ||
		summary.UniqueBlobs != 1 || summary.TotalBytes != int64(len(blobs[firstBlobCID(blobs)])) ||
		!validSHA256Identifier(summary.ManifestSHA256) {
		t.Fatalf("summary=%+v", summary)
	}
	if got := content.String(); got != "mailboxstate.ContentVerifiedSource(redacted)" || strings.Contains(got, inventory.target.RepoDID) {
		t.Fatalf("unsafe String=%q", got)
	}

	var sourceKeys []string
	var firstRaw []byte
	var retained ContentVerifiedMessage
	err = content.VisitMessages(context.Background(), func(message ContentVerifiedMessage) error {
		version, raw, err := message.Open()
		if err != nil {
			return err
		}
		if !bytes.Equal(raw, blobs[version.Record.Raw.Ref.Link]) || mailbox.ValidateStoredMessage(inventory.target.RepoDID, version.RKey, version.Record, raw) != nil {
			t.Fatalf("invalid visited message rkey=%q", version.RKey)
		}
		sourceKeys = append(sourceKeys, version.Record.SourceKey)
		if firstRaw == nil {
			retained = message
			firstRaw = raw
			firstRaw[0] ^= 0xff
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	seenSourceKeys := make(map[string]bool, len(sourceKeys))
	for _, sourceKey := range sourceKeys {
		seenSourceKeys[sourceKey] = true
	}
	if len(sourceKeys) != 2 || !seenSourceKeys["synthetic-a"] || !seenSourceKeys["synthetic-b"] {
		t.Fatalf("source keys=%v", sourceKeys)
	}
	if _, _, err := retained.Open(); !errors.Is(err, ErrContentVerification) {
		t.Fatalf("retained visited message remained valid: %v", err)
	}
	if err := content.VisitMessages(context.Background(), func(message ContentVerifiedMessage) error {
		_, raw, openErr := message.Open()
		if openErr != nil || raw[0] == firstRaw[0] {
			t.Fatalf("content copy escaped: error=%v raw=%x", openErr, raw)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	content.Close()
	content.Close()
	if !errors.Is(content.ValidateSeal(), ErrContentVerification) || content.Summary() != (ContentVerificationSummary{}) {
		t.Fatal("closed content capability retained validity")
	}
	if err := content.VisitMessages(context.Background(), func(ContentVerifiedMessage) error { return nil }); !errors.Is(err, ErrContentVerification) {
		t.Fatalf("visit after close error=%v", err)
	}
}

func TestReadOfficialSpacesRecoverySourceRejectsSemanticContentMismatchRedacted(t *testing.T) {
	inventory := validOfficialInventory(t)
	raw := []byte("synthetic non-sensitive RFC 5322 bytes: message")
	blobs := map[string][]byte{}
	secretRKey := ""
	for _, record := range inventory.records {
		if record.Collection != mailbox.MessageCollection {
			continue
		}
		message, err := decodeOfficialMessage(record.Value)
		if err != nil {
			t.Fatal(err)
		}
		blobs[message.Raw.Ref.Link] = raw
		secretRKey = record.RKey
	}
	client, credentials := newSyntheticAuthenticatedClient(t, inventory, blobs)
	content, err := ReadOfficialSpacesRecoverySource(context.Background(), client)
	if content != nil || !errors.Is(err, ErrContentVerification) || err.Error() != ErrContentVerification.Error() || strings.Contains(err.Error(), secretRKey) {
		t.Fatalf("content=%v error=%v", content, err)
	}
	if credentials.acquired != 2 || credentials.closed != 2 {
		t.Fatalf("acquired=%d closed=%d", credentials.acquired, credentials.closed)
	}
}

func TestReadOfficialSpacesRecoverySourceValidatesEverySharedBlobReference(t *testing.T) {
	inventory, blobs := invalidSharedBlobReferenceInventory(t)
	client, credentials := newSyntheticAuthenticatedClient(t, inventory, blobs)
	content, err := ReadOfficialSpacesRecoverySource(context.Background(), client)
	if content != nil || !errors.Is(err, ErrContentVerification) {
		t.Fatalf("content=%v error=%v", content, err)
	}
	if credentials.blobGets != 1 || credentials.acquired != 2 || credentials.closed != 2 {
		t.Fatalf("blobGets=%d acquired=%d closed=%d", credentials.blobGets, credentials.acquired, credentials.closed)
	}
}

func TestReadOfficialSpacesRecoverySourceRejectsCommitDriftAndSupportsEmptyMailbox(t *testing.T) {
	inventory, blobs := validContentInventory(t)
	client, credentials := newSyntheticAuthenticatedClient(t, inventory, blobs)
	drifted := inventory.clone()
	drifted.revision = "3jzfcijpj2z2b"
	privateKey, err := atcrypto.ParsePrivateBytesP256(bytes.Repeat([]byte{0x71}, 32))
	if err != nil {
		t.Fatal(err)
	}
	credentials.after, _ = encodeSyntheticSource(t, drifted, privateKey)
	if content, err := ReadOfficialSpacesRecoverySource(context.Background(), client); content != nil || !errors.Is(err, ErrContentVerification) {
		t.Fatalf("drift content=%v error=%v", content, err)
	}
	if credentials.closed != 2 {
		t.Fatalf("closed=%d", credentials.closed)
	}

	empty := validOfficialInventory(t)
	empty.records = removeSourceCollection(empty.records, mailbox.MessageCollection, len(empty.records))
	empty.records = removeSourceCollection(empty.records, MessageStateRevisionCollection, len(empty.records))
	empty.records = removeSourceCollection(empty.records, MessageStateOperationCollection, len(empty.records))
	emptyClient, emptyCredentials := newSyntheticAuthenticatedClient(t, empty, map[string][]byte{})
	emptyContent, err := ReadOfficialSpacesRecoverySource(context.Background(), emptyClient)
	if err != nil {
		t.Fatal(err)
	}
	defer emptyContent.Close()
	if summary := emptyContent.Summary(); summary.MessageVersions != 0 || summary.UniqueBlobs != 0 || summary.TotalBytes != 0 {
		t.Fatalf("empty summary=%+v", summary)
	}
	if emptyCredentials.acquired != 2 || emptyCredentials.closed != 2 || emptyCredentials.blobGets != 0 {
		t.Fatalf("empty acquired=%d closed=%d gets=%d", emptyCredentials.acquired, emptyCredentials.closed, emptyCredentials.blobGets)
	}
}

func TestContentVerifiedSourceCloseDuringVisitIsRaceSafeAndMutationFailsClosed(t *testing.T) {
	inventory, blobs := validContentInventory(t)
	client, _ := newSyntheticAuthenticatedClient(t, inventory, blobs)
	content, err := ReadOfficialSpacesRecoverySource(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	visitDone := make(chan error, 1)
	visits := 0
	go func() {
		visitDone <- content.VisitMessages(context.Background(), func(message ContentVerifiedMessage) error {
			visits++
			if visits == 1 {
				close(started)
				<-release
			}
			_, _, openErr := message.Open()
			return openErr
		})
	}()
	<-started
	content.Close()
	close(release)
	if visitErr := <-visitDone; visitErr != nil || visits != 2 {
		t.Fatalf("close-during-visit visits=%d error=%v", visits, visitErr)
	}
	if !errors.Is(content.ValidateSeal(), ErrContentVerification) {
		t.Fatal("closed capability remained valid")
	}

	client, _ = newSyntheticAuthenticatedClient(t, inventory, blobs)
	content, err = ReadOfficialSpacesRecoverySource(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range content.blobs {
		raw[0] ^= 0xff
		break
	}
	if !errors.Is(content.ValidateSeal(), ErrContentVerification) || content.Summary() != (ContentVerificationSummary{}) {
		t.Fatal("mutated content capability retained validity")
	}
	content.Close()
}

func TestContentVerifiedSourceVisitHonorsCancellationBetweenMessages(t *testing.T) {
	inventory, blobs := validContentInventory(t)
	client, _ := newSyntheticAuthenticatedClient(t, inventory, blobs)
	content, err := ReadOfficialSpacesRecoverySource(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	defer content.Close()
	ctx, cancel := context.WithCancel(context.Background())
	visits := 0
	err = content.VisitMessages(ctx, func(ContentVerifiedMessage) error {
		visits++
		cancel()
		return nil
	})
	if !errors.Is(err, context.Canceled) || visits != 1 {
		t.Fatalf("error=%v visits=%d", err, visits)
	}
}

func TestReadOfficialSpacesRecoverySourceIncludesSupersededTombstonedHistory(t *testing.T) {
	inventory, blobs := historicalContentInventory(t)
	client, credentials := newSyntheticAuthenticatedClient(t, inventory, blobs)
	content, err := ReadOfficialSpacesRecoverySource(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	defer content.Close()
	if summary := content.Summary(); summary.MessageVersions != 2 || summary.UniqueBlobs != 2 || credentials.blobGets != 2 {
		t.Fatalf("summary=%+v blobGets=%d", summary, credentials.blobGets)
	}
	states := content.MessageStates()
	if len(states) != 1 || !states[0].Tombstone {
		t.Fatalf("states=%+v", states)
	}
	seen := map[string]bool{}
	if err := content.VisitMessages(context.Background(), func(message ContentVerifiedMessage) error {
		version, _, openErr := message.Open()
		seen[version.RKey] = true
		return openErr
	}); err != nil || len(seen) != 2 {
		t.Fatalf("visited=%d error=%v", len(seen), err)
	}
}

func TestPrepareOfficialContentRejectsAggregateBytesBeforeBlobRead(t *testing.T) {
	messages := make([]MessageVersion, 7)
	for index := range messages {
		raw := []byte{byte(index + 1)}
		blobCID, err := (cid.Prefix{Version: 1, Codec: cid.Raw, MhType: multihash.SHA2_256, MhLength: 32}).Sum(raw)
		if err != nil {
			t.Fatal(err)
		}
		messages[index] = MessageVersion{RKey: sourceSHA256ID(string(raw)), Record: mailbox.MessageRecord{
			Raw:  mailbox.BlobRef{Ref: mailbox.CIDLink{Link: blobCID.String()}, Size: mailbox.MaxRawMessageBytes},
			Size: mailbox.MaxRawMessageBytes,
		}}
	}
	if _, _, _, err := prepareOfficialContent(messages); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("aggregate content error=%v", err)
	}
}

func TestReadOfficialSpacesRecoverySourceRejectsDeclaredAggregateBeforeBlobCredential(t *testing.T) {
	inventory := oversizedDeclaredContentInventory(t)
	client, credentials := newSyntheticAuthenticatedClient(t, inventory, map[string][]byte{})
	content, err := ReadOfficialSpacesRecoverySource(context.Background(), client)
	if content != nil || !errors.Is(err, ErrContentVerification) {
		t.Fatalf("content=%v error=%v", content, err)
	}
	if credentials.acquired != 1 || credentials.closed != 1 || credentials.blobGets != 0 {
		t.Fatalf("acquired=%d closed=%d blobGets=%d", credentials.acquired, credentials.closed, credentials.blobGets)
	}
}

func validContentInventory(t *testing.T) (officialSpacesInventory, map[string][]byte) {
	t.Helper()
	inventory := validOfficialInventory(t)
	inventory.records = removeSourceCollection(inventory.records, mailbox.MessageCollection, len(inventory.records))
	inventory.records = removeSourceCollection(inventory.records, MessageStateRevisionCollection, len(inventory.records))
	inventory.records = removeSourceCollection(inventory.records, MessageStateOperationCollection, len(inventory.records))
	raw := []byte("From: sender@example.invalid\r\nTo: member@example.invalid\r\n\r\nsynthetic content\r\n")
	blobCID, err := (cid.Prefix{Version: 1, Codec: cid.Raw, MhType: multihash.SHA2_256, MhLength: 32}).Sum(raw)
	if err != nil {
		t.Fatal(err)
	}
	blob := mailbox.BlobRef{Type: "blob", Ref: mailbox.CIDLink{Link: blobCID.String()}, MIMEType: mailbox.MessageMIMEType, Size: int64(len(raw))}
	for index, sourceKey := range []string{"synthetic-a", "synthetic-b"} {
		pair, err := mailbox.NewMessagePair(mailbox.ImportedMessage{
			RecipientDID: inventory.target.RepoDID, SourceKey: sourceKey, Raw: raw, Mailbox: "INBOX",
			DeliveredAt: time.Unix(int64(10+index), 0).UTC(),
		}, blob)
		if err != nil {
			t.Fatal(err)
		}
		revision := StateRevision{Record: RevisionRecord{
			Type: MessageStateRevisionCollection, LogicalMessageID: pair.Message.LogicalMessageID,
			OperationID: "initial", Parents: []string{}, Revision: 1, Version: pair.RKey,
			MailboxIDs: []string{mustStandardFolderID(t, inventory.target.RepoDID, "inbox")},
			CreatedAt:  time.Unix(int64(20+index), 0).UTC().Format(time.RFC3339Nano),
		}}
		revision.RKey, err = StateRevisionRKey(inventory.target.RepoDID, revision.Record)
		if err != nil {
			t.Fatal(err)
		}
		claim, err := NewOperationClaim(inventory.target.RepoDID, revision)
		if err != nil {
			t.Fatal(err)
		}
		inventory.records = append(inventory.records,
			sourceRecord(t, mailbox.MessageCollection, pair.RKey, pair.Message),
			sourceRecord(t, MessageStateRevisionCollection, revision.RKey, revision.Record),
			sourceRecord(t, MessageStateOperationCollection, claim.RKey, claim.Record),
		)
	}
	return inventory, map[string][]byte{blobCID.String(): raw}
}

func historicalContentInventory(t *testing.T) (officialSpacesInventory, map[string][]byte) {
	t.Helper()
	inventory := validOfficialInventory(t)
	inventory.records = removeSourceCollection(inventory.records, mailbox.MessageCollection, len(inventory.records))
	inventory.records = removeSourceCollection(inventory.records, MessageStateRevisionCollection, len(inventory.records))
	inventory.records = removeSourceCollection(inventory.records, MessageStateOperationCollection, len(inventory.records))

	var pairs []mailbox.MessagePair
	blobs := map[string][]byte{}
	for index, body := range []string{"first version", "second version"} {
		raw := []byte("From: sender@example.invalid\r\nTo: member@example.invalid\r\n\r\n" + body + "\r\n")
		blobCID, err := (cid.Prefix{Version: 1, Codec: cid.Raw, MhType: multihash.SHA2_256, MhLength: 32}).Sum(raw)
		if err != nil {
			t.Fatal(err)
		}
		pair, err := mailbox.NewMessagePair(mailbox.ImportedMessage{
			RecipientDID: inventory.target.RepoDID, SourceKey: "synthetic-draft", Raw: raw, Mailbox: "Drafts",
			DeliveredAt: time.Unix(int64(30+index), 0).UTC(),
		}, mailbox.BlobRef{
			Type: "blob", Ref: mailbox.CIDLink{Link: blobCID.String()},
			MIMEType: mailbox.MessageMIMEType, Size: int64(len(raw)),
		})
		if err != nil {
			t.Fatal(err)
		}
		pairs = append(pairs, pair)
		blobs[blobCID.String()] = raw
		inventory.records = append(inventory.records, sourceRecord(t, mailbox.MessageCollection, pair.RKey, pair.Message))
	}
	if pairs[0].Message.LogicalMessageID != pairs[1].Message.LogicalMessageID {
		t.Fatal("historical versions do not share a logical identity")
	}

	revisions := []StateRevision{{Record: RevisionRecord{
		Type: MessageStateRevisionCollection, LogicalMessageID: pairs[0].Message.LogicalMessageID,
		OperationID: "create", Parents: []string{}, Revision: 1, Version: pairs[0].RKey,
		MailboxIDs: []string{mustStandardFolderID(t, inventory.target.RepoDID, "drafts")},
		CreatedAt:  time.Unix(40, 0).UTC().Format(time.RFC3339Nano),
	}}}
	var err error
	revisions[0].RKey, err = StateRevisionRKey(inventory.target.RepoDID, revisions[0].Record)
	if err != nil {
		t.Fatal(err)
	}
	revisions = append(revisions, StateRevision{Record: RevisionRecord{
		Type: MessageStateRevisionCollection, LogicalMessageID: pairs[0].Message.LogicalMessageID,
		OperationID: "edit", Parents: []string{revisions[0].RKey}, Revision: 2,
		Version: pairs[1].RKey, CreatedAt: time.Unix(41, 0).UTC().Format(time.RFC3339Nano),
	}})
	revisions[1].RKey, err = StateRevisionRKey(inventory.target.RepoDID, revisions[1].Record)
	if err != nil {
		t.Fatal(err)
	}
	revisions = append(revisions, StateRevision{Record: RevisionRecord{
		Type: MessageStateRevisionCollection, LogicalMessageID: pairs[0].Message.LogicalMessageID,
		OperationID: "delete", Parents: []string{revisions[1].RKey}, Revision: 3,
		Tombstone: true, CreatedAt: time.Unix(42, 0).UTC().Format(time.RFC3339Nano),
	}})
	revisions[2].RKey, err = StateRevisionRKey(inventory.target.RepoDID, revisions[2].Record)
	if err != nil {
		t.Fatal(err)
	}
	for _, revision := range revisions {
		claim, err := NewOperationClaim(inventory.target.RepoDID, revision)
		if err != nil {
			t.Fatal(err)
		}
		inventory.records = append(inventory.records,
			sourceRecord(t, MessageStateRevisionCollection, revision.RKey, revision.Record),
			sourceRecord(t, MessageStateOperationCollection, claim.RKey, claim.Record),
		)
	}
	return inventory, blobs
}

func invalidSharedBlobReferenceInventory(t *testing.T) (officialSpacesInventory, map[string][]byte) {
	t.Helper()
	inventory, blobs := validContentInventory(t)
	messageIndex := -1
	oldRKey := ""
	for index, record := range inventory.records {
		if record.Collection == mailbox.MessageCollection && record.RKey > oldRKey {
			messageIndex = index
			oldRKey = record.RKey
		}
	}
	if messageIndex < 0 {
		t.Fatal("missing shared message record")
	}
	message, err := decodeOfficialMessage(inventory.records[messageIndex].Value)
	if err != nil {
		t.Fatal(err)
	}
	message.SourceKey += "-tampered"
	message.LogicalMessageID = mailbox.LogicalMessageID(inventory.target.RepoDID, message.SourceKey, oldRKey)
	inventory.records[messageIndex] = sourceRecord(t, mailbox.MessageCollection, oldRKey, message)

	var oldRevisionRKey string
	var replacement StateRevision
	for index, record := range inventory.records {
		if record.Collection != MessageStateRevisionCollection {
			continue
		}
		revision, err := decodeOfficialMessageRevision(record.Value)
		if err != nil {
			t.Fatal(err)
		}
		if revision.Version != oldRKey {
			continue
		}
		oldRevisionRKey = record.RKey
		revision.LogicalMessageID = message.LogicalMessageID
		replacement.Record = revision
		replacement.RKey, err = StateRevisionRKey(inventory.target.RepoDID, revision)
		if err != nil {
			t.Fatal(err)
		}
		inventory.records[index] = sourceRecord(t, MessageStateRevisionCollection, replacement.RKey, replacement.Record)
		break
	}
	if oldRevisionRKey == "" {
		t.Fatal("missing shared message revision")
	}
	for index, record := range inventory.records {
		if record.Collection != MessageStateOperationCollection {
			continue
		}
		claim, err := decodeOfficialMessageClaim(record.Value)
		if err != nil {
			t.Fatal(err)
		}
		if claim.RevisionRKey != oldRevisionRKey {
			continue
		}
		replacementClaim, err := NewOperationClaim(inventory.target.RepoDID, replacement)
		if err != nil {
			t.Fatal(err)
		}
		inventory.records[index] = sourceRecord(t, MessageStateOperationCollection, replacementClaim.RKey, replacementClaim.Record)
		return inventory, blobs
	}
	t.Fatal("missing shared message operation claim")
	return officialSpacesInventory{}, nil
}

func oversizedDeclaredContentInventory(t *testing.T) officialSpacesInventory {
	t.Helper()
	inventory := validOfficialInventory(t)
	inventory.records = removeSourceCollection(inventory.records, mailbox.MessageCollection, len(inventory.records))
	inventory.records = removeSourceCollection(inventory.records, MessageStateRevisionCollection, len(inventory.records))
	inventory.records = removeSourceCollection(inventory.records, MessageStateOperationCollection, len(inventory.records))
	for index := 0; index < 7; index++ {
		raw := []byte{byte(index + 1)}
		blobCID, err := (cid.Prefix{Version: 1, Codec: cid.Raw, MhType: multihash.SHA2_256, MhLength: 32}).Sum(raw)
		if err != nil {
			t.Fatal(err)
		}
		pair, err := mailbox.NewMessagePair(mailbox.ImportedMessage{
			RecipientDID: inventory.target.RepoDID, SourceKey: string(rune('a' + index)), Raw: raw, Mailbox: "INBOX",
			DeliveredAt: time.Unix(int64(50+index), 0).UTC(),
		}, mailbox.BlobRef{
			Type: "blob", Ref: mailbox.CIDLink{Link: blobCID.String()},
			MIMEType: mailbox.MessageMIMEType, Size: int64(len(raw)),
		})
		if err != nil {
			t.Fatal(err)
		}
		pair.Message.Size = mailbox.MaxRawMessageBytes
		pair.Message.Raw.Size = mailbox.MaxRawMessageBytes
		revision := StateRevision{Record: RevisionRecord{
			Type: MessageStateRevisionCollection, LogicalMessageID: pair.Message.LogicalMessageID,
			OperationID: "initial", Parents: []string{}, Revision: 1, Version: pair.RKey,
			MailboxIDs: []string{mustStandardFolderID(t, inventory.target.RepoDID, "inbox")},
			CreatedAt:  time.Unix(int64(60+index), 0).UTC().Format(time.RFC3339Nano),
		}}
		revision.RKey, err = StateRevisionRKey(inventory.target.RepoDID, revision.Record)
		if err != nil {
			t.Fatal(err)
		}
		claim, err := NewOperationClaim(inventory.target.RepoDID, revision)
		if err != nil {
			t.Fatal(err)
		}
		inventory.records = append(inventory.records,
			sourceRecord(t, mailbox.MessageCollection, pair.RKey, pair.Message),
			sourceRecord(t, MessageStateRevisionCollection, revision.RKey, revision.Record),
			sourceRecord(t, MessageStateOperationCollection, claim.RKey, claim.Record),
		)
	}
	return inventory
}

func firstBlobCID(blobs map[string][]byte) string {
	for blobCID := range blobs {
		return blobCID
	}
	return ""
}
