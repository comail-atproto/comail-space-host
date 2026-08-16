// Package authoritycert runs a destructive synthetic conformance proof in a
// newly provisioned, dedicated mailbox space. It never targets a real mailbox.
package authoritycert

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/comail-atproto/comail-pds-lab/internal/mailbox"
	"github.com/comail-atproto/comail-pds-lab/internal/mailboxstate"
	"github.com/comail-atproto/comail-pds-lab/internal/projection"
	"github.com/comail-atproto/comail-pds-lab/internal/repository"
)

type Options struct {
	RecipientDID string
	SpaceKey     string
	RunID        string
	WorkDir      string
	Now          time.Time
}

type Checks struct {
	ByteExactReadback    bool `json:"byteExactReadback"`
	AtomicMessageState   bool `json:"atomicMessageState"`
	ProviderCASConflict  bool `json:"providerCasConflict"`
	IdempotentStateRetry bool `json:"idempotentStateRetry"`
	MailboxMove          bool `json:"mailboxMove"`
	RebuildBeforeDelete  bool `json:"rebuildBeforeDelete"`
	TombstoneRecovery    bool `json:"tombstoneRecovery"`
}

type ProjectionSummary struct {
	Folders        int    `json:"folders"`
	Messages       int    `json:"messages"`
	States         int    `json:"states"`
	Tombstones     int    `json:"tombstones"`
	TotalBytes     int64  `json:"totalBytes"`
	ManifestSHA256 string `json:"manifestSha256"`
}

type Report struct {
	Version       int                     `json:"version"`
	ProviderID    string                  `json:"providerId"`
	ProviderEpoch string                  `json:"providerEpoch"`
	TargetSHA256  string                  `json:"targetSha256"`
	Capabilities  repository.Capabilities `json:"capabilities"`
	Checks        Checks                  `json:"checks"`
	BeforeDelete  ProjectionSummary       `json:"beforeDelete"`
	AfterDelete   ProjectionSummary       `json:"afterDelete"`
	Passed        bool                    `json:"passed"`
}

// Run requires a fresh dedicated space and writes only one synthetic message.
// The report contains no DID, space URI, message bytes, or credential material.
func Run(ctx context.Context, repo repository.Repository, options Options) (Report, error) {
	report := Report{Version: 1}
	if repo == nil || !validOptions(options) {
		return report, errors.New("authority certification: invalid exact target options")
	}
	capabilities, err := repo.Capabilities(ctx)
	if err != nil {
		return report, fmt.Errorf("authority certification: capabilities: %w", err)
	}
	report.ProviderID = repo.ProviderID()
	report.Capabilities = capabilities
	if !capabilities.AtomicApplyWrites || !capabilities.CompareAndSwap || !capabilities.ReferencedBlobs {
		return report, repository.ErrUnsupported
	}
	target, err := repo.EnsureMailbox(ctx, options.RecipientDID, options.SpaceKey)
	if err != nil {
		return report, fmt.Errorf("authority certification: ensure dedicated mailbox: %w", err)
	}
	if err := target.ValidateFor(options.RecipientDID); err != nil {
		return report, err
	}
	report.ProviderEpoch = target.Epoch
	report.TargetSHA256 = targetHash(target)
	for _, collection := range []string{mailbox.FolderCollection, mailbox.MessageCollection, mailbox.MessageStateCollection} {
		records, err := repo.ListRecords(ctx, target, collection)
		if err != nil {
			return report, fmt.Errorf("authority certification: inventory fresh space: %w", err)
		}
		if len(records) != 0 {
			return report, errors.New("authority certification: dedicated space is not empty")
		}
	}
	if err := os.Mkdir(options.WorkDir, 0o700); err != nil {
		return report, fmt.Errorf("authority certification: create work directory: %w", err)
	}

	inbox := mailbox.NewFolder("INBOX", "inbox", mailbox.StableUIDValidity(options.RecipientDID, "INBOX"))
	archive := mailbox.NewFolder("Archive", "archive", mailbox.StableUIDValidity(options.RecipientDID, "Archive"))
	if _, err := repo.ApplyWrites(ctx, target, []repository.Write{
		{Action: repository.Create, Collection: mailbox.FolderCollection, RKey: inbox.RKey, Value: inbox.Record},
		{Action: repository.Create, Collection: mailbox.FolderCollection, RKey: archive.RKey, Value: archive.Record},
	}); err != nil {
		return report, fmt.Errorf("authority certification: create folders: %w", err)
	}
	raw := []byte("From: sender@example.test\r\nTo: mailbox@example.test\r\nSubject: Comail authority certification\r\nMessage-ID: <" + options.RunID + "@example.test>\r\n\r\nSynthetic certification message.\r\n")
	blob, err := repo.UploadBlob(ctx, target, raw, mailbox.MessageMIMEType)
	if err != nil {
		return report, fmt.Errorf("authority certification: upload synthetic message: %w", err)
	}
	pair, err := mailbox.NewMessagePair(mailbox.ImportedMessage{
		RecipientDID: options.RecipientDID, SourceKey: "authority-cert-v1:" + options.RunID,
		Raw: raw, Mailbox: "INBOX", DeliveredAt: options.Now,
	}, blob)
	if err != nil {
		return report, err
	}
	if _, err := repo.ApplyWrites(ctx, target, []repository.Write{
		{Action: repository.Create, Collection: mailbox.MessageCollection, RKey: pair.RKey, Value: pair.Message},
		{Action: repository.Create, Collection: mailbox.MessageStateCollection, RKey: pair.RKey, Value: pair.State},
	}); err != nil {
		return report, fmt.Errorf("authority certification: atomic message/state create: %w", err)
	}
	messageStored, messageErr := repo.GetRecord(ctx, target, mailbox.MessageCollection, pair.RKey)
	stateStored, stateErr := repo.GetRecord(ctx, target, mailbox.MessageStateCollection, pair.RKey)
	if messageErr != nil || stateErr != nil {
		return report, errors.New("authority certification: atomic message/state readback failed")
	}
	var message mailbox.MessageRecord
	if json.Unmarshal(messageStored.Value, &message) != nil {
		return report, mailbox.ErrIntegrity
	}
	readback, err := repo.GetBlob(ctx, target, message.Raw.Ref.Link)
	if err != nil || !bytes.Equal(readback, raw) || mailbox.ValidateStoredMessage(options.RecipientDID, pair.RKey, message, readback) != nil {
		return report, mailbox.ErrIntegrity
	}
	report.Checks.ByteExactReadback = true
	report.Checks.AtomicMessageState = true

	var base mailbox.MessageStateRecord
	if json.Unmarshal(stateStored.Value, &base) != nil || base.Revision != 1 {
		return report, mailbox.ErrIntegrity
	}
	winner := base
	winner.Keywords = []string{"$seen"}
	winner.Revision = 2
	winner.UpdatedAt = options.Now.Add(time.Second).Format(time.RFC3339Nano)
	winner.LastOperation = options.RunID + ":cas-winner"
	if _, err := repo.PutRecordCAS(ctx, target, mailbox.MessageStateCollection, pair.RKey, winner, stateStored.CID); err != nil {
		return report, fmt.Errorf("authority certification: winning CAS: %w", err)
	}
	loser := base
	loser.Keywords = []string{"$flagged"}
	loser.Revision = 2
	loser.UpdatedAt = options.Now.Add(2 * time.Second).Format(time.RFC3339Nano)
	loser.LastOperation = options.RunID + ":cas-loser"
	if _, err := repo.PutRecordCAS(ctx, target, mailbox.MessageStateCollection, pair.RKey, loser, stateStored.CID); !errors.Is(err, repository.ErrConflict) {
		return report, errors.New("authority certification: provider accepted a stale CAS")
	}
	report.Checks.ProviderCASConflict = true

	flagged, err := mailboxstate.Apply(ctx, repo, target, mailboxstate.Mutation{
		MessageRKey: pair.RKey, ExpectedRevision: 2, OperationID: options.RunID + ":flag", Operation: mailboxstate.Flag, Now: options.Now.Add(3 * time.Second),
	})
	if err != nil {
		return report, err
	}
	replayed, err := mailboxstate.Apply(ctx, repo, target, mailboxstate.Mutation{
		MessageRKey: pair.RKey, ExpectedRevision: 2, OperationID: options.RunID + ":flag", Operation: mailboxstate.Flag, Now: options.Now.Add(4 * time.Second),
	})
	if err != nil || replayed.Revision != flagged.Revision || replayed.UpdatedAt != flagged.UpdatedAt {
		return report, errors.New("authority certification: state retry was not idempotent")
	}
	report.Checks.IdempotentStateRetry = true
	moved, err := mailboxstate.Apply(ctx, repo, target, mailboxstate.Mutation{
		MessageRKey: pair.RKey, ExpectedRevision: flagged.Revision, OperationID: options.RunID + ":move", Operation: mailboxstate.Move, Mailbox: "Archive", Now: options.Now.Add(5 * time.Second),
	})
	if err != nil || len(moved.MailboxIDs) != 1 || moved.MailboxIDs[0] != archive.RKey {
		return report, errors.New("authority certification: mailbox move failed")
	}
	report.Checks.MailboxMove = true

	before, err := projection.Rebuild(ctx, repo, target, filepath.Join(options.WorkDir, "before-delete.sqlite"))
	if err != nil || !before.Passed() || before.Messages != 1 || before.States != 1 || before.Tombstones != 0 {
		return report, errors.New("authority certification: rebuild before tombstone failed")
	}
	report.BeforeDelete = summarize(before)
	report.Checks.RebuildBeforeDelete = true
	deleted, err := mailboxstate.Apply(ctx, repo, target, mailboxstate.Mutation{
		MessageRKey: pair.RKey, ExpectedRevision: moved.Revision, OperationID: options.RunID + ":delete", Operation: mailboxstate.Tombstone, Now: options.Now.Add(6 * time.Second),
	})
	if err != nil || !deleted.Tombstone {
		return report, errors.New("authority certification: tombstone failed")
	}
	after, err := projection.Rebuild(ctx, repo, target, filepath.Join(options.WorkDir, "after-delete.sqlite"))
	if err != nil || !after.Passed() || after.Messages != 1 || after.States != 1 || after.Tombstones != 1 {
		return report, errors.New("authority certification: rebuild after tombstone failed")
	}
	report.AfterDelete = summarize(after)
	report.Checks.TombstoneRecovery = true
	report.Passed = allChecks(report.Checks)
	return report, nil
}

func validOptions(options Options) bool {
	return strings.HasPrefix(options.RecipientDID, "did:") && !strings.ContainsAny(options.RecipientDID, "/?# \t\r\n") &&
		options.SpaceKey != "" && len(options.SpaceKey) <= 128 && !strings.ContainsAny(options.SpaceKey, "/?# \t\r\n") &&
		options.RunID != "" && len(options.RunID) <= 96 && !strings.ContainsAny(options.RunID, " \t\r\n\x00") &&
		filepath.IsAbs(options.WorkDir) && options.WorkDir != string(filepath.Separator) && !options.Now.IsZero()
}

func targetHash(target repository.Target) string {
	encoded, _ := json.Marshal(target)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func summarize(report projection.Report) ProjectionSummary {
	return ProjectionSummary{
		Folders: report.Folders, Messages: report.Messages, States: report.States,
		Tombstones: report.Tombstones, TotalBytes: report.TotalBytes, ManifestSHA256: report.ManifestSHA256,
	}
}

func allChecks(checks Checks) bool {
	values := []bool{
		checks.ByteExactReadback, checks.AtomicMessageState, checks.ProviderCASConflict,
		checks.IdempotentStateRetry, checks.MailboxMove, checks.RebuildBeforeDelete, checks.TombstoneRecovery,
	}
	for _, value := range values {
		if !value {
			return false
		}
	}
	return true
}
