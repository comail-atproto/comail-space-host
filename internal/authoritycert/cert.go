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
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/comail-atproto/comail-space-host/internal/mailbox"
	"github.com/comail-atproto/comail-space-host/internal/mailboxstate"
	"github.com/comail-atproto/comail-space-host/internal/projection"
	"github.com/comail-atproto/comail-space-host/internal/repository"
)

type Options struct {
	RecipientDID string
	SpaceKey     string
	RunID        string
	WorkDir      string
	Now          time.Time
}

type Checks struct {
	ByteExactReadback        bool `json:"byteExactReadback"`
	AtomicMessageState       bool `json:"atomicMessageState"`
	ProviderCASConflict      bool `json:"providerCasConflict"`
	IdempotentStateRetry     bool `json:"idempotentStateRetry"`
	MailboxMove              bool `json:"mailboxMove"`
	SourceVersionReplacement bool `json:"sourceVersionReplacement"`
	RebuildBeforeDelete      bool `json:"rebuildBeforeDelete"`
	TombstoneRecovery        bool `json:"tombstoneRecovery"`
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

// LoadEvidence accepts only an owner-only, fully passing v2 report from the
// exact provider epoch the agent will serve. Certification deliberately runs
// in a disposable space; the operational target is bound separately by the
// agent protocol and Comail admission configuration. The evidence digest is
// what the Comail side pins during authority admission.
func LoadEvidence(path, providerID string, target repository.Target) (string, error) {
	if !filepath.IsAbs(path) || path == string(filepath.Separator) || providerID == "" {
		return "", errors.New("authority certification: exact evidence path and provider are required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o177 != 0 {
		return "", errors.New("authority certification: evidence must be an owner-only regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	opened, statErr := file.Stat()
	if statErr != nil || !opened.Mode().IsRegular() || opened.Mode().Perm()&0o177 != 0 || !os.SameFile(info, opened) {
		_ = file.Close()
		return "", errors.New("authority certification: evidence changed or became unsafe while opening")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, 64*1024+1))
	closeErr := file.Close()
	if readErr != nil {
		return "", readErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if len(data) == 0 || len(data) > 64*1024 {
		return "", errors.New("authority certification: evidence size is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var report Report
	if err := decoder.Decode(&report); err != nil {
		return "", errors.New("authority certification: invalid evidence")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return "", errors.New("authority certification: trailing evidence data")
	}
	if target.ValidateFor(target.RepoDID) != nil || report.Version != 2 || !report.Passed || !allChecks(report.Checks) ||
		report.ProviderID != providerID || report.ProviderEpoch != target.Epoch || report.TargetSHA256 == "" ||
		!report.Capabilities.AtomicApplyWrites || !report.Capabilities.CompareAndSwap || !report.Capabilities.ReferencedBlobs {
		return "", errors.New("authority certification: evidence does not bind the exact certified provider epoch")
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// Run requires a fresh dedicated space and writes only one synthetic message.
// The report contains no DID, space URI, message bytes, or credential material.
func Run(ctx context.Context, repo repository.Repository, options Options) (Report, error) {
	report := Report{Version: 2}
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
	sourceKey := "authority-cert-source:" + options.RunID
	raw := []byte("From: sender@example.test\r\nTo: mailbox@example.test\r\nSubject: Comail authority certification\r\nMessage-ID: <" + options.RunID + "@example.test>\r\n\r\nSynthetic certification message.\r\n")
	blob, err := repo.UploadBlob(ctx, target, raw, mailbox.MessageMIMEType)
	if err != nil {
		return report, fmt.Errorf("authority certification: upload synthetic message: %w", err)
	}
	pair, err := mailbox.NewMessagePair(mailbox.ImportedMessage{
		RecipientDID: options.RecipientDID, SourceKey: sourceKey,
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

	// Prove the compose/edit primitive: a stable source identity may advance to
	// new immutable bytes only by atomically creating the new pair and
	// CID-guarding the tombstone of the one prior live version.
	priorState, err := repo.GetRecord(ctx, target, mailbox.MessageStateCollection, pair.RKey)
	if err != nil {
		return report, fmt.Errorf("authority certification: read source version state: %w", err)
	}
	editedRaw := append(append([]byte(nil), raw...), []byte("Edited synthetic version.\r\n")...)
	editedBlob, err := repo.UploadBlob(ctx, target, editedRaw, mailbox.MessageMIMEType)
	if err != nil {
		return report, fmt.Errorf("authority certification: upload edited source version: %w", err)
	}
	editedPair, err := mailbox.NewMessagePair(mailbox.ImportedMessage{
		RecipientDID: options.RecipientDID, SourceKey: sourceKey,
		Raw: editedRaw, Mailbox: "Archive", Keywords: append([]string(nil), moved.Keywords...),
		DeliveredAt: options.Now.Add(6 * time.Second),
	}, editedBlob)
	if err != nil {
		return report, err
	}
	priorTombstone := moved
	priorTombstone.Tombstone = true
	priorTombstone.DeletePending = false
	priorTombstone.Revision++
	priorTombstone.UpdatedAt = options.Now.Add(7 * time.Second).Format(time.RFC3339Nano)
	priorTombstone.LastOperation = options.RunID + ":source-version"
	if _, err := repo.ApplyWrites(ctx, target, []repository.Write{
		{Action: repository.Create, Collection: mailbox.MessageCollection, RKey: editedPair.RKey, Value: editedPair.Message},
		{Action: repository.Create, Collection: mailbox.MessageStateCollection, RKey: editedPair.RKey, Value: editedPair.State},
		{Action: repository.Update, Collection: mailbox.MessageStateCollection, RKey: pair.RKey, Value: priorTombstone, SwapCID: priorState.CID},
	}); err != nil {
		return report, fmt.Errorf("authority certification: atomic source version replacement: %w", err)
	}
	storedPrior, priorErr := repo.GetRecord(ctx, target, mailbox.MessageStateCollection, pair.RKey)
	storedEdited, editedErr := repo.GetRecord(ctx, target, mailbox.MessageStateCollection, editedPair.RKey)
	var verifiedPrior, verifiedEdited mailbox.MessageStateRecord
	if priorErr != nil || editedErr != nil || json.Unmarshal(storedPrior.Value, &verifiedPrior) != nil ||
		json.Unmarshal(storedEdited.Value, &verifiedEdited) != nil || !verifiedPrior.Tombstone || verifiedEdited.Tombstone {
		return report, errors.New("authority certification: source version replacement did not leave exactly one live version")
	}
	storedEditedMessage, err := repo.GetRecord(ctx, target, mailbox.MessageCollection, editedPair.RKey)
	if err != nil {
		return report, errors.New("authority certification: edited source version readback failed")
	}
	var editedMessage mailbox.MessageRecord
	if json.Unmarshal(storedEditedMessage.Value, &editedMessage) != nil || editedMessage.SourceKey != sourceKey {
		return report, mailbox.ErrIntegrity
	}
	editedReadback, err := repo.GetBlob(ctx, target, editedMessage.Raw.Ref.Link)
	if err != nil || !bytes.Equal(editedReadback, editedRaw) || mailbox.ValidateStoredMessage(options.RecipientDID, editedPair.RKey, editedMessage, editedReadback) != nil {
		return report, mailbox.ErrIntegrity
	}
	report.Checks.SourceVersionReplacement = true

	before, err := projection.Rebuild(ctx, repo, target, filepath.Join(options.WorkDir, "before-delete.sqlite"))
	if err != nil || !before.Passed() || before.Messages != 2 || before.States != 2 || before.Tombstones != 1 {
		return report, errors.New("authority certification: rebuild before tombstone failed")
	}
	report.BeforeDelete = summarize(before)
	report.Checks.RebuildBeforeDelete = true
	deleted, err := mailboxstate.Apply(ctx, repo, target, mailboxstate.Mutation{
		MessageRKey: editedPair.RKey, ExpectedRevision: editedPair.State.Revision, OperationID: options.RunID + ":delete", Operation: mailboxstate.Tombstone, Now: options.Now.Add(8 * time.Second),
	})
	if err != nil || !deleted.Tombstone {
		return report, errors.New("authority certification: tombstone failed")
	}
	after, err := projection.Rebuild(ctx, repo, target, filepath.Join(options.WorkDir, "after-delete.sqlite"))
	if err != nil || !after.Passed() || after.Messages != 2 || after.States != 2 || after.Tombstones != 2 {
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
		checks.IdempotentStateRetry, checks.MailboxMove, checks.SourceVersionReplacement,
		checks.RebuildBeforeDelete, checks.TombstoneRecovery,
	}
	for _, value := range values {
		if !value {
			return false
		}
	}
	return true
}
