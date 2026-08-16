package migrate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"

	"github.com/comail-atproto/comail-pds-lab/internal/mailbox"
	"github.com/comail-atproto/comail-pds-lab/internal/repository"
	"github.com/comail-atproto/comail-pds-lab/internal/sqliteimport"
)

type Options struct {
	RecipientDID string
	SpaceKey     string
	Commit       bool
}

type Mismatch struct {
	Kind   string `json:"kind"`
	Key    string `json:"key"`
	Detail string `json:"detail"`
}

type Verification struct {
	SourceMessages      int        `json:"sourceMessages"`
	DestinationMessages int        `json:"destinationMessages"`
	VerifiedMessages    int        `json:"verifiedMessages"`
	SourceFolders       int        `json:"sourceFolders"`
	DestinationFolders  int        `json:"destinationFolders"`
	VerifiedFolders     int        `json:"verifiedFolders"`
	Mismatches          []Mismatch `json:"mismatches,omitempty"`
}

func (v Verification) Passed() bool {
	return len(v.Mismatches) == 0 &&
		v.SourceMessages == v.DestinationMessages &&
		v.SourceMessages == v.VerifiedMessages &&
		v.SourceFolders == v.DestinationFolders &&
		v.SourceFolders == v.VerifiedFolders
}

type Report struct {
	Version          int                     `json:"version"`
	DryRun           bool                    `json:"dryRun"`
	Provider         string                  `json:"provider"`
	Capabilities     repository.Capabilities `json:"capabilities"`
	Target           repository.Target       `json:"target,omitempty"`
	SourceFolders    int                     `json:"sourceFolders"`
	SourceMessages   int                     `json:"sourceMessages"`
	SourceBytes      int64                   `json:"sourceBytes"`
	ExpungedSkipped  int                     `json:"expungedSkipped"`
	OversizeBlocked  int                     `json:"oversizeBlocked"`
	CreatedFolders   int                     `json:"createdFolders"`
	ExistingFolders  int                     `json:"existingFolders"`
	CreatedMessages  int                     `json:"createdMessages"`
	ExistingMessages int                     `json:"existingMessages"`
	Fingerprints     []string                `json:"fingerprints"`
	Verification     Verification            `json:"verification"`
}

type SourceSnapshot interface {
	Inspect(context.Context, string, string) (sqliteimport.Inventory, error)
	Folders(context.Context, sqliteimport.Space) ([]sqliteimport.SourceFolder, error)
	Stream(context.Context, sqliteimport.Space, func(sqliteimport.SourceMessage) error) error
}

func Run(ctx context.Context, snapshot SourceSnapshot, repo repository.Repository, opts Options) (Report, error) {
	report := Report{Version: 1, DryRun: !opts.Commit, Fingerprints: []string{}}
	if snapshot == nil || repo == nil {
		return report, errors.New("migrate: snapshot and repository are required")
	}
	report.Provider = repo.ProviderID()
	capabilities, err := repo.Capabilities(ctx)
	if err != nil {
		return report, fmt.Errorf("migrate: read provider capabilities: %w", err)
	}
	report.Capabilities = capabilities
	inv, err := snapshot.Inspect(ctx, opts.RecipientDID, opts.SpaceKey)
	if err != nil {
		return report, err
	}
	report.SourceFolders = inv.Folders
	report.SourceMessages = inv.LiveMessages
	report.SourceBytes = inv.LiveBytes
	report.ExpungedSkipped = inv.ExpungedMessages
	report.OversizeBlocked = inv.OversizeMessages
	if inv.OversizeMessages > 0 {
		return report, fmt.Errorf("%w: snapshot contains %d oversized messages", mailbox.ErrMessageTooLarge, inv.OversizeMessages)
	}
	if !opts.Commit {
		err := snapshot.Stream(ctx, inv.Space, func(src sqliteimport.SourceMessage) error {
			report.Fingerprints = append(report.Fingerprints, mailbox.ImportedFingerprint(src.Imported))
			return nil
		})
		sort.Strings(report.Fingerprints)
		return report, err
	}
	if !capabilities.AtomicApplyWrites || !capabilities.CompareAndSwap || !capabilities.ReferencedBlobs {
		return report, fmt.Errorf("%w: provider lacks an authority-critical capability", repository.ErrUnsupported)
	}
	target, err := repo.EnsureMailbox(ctx, opts.RecipientDID, opts.SpaceKey)
	if err != nil {
		return report, fmt.Errorf("migrate: ensure mailbox: %w", err)
	}
	if err := target.ValidateFor(opts.RecipientDID); err != nil {
		return report, fmt.Errorf("migrate: target binding: %w", err)
	}
	report.Target = target
	folders, err := snapshot.Folders(ctx, inv.Space)
	if err != nil {
		return report, err
	}
	for _, folder := range folders {
		existing, err := repo.GetRecord(ctx, target, mailbox.FolderCollection, folder.Folder.RKey)
		switch {
		case err == nil:
			if err := verifyFolderRecord(existing, folder.Folder.Record); err != nil {
				return report, err
			}
			report.ExistingFolders++
		case errors.Is(err, repository.ErrNotFound):
			_, createErr := repo.ApplyWrites(ctx, target, []repository.Write{{
				Action: repository.Create, Collection: mailbox.FolderCollection,
				RKey: folder.Folder.RKey, Value: folder.Folder.Record,
			}})
			if createErr != nil {
				if errors.Is(createErr, repository.ErrExists) {
					existing, getErr := repo.GetRecord(ctx, target, mailbox.FolderCollection, folder.Folder.RKey)
					if getErr != nil {
						return report, errors.Join(createErr, getErr)
					}
					if err := verifyFolderRecord(existing, folder.Folder.Record); err != nil {
						return report, err
					}
					report.ExistingFolders++
					continue
				}
				return report, fmt.Errorf("migrate: create folder record: %w", createErr)
			}
			report.CreatedFolders++
		default:
			return report, fmt.Errorf("migrate: inspect folder record: %w", err)
		}
	}
	err = snapshot.Stream(ctx, inv.Space, func(src sqliteimport.SourceMessage) error {
		fingerprint := mailbox.ImportedFingerprint(src.Imported)
		report.Fingerprints = append(report.Fingerprints, fingerprint)
		existing, getErr := repo.GetRecord(ctx, target, mailbox.MessageCollection, fingerprint)
		if getErr == nil {
			if err := verifyExistingMessage(ctx, repo, target, src.Imported, existing); err != nil {
				return err
			}
			report.ExistingMessages++
			return nil
		}
		if !errors.Is(getErr, repository.ErrNotFound) {
			return fmt.Errorf("migrate: inspect destination message: %w", getErr)
		}
		// A state without its immutable message means a prior implementation
		// violated atomicity. Refuse to overwrite or guess.
		if _, stateErr := repo.GetRecord(ctx, target, mailbox.MessageStateCollection, fingerprint); stateErr == nil {
			return fmt.Errorf("%w: orphan message state for %s", mailbox.ErrIntegrity, fingerprint)
		} else if !errors.Is(stateErr, repository.ErrNotFound) {
			return stateErr
		}
		blob, err := repo.UploadBlob(ctx, target, src.Imported.Raw, mailbox.MessageMIMEType)
		if err != nil {
			return fmt.Errorf("migrate: upload message blob: %w", err)
		}
		pair, err := mailbox.NewMessagePair(src.Imported, blob)
		if err != nil {
			return err
		}
		_, err = repo.ApplyWrites(ctx, target, []repository.Write{
			{Action: repository.Create, Collection: mailbox.MessageCollection, RKey: pair.RKey, Value: pair.Message},
			{Action: repository.Create, Collection: mailbox.MessageStateCollection, RKey: pair.RKey, Value: pair.State},
		})
		if err == nil {
			report.CreatedMessages++
			return nil
		}
		if !errors.Is(err, repository.ErrExists) {
			return fmt.Errorf("migrate: atomically create message and state: %w", err)
		}
		// Resolve an ambiguous response or a concurrent identical importer by
		// checking committed content. ErrExists alone is never proof of success.
		existing, getErr = repo.GetRecord(ctx, target, mailbox.MessageCollection, pair.RKey)
		if getErr != nil {
			return errors.Join(err, getErr)
		}
		if verifyErr := verifyExistingMessage(ctx, repo, target, src.Imported, existing); verifyErr != nil {
			return errors.Join(err, verifyErr)
		}
		report.ExistingMessages++
		return nil
	})
	sort.Strings(report.Fingerprints)
	if err != nil {
		return report, err
	}
	report.Verification, err = Verify(ctx, snapshot, inv.Space, repo, target)
	if err != nil {
		return report, err
	}
	if !report.Verification.Passed() {
		return report, fmt.Errorf("%w: post-migration reconstruction mismatch", mailbox.ErrIntegrity)
	}
	return report, nil
}

func verifyFolderRecord(record repository.Record, expected mailbox.FolderRecord) error {
	var got mailbox.FolderRecord
	if err := json.Unmarshal(record.Value, &got); err != nil {
		return fmt.Errorf("%w: decode existing folder record", mailbox.ErrIntegrity)
	}
	if !reflect.DeepEqual(got, expected) {
		return fmt.Errorf("%w: existing folder record differs", mailbox.ErrIntegrity)
	}
	return nil
}

func verifyExistingMessage(ctx context.Context, repo repository.Repository, target repository.Target, src mailbox.ImportedMessage, record repository.Record) error {
	var got mailbox.MessageRecord
	if err := json.Unmarshal(record.Value, &got); err != nil {
		return fmt.Errorf("%w: decode existing message record", mailbox.ErrIntegrity)
	}
	raw, err := repo.GetBlob(ctx, target, got.Raw.Ref.Link)
	if err != nil {
		return fmt.Errorf("%w: fetch existing message blob: %v", mailbox.ErrIntegrity, err)
	}
	if err := mailbox.ValidateStoredMessage(src.RecipientDID, record.RKey, got, raw); err != nil {
		return err
	}
	if !reflect.DeepEqual(raw, src.Raw) {
		return fmt.Errorf("%w: existing canonical bytes differ", mailbox.ErrIntegrity)
	}
	expected, err := mailbox.NewMessagePair(src, got.Raw)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(got, expected.Message) {
		return fmt.Errorf("%w: existing immutable metadata differs", mailbox.ErrIntegrity)
	}
	stateRecord, err := repo.GetRecord(ctx, target, mailbox.MessageStateCollection, record.RKey)
	if err != nil {
		return fmt.Errorf("%w: existing message state missing: %v", mailbox.ErrIntegrity, err)
	}
	var state mailbox.MessageStateRecord
	if err := json.Unmarshal(stateRecord.Value, &state); err != nil {
		return fmt.Errorf("%w: decode existing message state", mailbox.ErrIntegrity)
	}
	if !reflect.DeepEqual(state, expected.State) {
		return fmt.Errorf("%w: existing message state differs", mailbox.ErrIntegrity)
	}
	return nil
}

func WriteReport(path string, report Report) error {
	if path == "" {
		return errors.New("migrate: evidence path is required")
	}
	parent := filepath.Dir(path)
	if info, err := os.Stat(parent); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("migrate: evidence directory permissions are too broad: %o", info.Mode().Perm())
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}
