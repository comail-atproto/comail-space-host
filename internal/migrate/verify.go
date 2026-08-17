package migrate

import (
	"context"
	"encoding/json"
	"reflect"
	"sort"

	"github.com/comail-atproto/comail-space-host/internal/mailbox"
	"github.com/comail-atproto/comail-space-host/internal/repository"
	"github.com/comail-atproto/comail-space-host/internal/sqliteimport"
)

func Verify(ctx context.Context, snapshot SourceSnapshot, space sqliteimport.Space, repo repository.Repository, target repository.Target) (Verification, error) {
	verification := Verification{}
	type expectedMessage struct {
		imported mailbox.ImportedMessage
	}
	expectedMessages := make(map[string]expectedMessage)
	if err := snapshot.Stream(ctx, space, func(src sqliteimport.SourceMessage) error {
		fingerprint := mailbox.ImportedFingerprint(src.Imported)
		expectedMessages[fingerprint] = expectedMessage{imported: src.Imported}
		return nil
	}); err != nil {
		return verification, err
	}
	verification.SourceMessages = len(expectedMessages)
	folders, err := snapshot.Folders(ctx, space)
	if err != nil {
		return verification, err
	}
	expectedFolders := make(map[string]mailbox.FolderRecord, len(folders))
	for _, folder := range folders {
		expectedFolders[folder.Folder.RKey] = folder.Folder.Record
	}
	verification.SourceFolders = len(expectedFolders)
	destinationMessages, err := repo.ListRecords(ctx, target, mailbox.MessageCollection)
	if err != nil {
		return verification, err
	}
	verification.DestinationMessages = len(destinationMessages)
	seen := make(map[string]bool, len(destinationMessages))
	for _, record := range destinationMessages {
		expected, ok := expectedMessages[record.RKey]
		if !ok {
			verification.Mismatches = append(verification.Mismatches, Mismatch{Kind: "extra-message", Key: record.RKey, Detail: "destination record is absent from source snapshot"})
			continue
		}
		seen[record.RKey] = true
		if err := verifyExistingMessage(ctx, repo, target, expected.imported, record); err != nil {
			verification.Mismatches = append(verification.Mismatches, Mismatch{Kind: "message-integrity", Key: record.RKey, Detail: "record, blob, or state differs from source"})
			continue
		}
		verification.VerifiedMessages++
	}
	for fingerprint := range expectedMessages {
		if !seen[fingerprint] {
			verification.Mismatches = append(verification.Mismatches, Mismatch{Kind: "missing-message", Key: fingerprint, Detail: "source message is absent from destination"})
		}
	}
	destinationFolders, err := repo.ListRecords(ctx, target, mailbox.FolderCollection)
	if err != nil {
		return verification, err
	}
	verification.DestinationFolders = len(destinationFolders)
	seenFolders := make(map[string]bool, len(destinationFolders))
	for _, record := range destinationFolders {
		expected, ok := expectedFolders[record.RKey]
		if !ok {
			verification.Mismatches = append(verification.Mismatches, Mismatch{Kind: "extra-folder", Key: record.RKey, Detail: "destination folder is absent from source snapshot"})
			continue
		}
		seenFolders[record.RKey] = true
		var got mailbox.FolderRecord
		if json.Unmarshal(record.Value, &got) != nil || !reflect.DeepEqual(got, expected) {
			verification.Mismatches = append(verification.Mismatches, Mismatch{Kind: "folder-integrity", Key: record.RKey, Detail: "folder definition differs from source"})
			continue
		}
		verification.VerifiedFolders++
	}
	for rkey := range expectedFolders {
		if !seenFolders[rkey] {
			verification.Mismatches = append(verification.Mismatches, Mismatch{Kind: "missing-folder", Key: rkey, Detail: "source folder is absent from destination"})
		}
	}
	stateRecords, err := repo.ListRecords(ctx, target, mailbox.MessageStateCollection)
	if err != nil {
		return verification, err
	}
	if len(stateRecords) != len(expectedMessages) {
		verification.Mismatches = append(verification.Mismatches, Mismatch{Kind: "state-count", Key: "sha256-redacted", Detail: "message-state count differs from source message count"})
	}
	for _, stateRecord := range stateRecords {
		if _, ok := expectedMessages[stateRecord.RKey]; !ok {
			verification.Mismatches = append(verification.Mismatches, Mismatch{Kind: "extra-state", Key: stateRecord.RKey, Detail: "state is not tied to a source message"})
		}
	}
	sort.Slice(verification.Mismatches, func(i, j int) bool {
		if verification.Mismatches[i].Kind == verification.Mismatches[j].Kind {
			return verification.Mismatches[i].Key < verification.Mismatches[j].Key
		}
		return verification.Mismatches[i].Kind < verification.Mismatches[j].Kind
	})
	return verification, nil
}
