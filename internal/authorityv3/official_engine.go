// SPDX-License-Identifier: AGPL-3.0-or-later

package authorityv3

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/comail-atproto/comail-space-host/internal/mailbox"
	"github.com/comail-atproto/comail-space-host/internal/mailboxstate"
	"github.com/comail-atproto/comail-space-host/internal/providers/officialspaces"
	"github.com/comail-atproto/comail-space-host/internal/repository"
)

var standardFolders = []struct {
	Role string
	Name string
}{
	{Role: "archive", Name: "Archive"},
	{Role: "drafts", Name: "Drafts"},
	{Role: "important", Name: "Important"},
	{Role: "inbox", Name: "Inbox"},
	{Role: "junk", Name: "Junk"},
	{Role: "sent", Name: "Sent"},
	{Role: "trash", Name: "Trash"},
}

type officialWriter interface {
	TransportID() string
	Target() officialspaces.Target
	UploadMessageBlob(context.Context, []byte) (mailbox.BlobRef, error)
	CreateBatch(context.Context, []officialspaces.Create) ([]officialspaces.CreateResult, error)
	InspectRecord(context.Context, string, string) (officialspaces.UnverifiedRecord, error)
}

type snapshotReader func(context.Context) (Snapshot, error)

// OfficialEngine is the official-Spaces implementation of the separate v3
// authority contract. Its client owns member OAuth and delegated DPoP
// credentials; none cross into the relay-facing handler.
type OfficialEngine struct {
	target       Target
	client       officialWriter
	readSnapshot snapshotReader
	now          func() time.Time
}

func NewOfficialEngine(client *officialspaces.Client, target Target) (*OfficialEngine, error) {
	if client == nil {
		return nil, errors.New("authorityv3: official Spaces client is required")
	}
	engine, err := newOfficialEngine(client, target, nil)
	if err != nil {
		return nil, err
	}
	engine.readSnapshot = func(ctx context.Context) (Snapshot, error) {
		return readOfficialSnapshot(ctx, client, target)
	}
	return engine, nil
}

func newOfficialEngine(client officialWriter, target Target, reader snapshotReader) (*OfficialEngine, error) {
	if client == nil || target.ProviderID == "" || strings.ContainsAny(target.ProviderID, " \t\r\n") ||
		target.AuthorityCertificateGeneration != AuthorityGeneration || !validLowerSHA256(target.AuthorityCertificateSHA256) {
		return nil, errors.New("authorityv3: exact official target and certificate are required")
	}
	wireTarget := client.Target()
	repositoryTarget := repository.Target{
		ProviderOrigin: target.Origin, SpaceURI: target.SpaceURI, RepoDID: target.RepoDID, Epoch: target.Epoch,
	}
	if client.TransportID() != target.ProviderID || wireTarget.Origin != target.Origin || wireTarget.SpaceURI != target.SpaceURI ||
		wireTarget.RepoDID != target.RepoDID || wireTarget.Epoch != target.Epoch ||
		target.Epoch != officialspaces.PinnedEpoch || repositoryTarget.ValidateFor(target.RepoDID) != nil {
		return nil, repository.ErrTarget
	}
	return &OfficialEngine{target: target, client: client, readSnapshot: reader, now: time.Now}, nil
}

func (engine *OfficialEngine) Capabilities(context.Context) (Capabilities, error) {
	return Capabilities{
		PrivateRecords: true, ReferencedBlobs: true, AtomicCreateBatch: true,
		IdempotentOperationClaims: true, AuthenticatedStableRead: true, CompleteInventory: true,
		ConcurrentHeads: true, Tombstones: true, SourceVersioning: true,
		AuthorityCertificateSHA256: engine.target.AuthorityCertificateSHA256,
		AuthorityGeneration:        AuthorityGeneration,
	}, nil
}

func (engine *OfficialEngine) Snapshot(ctx context.Context) (Snapshot, error) {
	if engine == nil || engine.readSnapshot == nil {
		return Snapshot{}, errors.New("authorityv3: source-authenticated snapshot reader is unavailable")
	}
	snapshot, err := engine.readSnapshot(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	if snapshot.Target != engine.target || snapshot.Version != ProtocolVersion {
		clearSnapshot(&snapshot)
		return Snapshot{}, repository.ErrTarget
	}
	return snapshot, nil
}

func (engine *OfficialEngine) Store(ctx context.Context, input StoreInput) (Receipt, error) {
	if engine == nil || input.RecipientDID != engine.target.RepoDID || len(input.Raw) == 0 ||
		len(input.Raw) > mailbox.MaxRawMessageBytes || len(input.Placement.Folders) == 0 {
		return Receipt{}, mailbox.ErrInvalidRecord
	}
	folders, err := engine.ensureFolders(ctx, input.Placement.Folders)
	if err != nil {
		return Receipt{}, err
	}
	current, err := engine.Snapshot(ctx)
	if err != nil {
		return Receipt{}, err
	}
	defer clearSnapshot(&current)

	imported := mailbox.ImportedMessage{
		RecipientDID: input.RecipientDID, SourceKey: input.Placement.SourceKey,
		Raw: bytes.Clone(input.Raw), Mailbox: input.Placement.Folders[0].Name,
		Keywords: append([]string(nil), input.Placement.Keywords...), DeliveredAt: engine.now().UTC(),
	}
	fingerprint := mailbox.ImportedFingerprint(imported)
	logicalID := mailbox.LogicalMessageID(input.RecipientDID, input.Placement.SourceKey, fingerprint)
	if version, found := findVersion(current, fingerprint); found {
		if version.LogicalMessageID != logicalID || !bytes.Equal(version.Raw, input.Raw) {
			return Receipt{}, mailbox.ErrIntegrity
		}
		return engine.receipt(fingerprint, input.Raw), nil
	}
	prior, hasPrior := findState(current, logicalID)
	if hasPrior && prior.Tombstone {
		// Tombstones are irreversible in the append-only reducer. Appending a
		// new live version from a tombstoned head would permanently invalidate
		// the complete source, so reject before uploading bytes or writing.
		return Receipt{}, ErrConflict
	}

	blob, err := engine.client.UploadMessageBlob(ctx, input.Raw)
	if err != nil {
		return Receipt{}, err
	}
	pair, err := mailbox.NewMessagePair(imported, blob)
	if err != nil {
		return Receipt{}, err
	}
	mailboxIDs := make([]string, 0, len(folders))
	for _, folder := range folders {
		mailboxIDs = append(mailboxIDs, folder.FolderID)
	}
	sort.Strings(mailboxIDs)
	keywords := append([]string(nil), input.Placement.Keywords...)
	sort.Strings(keywords)

	record := mailboxstate.RevisionRecord{
		Type: mailbox.MessageStateRevisionCollection, LogicalMessageID: logicalID,
		OperationID: "initial", Parents: []string{}, Revision: 1, Version: pair.RKey,
		MailboxIDs: mailboxIDs, Keywords: keywordAssignments(nil, keywords),
		CreatedAt: engine.now().UTC().Format(time.RFC3339Nano),
	}
	if hasPrior {
		record.OperationID = "version-" + strings.TrimPrefix(fingerprint, "sha256-")
		record.Parents = append([]string(nil), prior.Heads...)
		record.Revision = prior.Height + 1
		record.Keywords = keywordAssignments(prior.Keywords, keywords)
	}
	revision, claim, err := buildStateCreates(engine.target.RepoDID, record)
	if err != nil {
		return Receipt{}, err
	}
	messageValue, err := json.Marshal(pair.Message)
	if err != nil {
		return Receipt{}, err
	}
	creates := []officialspaces.Create{
		{Collection: mailbox.MessageCollection, RKey: pair.RKey, Value: messageValue},
		revision,
		claim,
	}
	if _, err := engine.client.CreateBatch(ctx, creates); err != nil {
		if !errors.Is(err, repository.ErrExists) {
			return Receipt{}, err
		}
		exists, inspectErr := engine.stateAppendExists(ctx, record)
		if inspectErr != nil {
			return Receipt{}, inspectErr
		}
		if !exists {
			return Receipt{}, ErrConflict
		}
	}
	verified, err := engine.Snapshot(ctx)
	if err != nil {
		return Receipt{}, err
	}
	defer clearSnapshot(&verified)
	version, found := findVersion(verified, fingerprint)
	if !found || version.LogicalMessageID != logicalID || !bytes.Equal(version.Raw, input.Raw) {
		return Receipt{}, mailbox.ErrIntegrity
	}
	state, found := findState(verified, logicalID)
	if !found || state.Version != fingerprint || !equalStrings(state.MailboxIDs, mailboxIDs) ||
		!equalStrings(state.Keywords, keywords) {
		return Receipt{}, ErrConflict
	}
	return engine.receipt(fingerprint, input.Raw), nil
}

func (engine *OfficialEngine) AppendState(ctx context.Context, mutation StateMutation) (MessageState, error) {
	current, err := engine.Snapshot(ctx)
	if err != nil {
		return MessageState{}, err
	}
	defer clearSnapshot(&current)
	state, found := findState(current, mutation.LogicalMessageID)
	if !found || current.SnapshotID != mutation.SnapshotID || state.SnapshotID != mutation.SnapshotID ||
		state.HeadsDigest != mutation.ExpectedHeadsDigest || state.StateDigest != mutation.ExpectedStateDigest ||
		state.Height != mutation.ExpectedHeight || state.RevisionCount != mutation.ExpectedRevisionCount ||
		!equalStrings(state.Heads, mutation.ExpectedHeads) {
		return MessageState{}, ErrConflict
	}
	if state.Tombstone {
		// A reduced tombstone can never be resurrected. Repeated tombstones are
		// also rejected: they add no state and unnecessarily expand immutable
		// history.
		return MessageState{}, ErrConflict
	}
	if mutation.Tombstone && (mutation.Version != state.Version ||
		!equalStrings(mutation.MailboxIDs, state.MailboxIDs) ||
		!equalStrings(mutation.Keywords, state.Keywords) || mutation.DeletePending) {
		// Tombstone records carry no live assignments. The reducer retains the
		// existing version/folders/keywords and forces deletePending=false, so
		// require that exact projected result before the irreversible append.
		return MessageState{}, ErrConflict
	}
	selected, found := findVersion(current, mutation.Version)
	if !mutation.Tombstone && (!found || selected.LogicalMessageID != mutation.LogicalMessageID ||
		!liveFolderSet(current.Folders, mutation.MailboxIDs)) {
		return MessageState{}, mailbox.ErrInvalidRecord
	}

	record := mailboxstate.RevisionRecord{
		Type: mailbox.MessageStateRevisionCollection, LogicalMessageID: mutation.LogicalMessageID,
		OperationID: mutation.OperationID, Parents: append([]string(nil), mutation.ExpectedHeads...),
		Revision: mutation.ExpectedHeight + 1, CreatedAt: engine.now().UTC().Format(time.RFC3339Nano),
	}
	if mutation.Tombstone {
		record.Tombstone = true
	} else {
		record.Version = mutation.Version
		record.MailboxIDs = append([]string(nil), mutation.MailboxIDs...)
		record.Keywords = keywordAssignments(state.Keywords, mutation.Keywords)
		deletePending := mutation.DeletePending
		record.DeletePending = &deletePending
	}
	revision, claim, err := buildStateCreates(engine.target.RepoDID, record)
	if err != nil {
		return MessageState{}, err
	}
	if _, err := engine.client.CreateBatch(ctx, []officialspaces.Create{revision, claim}); err != nil {
		if !errors.Is(err, repository.ErrExists) {
			return MessageState{}, err
		}
		exists, inspectErr := engine.stateAppendExists(ctx, record)
		if inspectErr != nil {
			return MessageState{}, inspectErr
		}
		if !exists {
			return MessageState{}, ErrConflict
		}
	}
	verified, err := engine.Snapshot(ctx)
	if err != nil {
		return MessageState{}, err
	}
	defer clearSnapshot(&verified)
	result, found := findState(verified, mutation.LogicalMessageID)
	if !found || result.SnapshotID == mutation.SnapshotID || result.Version != mutation.Version ||
		!equalStrings(result.MailboxIDs, mutation.MailboxIDs) || !equalStrings(result.Keywords, mutation.Keywords) ||
		result.DeletePending != mutation.DeletePending || result.Tombstone != mutation.Tombstone ||
		result.Height != mutation.ExpectedHeight+1 || result.RevisionCount != mutation.ExpectedRevisionCount+1 {
		return MessageState{}, ErrConflict
	}
	return result, nil
}

func (engine *OfficialEngine) ensureFolders(ctx context.Context, selections []FolderSelection) ([]FolderState, error) {
	standards := make([]FolderSelection, 0, len(standardFolders))
	for _, standard := range standardFolders {
		standards = append(standards, FolderSelection{SourceKey: "role:" + standard.Role, Name: standard.Name, Role: standard.Role})
	}
	if err := engine.ensureInitialFolderRecords(ctx, standards, false); err != nil {
		return nil, err
	}

	// Once the canonical set exists, a source-authenticated snapshot is the
	// admission boundary for custom names. This prevents a new custom folder
	// from poisoning the folder graph through a reserved or duplicate name.
	current, err := engine.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	defer clearSnapshot(&current)
	byID := make(map[string]FolderState, len(current.Folders))
	for _, folder := range current.Folders {
		byID[folder.FolderID] = folder
	}
	selected := make(map[string]struct{}, len(selections))
	result := make([]FolderState, 0, len(selections))
	for _, selection := range selections {
		folderID, err := folderIDFor(engine.target.RepoDID, selection)
		if err != nil {
			return nil, err
		}
		if _, duplicate := selected[folderID]; duplicate {
			return nil, mailbox.ErrInvalidRecord
		}
		selected[folderID] = struct{}{}
		if prior, exists := byID[folderID]; exists {
			if prior.Name != selection.Name || prior.Role != selection.Role || prior.Tombstone {
				return nil, mailbox.ErrInvalidRecord
			}
			result = append(result, prior)
			continue
		}
		// Creating custom folders safely needs a provider-atomic, globally
		// case-folded name reservation. The current five-record alpha schema has
		// no such primitive; snapshot-then-create is a TOCTOU that could admit
		// two SourceKeys with the same name and permanently poison reduction.
		// Existing source-authenticated custom folders remain selectable, but
		// new custom-folder creation stays fail-closed.
		return nil, mailbox.ErrInvalidRecord
	}
	return result, nil
}

func (engine *OfficialEngine) ensureInitialFolderRecords(ctx context.Context, selections []FolderSelection, retried bool) error {
	creates := make([]officialspaces.Create, 0, len(selections)*2)
	for _, selection := range selections {
		folderID, err := folderIDFor(engine.target.RepoDID, selection)
		if err != nil {
			return err
		}
		expected, revisionCreate, claimCreate, err := engine.initialFolderCreates(selection, folderID)
		if err != nil {
			return err
		}
		exists, err := engine.folderInitializationExists(ctx, expected)
		if err != nil {
			return err
		}
		if !exists {
			creates = append(creates, revisionCreate, claimCreate)
		}
	}
	if len(creates) == 0 {
		return nil
	}
	if _, err := engine.client.CreateBatch(ctx, creates); err != nil {
		if !errors.Is(err, repository.ErrExists) || retried {
			return err
		}
		// A racing initializer may have won. Verify every deterministic
		// operation claim once; repeated collisions fail closed.
		return engine.ensureInitialFolderRecords(ctx, selections, true)
	}
	return nil
}

func (engine *OfficialEngine) initialFolderCreates(
	selection FolderSelection,
	folderID string,
) (mailboxstate.FolderStateRevision, officialspaces.Create, officialspaces.Create, error) {
	revision := mailboxstate.FolderStateRevision{Record: mailboxstate.FolderRevisionRecord{
		Type: mailbox.FolderRevisionCollection, FolderID: folderID, OperationID: "initial",
		Parents: []string{}, Revision: 1, Name: selection.Name, Role: selection.Role,
		CreatedAt: engine.now().UTC().Format(time.RFC3339Nano),
	}}
	var err error
	revision.RKey, err = mailboxstate.FolderRevisionRKey(engine.target.RepoDID, revision.Record)
	if err != nil {
		return mailboxstate.FolderStateRevision{}, officialspaces.Create{}, officialspaces.Create{}, err
	}
	claim, err := mailboxstate.NewFolderOperationClaim(engine.target.RepoDID, revision)
	if err != nil {
		return mailboxstate.FolderStateRevision{}, officialspaces.Create{}, officialspaces.Create{}, err
	}
	revisionValue, err := json.Marshal(revision.Record)
	if err != nil {
		return mailboxstate.FolderStateRevision{}, officialspaces.Create{}, officialspaces.Create{}, err
	}
	claimValue, err := json.Marshal(claim.Record)
	if err != nil {
		return mailboxstate.FolderStateRevision{}, officialspaces.Create{}, officialspaces.Create{}, err
	}
	return revision,
		officialspaces.Create{Collection: mailbox.FolderRevisionCollection, RKey: revision.RKey, Value: revisionValue},
		officialspaces.Create{Collection: mailbox.FolderOperationCollection, RKey: claim.RKey, Value: claimValue}, nil
}

func (engine *OfficialEngine) folderInitializationExists(ctx context.Context, expected mailboxstate.FolderStateRevision) (bool, error) {
	claimKey, err := mailboxstate.FolderOperationClaimRKey(engine.target.RepoDID, expected.Record.FolderID, expected.Record.OperationID)
	if err != nil {
		return false, err
	}
	storedClaim, err := engine.client.InspectRecord(ctx, mailbox.FolderOperationCollection, claimKey)
	if errors.Is(err, repository.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	claim, err := mailboxstate.DecodeFolderOperationClaimRecord(storedClaim.Value)
	if err != nil || claim.FolderID != expected.Record.FolderID || claim.OperationID != expected.Record.OperationID {
		return false, mailbox.ErrIntegrity
	}
	storedRevision, err := engine.client.InspectRecord(ctx, mailbox.FolderRevisionCollection, claim.RevisionRKey)
	if err != nil {
		return false, err
	}
	record, err := mailboxstate.DecodeFolderRevisionRecord(storedRevision.Value)
	if err != nil {
		return false, mailbox.ErrIntegrity
	}
	actual := mailboxstate.FolderStateRevision{RKey: storedRevision.RKey, Record: record}
	if mailboxstate.VerifyFolderRevisionRetry(engine.target.RepoDID, expected, actual) != nil {
		return false, mailbox.ErrIntegrity
	}
	return true, nil
}

func (engine *OfficialEngine) stateAppendExists(ctx context.Context, expected mailboxstate.RevisionRecord) (bool, error) {
	claimKey, err := mailboxstate.OperationClaimRKey(engine.target.RepoDID, expected.LogicalMessageID, expected.OperationID)
	if err != nil {
		return false, err
	}
	storedClaim, err := engine.client.InspectRecord(ctx, mailbox.MessageStateOperationCollection, claimKey)
	if errors.Is(err, repository.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	claim, err := mailboxstate.DecodeOperationClaimRecord(storedClaim.Value)
	if err != nil || claim.LogicalMessageID != expected.LogicalMessageID || claim.OperationID != expected.OperationID {
		return false, mailbox.ErrIntegrity
	}
	storedRevision, err := engine.client.InspectRecord(ctx, mailbox.MessageStateRevisionCollection, claim.RevisionRKey)
	if err != nil {
		return false, err
	}
	record, err := mailboxstate.DecodeRevisionRecord(storedRevision.Value)
	if err != nil {
		return false, mailbox.ErrIntegrity
	}
	expectedRevision := mailboxstate.StateRevision{Record: expected}
	expectedRevision.RKey, err = mailboxstate.StateRevisionRKey(engine.target.RepoDID, expected)
	if err != nil {
		return false, err
	}
	actual := mailboxstate.StateRevision{RKey: storedRevision.RKey, Record: record}
	if mailboxstate.VerifyRevisionRetry(engine.target.RepoDID, expectedRevision, actual) != nil {
		return false, ErrConflict
	}
	return true, nil
}

func readOfficialSnapshot(ctx context.Context, client *officialspaces.Client, target Target) (Snapshot, error) {
	source, err := mailboxstate.ReadOfficialSpacesRecoverySource(ctx, client)
	if err != nil {
		return Snapshot{}, err
	}
	defer source.Close()
	summary := source.Summary()
	if summary.Target != client.Target() || summary.Target.Origin != target.Origin || summary.Target.SpaceURI != target.SpaceURI ||
		summary.Target.RepoDID != target.RepoDID || summary.Target.Epoch != target.Epoch {
		return Snapshot{}, repository.ErrTarget
	}
	snapshot := Snapshot{
		Version: ProtocolVersion, Target: target, Revision: summary.Revision,
		SnapshotID: summary.SnapshotID, ManifestSHA256: summary.ManifestSHA256,
	}
	for _, folder := range source.Folders() {
		snapshot.Folders = append(snapshot.Folders, FolderState(folder))
	}
	for _, state := range source.MessageStates() {
		snapshot.States = append(snapshot.States, MessageState(state))
	}
	err = source.VisitMessages(ctx, func(message mailboxstate.ContentVerifiedMessage) error {
		version, raw, openErr := message.Open()
		if openErr != nil {
			return openErr
		}
		snapshot.Messages = append(snapshot.Messages, MessageVersion{
			URI:  target.SpaceURI + "/" + target.RepoDID + "/" + mailbox.MessageCollection + "/" + version.RKey,
			RKey: version.RKey, Fingerprint: version.RKey, LogicalMessageID: version.Record.LogicalMessageID,
			SourceKey: version.Record.SourceKey, SHA256: version.Record.SHA256,
			Size: version.Record.Size, Raw: raw,
		})
		return nil
	})
	if err != nil || source.ValidateSeal() != nil {
		clearSnapshot(&snapshot)
		if err != nil {
			return Snapshot{}, err
		}
		return Snapshot{}, mailbox.ErrIntegrity
	}
	sort.Slice(snapshot.Folders, func(left, right int) bool { return snapshot.Folders[left].FolderID < snapshot.Folders[right].FolderID })
	sort.Slice(snapshot.Messages, func(left, right int) bool { return snapshot.Messages[left].RKey < snapshot.Messages[right].RKey })
	sort.Slice(snapshot.States, func(left, right int) bool {
		return snapshot.States[left].LogicalMessageID < snapshot.States[right].LogicalMessageID
	})
	return snapshot, nil
}

func buildStateCreates(repoDID string, record mailboxstate.RevisionRecord) (officialspaces.Create, officialspaces.Create, error) {
	revision := mailboxstate.StateRevision{Record: record}
	var err error
	revision.RKey, err = mailboxstate.StateRevisionRKey(repoDID, record)
	if err != nil {
		return officialspaces.Create{}, officialspaces.Create{}, err
	}
	claim, err := mailboxstate.NewOperationClaim(repoDID, revision)
	if err != nil {
		return officialspaces.Create{}, officialspaces.Create{}, err
	}
	revisionValue, err := json.Marshal(revision.Record)
	if err != nil {
		return officialspaces.Create{}, officialspaces.Create{}, err
	}
	claimValue, err := json.Marshal(claim.Record)
	if err != nil {
		return officialspaces.Create{}, officialspaces.Create{}, err
	}
	return officialspaces.Create{Collection: mailbox.MessageStateRevisionCollection, RKey: revision.RKey, Value: revisionValue},
		officialspaces.Create{Collection: mailbox.MessageStateOperationCollection, RKey: claim.RKey, Value: claimValue}, nil
}

func folderIDFor(repoDID string, selection FolderSelection) (string, error) {
	if selection.SourceKey == "" || selection.Name == "" || len(selection.SourceKey) > 512 || len(selection.Name) > 255 ||
		strings.ContainsAny(selection.SourceKey+selection.Name+selection.Role, "\r\n\x00") {
		return "", mailbox.ErrInvalidRecord
	}
	if selection.Role != "" {
		for _, standard := range standardFolders {
			if selection.Role == standard.Role && selection.Name == standard.Name {
				return mailboxstate.StandardFolderID(repoDID, selection.Role)
			}
		}
		return "", mailbox.ErrInvalidRecord
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("comail-portable-folder-v1\x00"))
	_, _ = hash.Write([]byte(repoDID))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(selection.SourceKey))
	return "folder-" + hex.EncodeToString(hash.Sum(nil)), nil
}

func keywordAssignments(current, desired []string) []mailboxstate.KeywordAssignment {
	wanted := make(map[string]bool, len(current)+len(desired))
	for _, keyword := range current {
		wanted[keyword] = false
	}
	for _, keyword := range desired {
		wanted[keyword] = true
	}
	keys := make([]string, 0, len(wanted))
	for keyword := range wanted {
		keys = append(keys, keyword)
	}
	sort.Strings(keys)
	result := make([]mailboxstate.KeywordAssignment, 0, len(keys))
	for _, keyword := range keys {
		result = append(result, mailboxstate.KeywordAssignment{Name: keyword, Present: wanted[keyword]})
	}
	return result
}

func findVersion(snapshot Snapshot, rkey string) (MessageVersion, bool) {
	for _, version := range snapshot.Messages {
		if version.RKey == rkey {
			return version, true
		}
	}
	return MessageVersion{}, false
}

func findState(snapshot Snapshot, logicalID string) (MessageState, bool) {
	for _, state := range snapshot.States {
		if state.LogicalMessageID == logicalID {
			return state, true
		}
	}
	return MessageState{}, false
}

func liveFolderSet(folders []FolderState, selected []string) bool {
	available := make(map[string]bool, len(folders))
	for _, folder := range folders {
		available[folder.FolderID] = !folder.Tombstone
	}
	if len(selected) == 0 {
		return false
	}
	for _, folderID := range selected {
		if !available[folderID] {
			return false
		}
	}
	return true
}

func folderNameExists(folders []FolderState, name string) bool {
	for _, folder := range folders {
		if !folder.Tombstone && strings.EqualFold(folder.Name, name) {
			return true
		}
	}
	return false
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func (engine *OfficialEngine) receipt(fingerprint string, raw []byte) Receipt {
	return Receipt{
		Target: engine.target, Fingerprint: fingerprint, SHA256: mailbox.RawSHA256(raw),
		Size: int64(len(raw)), Verified: true,
	}
}

func clearSnapshot(snapshot *Snapshot) {
	if snapshot == nil {
		return
	}
	for index := range snapshot.Messages {
		clear(snapshot.Messages[index].Raw)
		snapshot.Messages[index].Raw = nil
	}
}

func validLowerSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}

var _ Engine = (*OfficialEngine)(nil)

func (target Target) String() string { return "authorityv3.Target(redacted)" }

func (target Target) GoString() string { return target.String() }

func (snapshot Snapshot) String() string {
	return fmt.Sprintf("authorityv3.Snapshot(folders=%d,messages=%d,states=%d)", len(snapshot.Folders), len(snapshot.Messages), len(snapshot.States))
}

func (snapshot Snapshot) GoString() string { return snapshot.String() }
