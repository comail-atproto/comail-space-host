package projection

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/comail-atproto/comail-space-host/internal/mailbox"
	"github.com/comail-atproto/comail-space-host/internal/mailboxstate"
	"github.com/comail-atproto/comail-space-host/internal/providers/officialspaces"
	"github.com/comail-atproto/comail-space-host/internal/repository"
)

type officialProjectionSource interface {
	Summary() mailboxstate.ContentVerificationSummary
	Folders() []mailboxstate.ReducedFolderState
	MessageStates() []mailboxstate.ReducedState
	VisitMessages(context.Context, func(mailboxstate.MessageVersion, []byte) error) error
	ValidateSeal() error
}

type sealedOfficialProjectionSource struct {
	source *mailboxstate.ContentVerifiedSource
}

func (source sealedOfficialProjectionSource) Summary() mailboxstate.ContentVerificationSummary {
	return source.source.Summary()
}

func (source sealedOfficialProjectionSource) Folders() []mailboxstate.ReducedFolderState {
	return source.source.Folders()
}

func (source sealedOfficialProjectionSource) MessageStates() []mailboxstate.ReducedState {
	return source.source.MessageStates()
}

func (source sealedOfficialProjectionSource) VisitMessages(ctx context.Context, visit func(mailboxstate.MessageVersion, []byte) error) error {
	return source.source.VisitMessages(ctx, func(message mailboxstate.ContentVerifiedMessage) error {
		version, raw, err := message.Open()
		if err != nil {
			return err
		}
		defer clear(raw)
		return visit(version, raw)
	})
}

func (source sealedOfficialProjectionSource) ValidateSeal() error {
	return source.source.ValidateSeal()
}

// RebuildOfficial creates a fresh disposable SQLite projection from only one
// byte-complete, source-authenticated official Spaces recovery capability.
// Callers cannot substitute a record list, saved CAR, or self-asserted source.
func RebuildOfficial(ctx context.Context, source *mailboxstate.ContentVerifiedSource, destination string) (Report, error) {
	if source == nil {
		return Report{Version: 3}, errors.New("projection: sealed official source is required")
	}
	return rebuildOfficialSpaces(ctx, sealedOfficialProjectionSource{source: source}, destination)
}

type officialProjectionGraph struct {
	folders        []officialProjectionFolder
	folderByID     map[string]officialProjectionFolder
	selected       map[string]*officialProjectionState
	liveStates     int
	messageDeletes int
}

type officialProjectionFolder struct {
	state       mailboxstate.ReducedFolderState
	uidValidity uint32
}

type officialProjectionState struct {
	state mailboxstate.ReducedState
	uids  map[string]uint32
}

type officialManifest struct {
	Version  int                       `json:"version"`
	Target   repository.Target         `json:"target"`
	Folders  []officialManifestFolder  `json:"folders"`
	Messages []officialManifestMessage `json:"messages"`
}

type officialManifestFolder struct {
	FolderID    string `json:"folderId"`
	Name        string `json:"name"`
	Role        string `json:"role,omitempty"`
	UIDValidity uint32 `json:"uidValidity"`
	Revision    uint64 `json:"revision"`
}

type officialManifestMessage struct {
	RKey            string                       `json:"rkey"`
	SHA256          string                       `json:"sha256"`
	Size            int64                        `json:"size"`
	Keywords        []string                     `json:"keywords"`
	DeletePending   bool                         `json:"deletePending"`
	SourceMessageID string                       `json:"sourceMessageId,omitempty"`
	MessageDate     string                       `json:"messageDate,omitempty"`
	InReplyTo       string                       `json:"inReplyTo,omitempty"`
	References      []string                     `json:"references,omitempty"`
	Memberships     []officialManifestMembership `json:"memberships"`
}

type officialManifestMembership struct {
	FolderID    string `json:"folderId"`
	Mailbox     string `json:"mailbox"`
	UID         uint32 `json:"uid"`
	UIDValidity uint32 `json:"uidValidity"`
	ModSeq      uint64 `json:"modSeq"`
}

func rebuildOfficialSpaces(ctx context.Context, source officialProjectionSource, destination string) (Report, error) {
	report := Report{Version: 3}
	if ctx == nil || source == nil || !filepath.IsAbs(destination) {
		return report, errors.New("projection: source and absolute destination are required")
	}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	if err := refuseExistingOfficialProjectionArtifacts(destination); err != nil {
		return report, err
	}
	if err := source.ValidateSeal(); err != nil {
		return report, fmt.Errorf("projection: invalid official source: %w", err)
	}

	summary := source.Summary()
	report.Target = repository.Target{
		ProviderOrigin: summary.Target.Origin,
		SpaceURI:       summary.Target.SpaceURI,
		RepoDID:        summary.Target.RepoDID,
		Epoch:          summary.Target.Epoch,
	}
	if err := validateOfficialSummary(summary, report.Target); err != nil {
		return report, err
	}
	graph, err := buildOfficialProjectionGraph(summary, source.Folders(), source.MessageStates())
	if err != nil {
		return report, err
	}
	report.Folders = len(graph.folders)
	report.States = graph.liveStates
	report.Tombstones = graph.messageDeletes

	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return report, err
	}
	if err := refuseExistingOfficialProjectionArtifacts(destination); err != nil {
		return report, err
	}
	file, err := os.OpenFile(destination, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return report, fmt.Errorf("projection: create destination: %w", err)
	}
	created := true
	complete := false
	var db *sql.DB
	defer func() {
		if db != nil {
			_ = db.Close()
		}
		if created && !complete {
			removeProjectionArtifacts(destination)
		}
	}()
	if err := file.Close(); err != nil {
		return report, fmt.Errorf("projection: close new destination: %w", err)
	}

	destinationURL := (&url.URL{Scheme: "file", Path: filepath.ToSlash(destination)}).String()
	db, err = sql.Open("sqlite", destinationURL+"?mode=rw&_pragma=busy_timeout(5000)")
	if err != nil {
		return report, fmt.Errorf("projection: open destination: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := createSchema(db, report.Target); err != nil {
		return report, fmt.Errorf("projection: create official schema: %w", err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return report, fmt.Errorf("projection: begin official projection: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	manifest := officialManifest{Version: 1, Target: report.Target}
	for _, folder := range graph.folders {
		if _, err := tx.ExecContext(ctx, `INSERT INTO folders(rkey,name,role,uid_validity,revision,updated_at) VALUES(?,?,?,?,?,?)`,
			folder.state.FolderID, folder.state.Name, folder.state.Role, folder.uidValidity, folder.state.Height, ""); err != nil {
			return report, fmt.Errorf("projection: insert official folder: %w", err)
		}
		manifest.Folders = append(manifest.Folders, officialManifestFolder{
			FolderID: folder.state.FolderID, Name: folder.state.Name, Role: folder.state.Role,
			UIDValidity: folder.uidValidity, Revision: folder.state.Height,
		})
	}

	seenVersions := make(map[string]struct{}, summary.MessageVersions)
	seenSelected := make(map[string]struct{}, len(graph.selected))
	visitErr := source.VisitMessages(ctx, func(version mailboxstate.MessageVersion, raw []byte) error {
		if _, duplicate := seenVersions[version.RKey]; duplicate {
			return fmt.Errorf("%w: duplicate immutable message version", mailbox.ErrIntegrity)
		}
		seenVersions[version.RKey] = struct{}{}
		if err := mailbox.ValidateStoredMessage(report.Target.RepoDID, version.RKey, version.Record, raw); err != nil {
			return err
		}
		selected, ok := graph.selected[version.RKey]
		if !ok {
			return nil
		}
		if version.Record.LogicalMessageID != selected.state.LogicalMessageID {
			return fmt.Errorf("%w: selected version has wrong logical identity", mailbox.ErrIntegrity)
		}
		if err := insertOfficialMessage(ctx, tx, version, raw, selected, graph.folderByID, &manifest); err != nil {
			return err
		}
		seenSelected[version.RKey] = struct{}{}
		report.TotalBytes += int64(len(raw))
		return nil
	})
	if visitErr != nil {
		return report, fmt.Errorf("projection: visit official messages: %w", visitErr)
	}
	if len(seenVersions) != summary.MessageVersions || len(seenSelected) != len(graph.selected) {
		return report, fmt.Errorf("%w: official message inventory is incomplete", mailbox.ErrIntegrity)
	}
	if err := source.ValidateSeal(); err != nil {
		return report, fmt.Errorf("projection: official source changed during rebuild: %w", err)
	}
	report.Messages = len(seenSelected)
	sort.Slice(manifest.Messages, func(left, right int) bool {
		return manifest.Messages[left].RKey < manifest.Messages[right].RKey
	})
	report.ManifestSHA256, err = officialSemanticManifest(manifest)
	if err != nil {
		return report, err
	}
	if err := tx.Commit(); err != nil {
		return report, fmt.Errorf("projection: commit official projection: %w", err)
	}
	if err := db.Close(); err != nil {
		return report, fmt.Errorf("projection: close official projection: %w", err)
	}
	db = nil
	if err := os.Chmod(destination, 0o600); err != nil {
		return report, fmt.Errorf("projection: secure official projection: %w", err)
	}
	complete = true
	created = false
	return report, nil
}

func validateOfficialSummary(summary mailboxstate.ContentVerificationSummary, target repository.Target) error {
	if target.Epoch != officialspaces.PinnedEpoch || target.ValidateFor(target.RepoDID) != nil ||
		summary.Revision == "" || !validOfficialDigest(summary.SnapshotID) ||
		!validOfficialDigest(summary.ManifestSHA256) || summary.MessageVersions < 0 ||
		summary.UniqueBlobs < 0 || summary.TotalBytes < 0 {
		return errors.New("projection: invalid official source summary")
	}
	return nil
}

func buildOfficialProjectionGraph(
	summary mailboxstate.ContentVerificationSummary,
	folders []mailboxstate.ReducedFolderState,
	states []mailboxstate.ReducedState,
) (officialProjectionGraph, error) {
	graph := officialProjectionGraph{
		folderByID: make(map[string]officialProjectionFolder, len(folders)),
		selected:   make(map[string]*officialProjectionState),
	}
	liveNames := make(map[string]string, len(folders))
	for _, state := range folders {
		if state.FolderID == "" || state.SnapshotID != summary.SnapshotID || state.Name == "" || state.Height == 0 ||
			!validOfficialDigest(state.StateDigest) {
			return graph, fmt.Errorf("%w: invalid reduced folder", mailbox.ErrIntegrity)
		}
		if _, duplicate := graph.folderByID[state.FolderID]; duplicate {
			return graph, fmt.Errorf("%w: duplicate reduced folder", mailbox.ErrIntegrity)
		}
		folder := officialProjectionFolder{
			state: state, uidValidity: mailbox.StableFolderUIDValidity(summary.Target.RepoDID, state.FolderID),
		}
		graph.folderByID[state.FolderID] = folder
		if state.Tombstone {
			continue
		}
		foldedName := strings.ToLower(state.Name)
		if prior, duplicate := liveNames[foldedName]; duplicate && prior != state.FolderID {
			return graph, fmt.Errorf("%w: duplicate live folder name", mailbox.ErrIntegrity)
		}
		liveNames[foldedName] = state.FolderID
		graph.folders = append(graph.folders, folder)
	}
	sort.Slice(graph.folders, func(left, right int) bool {
		return graph.folders[left].state.FolderID < graph.folders[right].state.FolderID
	})

	seenLogical := make(map[string]struct{}, len(states))
	byFolder := make(map[string][]*officialProjectionState, len(graph.folders))
	for _, state := range states {
		if !validOfficialDigest(state.LogicalMessageID) || state.SnapshotID != summary.SnapshotID ||
			!validOfficialDigest(state.StateDigest) || state.Height == 0 {
			return graph, fmt.Errorf("%w: invalid reduced message state", mailbox.ErrIntegrity)
		}
		if _, duplicate := seenLogical[state.LogicalMessageID]; duplicate {
			return graph, fmt.Errorf("%w: duplicate reduced message state", mailbox.ErrIntegrity)
		}
		seenLogical[state.LogicalMessageID] = struct{}{}
		if state.Tombstone {
			graph.messageDeletes++
			continue
		}
		if !validOfficialDigest(state.Version) || len(state.MailboxIDs) == 0 {
			return graph, fmt.Errorf("%w: live message has no selected version or folder", mailbox.ErrIntegrity)
		}
		projected := &officialProjectionState{state: state, uids: make(map[string]uint32, len(state.MailboxIDs))}
		projected.state.MailboxIDs = append([]string(nil), state.MailboxIDs...)
		sort.Strings(projected.state.MailboxIDs)
		projected.state.Keywords = append([]string{}, state.Keywords...)
		sort.Strings(projected.state.Keywords)
		for index, folderID := range projected.state.MailboxIDs {
			if index > 0 && folderID == projected.state.MailboxIDs[index-1] {
				return graph, fmt.Errorf("%w: duplicate message folder membership", mailbox.ErrIntegrity)
			}
			folder, found := graph.folderByID[folderID]
			if !found || folder.state.Tombstone {
				return graph, fmt.Errorf("%w: message references unavailable folder", mailbox.ErrIntegrity)
			}
			byFolder[folderID] = append(byFolder[folderID], projected)
		}
		if _, duplicate := graph.selected[state.Version]; duplicate {
			return graph, fmt.Errorf("%w: immutable version selected twice", mailbox.ErrIntegrity)
		}
		graph.selected[state.Version] = projected
		graph.liveStates++
	}
	for folderID, projected := range byFolder {
		sort.Slice(projected, func(left, right int) bool {
			if projected[left].state.LogicalMessageID == projected[right].state.LogicalMessageID {
				return projected[left].state.Version < projected[right].state.Version
			}
			return projected[left].state.LogicalMessageID < projected[right].state.LogicalMessageID
		})
		for index, state := range projected {
			state.uids[folderID] = uint32(index + 1)
		}
	}
	return graph, nil
}

func insertOfficialMessage(
	ctx context.Context,
	tx *sql.Tx,
	version mailboxstate.MessageVersion,
	raw []byte,
	state *officialProjectionState,
	folderByID map[string]officialProjectionFolder,
	manifest *officialManifest,
) error {
	keywords, err := json.Marshal(state.state.Keywords)
	if err != nil {
		return err
	}
	normalizedReferences := append([]string{}, version.Record.References...)
	references, err := json.Marshal(normalizedReferences)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO messages(
rkey,raw,sha256,size,keywords_json,delete_pending,
source_message_id,message_date,in_reply_to,references_json
) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		version.RKey, raw, version.Record.SHA256, version.Record.Size, string(keywords), state.state.DeletePending,
		version.Record.SourceMessageID, version.Record.MessageDate, version.Record.InReplyTo, string(references)); err != nil {
		return fmt.Errorf("projection: insert official message: %w", err)
	}

	messageManifest := officialManifestMessage{
		RKey: version.RKey, SHA256: version.Record.SHA256, Size: version.Record.Size,
		Keywords: append([]string{}, state.state.Keywords...), DeletePending: state.state.DeletePending,
		SourceMessageID: version.Record.SourceMessageID, MessageDate: version.Record.MessageDate,
		InReplyTo: version.Record.InReplyTo, References: normalizedReferences,
	}
	for _, folderID := range state.state.MailboxIDs {
		folder := folderByID[folderID]
		uid := state.uids[folderID]
		if _, err := tx.ExecContext(ctx, `INSERT INTO message_mailboxes(rkey,mailbox,uid,uid_validity,modseq) VALUES(?,?,?,?,?)`,
			version.RKey, folder.state.Name, uid, folder.uidValidity, state.state.Height); err != nil {
			return fmt.Errorf("projection: insert official message membership: %w", err)
		}
		messageManifest.Memberships = append(messageManifest.Memberships, officialManifestMembership{
			FolderID: folderID, Mailbox: folder.state.Name, UID: uid,
			UIDValidity: folder.uidValidity, ModSeq: state.state.Height,
		})
	}
	manifest.Messages = append(manifest.Messages, messageManifest)
	return nil
}

func officialSemanticManifest(manifest officialManifest) (string, error) {
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return "", fmt.Errorf("projection: encode semantic manifest: %w", err)
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte("comail-official-sqlite-projection-v1\x00"))
	_, _ = digest.Write(encoded)
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func validOfficialDigest(value string) bool {
	if len(value) != len("sha256-")+sha256.Size*2 || !strings.HasPrefix(value, "sha256-") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256-"))
	return err == nil
}

func removeProjectionArtifacts(destination string) {
	for _, suffix := range []string{"-journal", "-wal", "-shm", ""} {
		_ = os.Remove(destination + suffix)
	}
}

func refuseExistingOfficialProjectionArtifacts(destination string) error {
	for _, suffix := range []string{"", "-journal", "-wal", "-shm"} {
		artifact := destination + suffix
		if _, err := os.Lstat(artifact); err == nil {
			return fmt.Errorf("projection: destination artifact exists: %w", os.ErrExist)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}
