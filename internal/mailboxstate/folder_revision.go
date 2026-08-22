package mailboxstate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/comail-atproto/comail-space-host/internal/mailbox"
)

const (
	FolderRevisionCollection  = mailbox.FolderRevisionCollection
	FolderOperationCollection = mailbox.FolderOperationCollection
	maxFolderCount            = 4096
)

var ErrFolderNameCollision = fmt.Errorf("%w: live folder name collision", ErrInvalidReference)

var standardFolderRoles = map[string]struct{}{
	"inbox": {}, "archive": {}, "drafts": {}, "sent": {},
	"junk": {}, "trash": {}, "important": {},
}

var standardFolderNames = map[string]string{
	"inbox": "Inbox", "archive": "Archive", "drafts": "Drafts", "sent": "Sent",
	"junk": "Junk", "trash": "Trash", "important": "Important",
}

type FolderRevisionRecord struct {
	Type        string   `json:"$type"`
	FolderID    string   `json:"folderId"`
	OperationID string   `json:"operationId"`
	Parents     []string `json:"parents"`
	Revision    uint64   `json:"revision"`
	Name        string   `json:"name,omitempty"`
	Role        string   `json:"role,omitempty"`
	Tombstone   bool     `json:"tombstone,omitempty"`
	Merge       bool     `json:"merge,omitempty"`
	CreatedAt   string   `json:"createdAt"`
}

type FolderStateRevision struct {
	RKey   string               `json:"rkey"`
	Record FolderRevisionRecord `json:"record"`
}

type FolderOperationClaimRecord struct {
	Type         string `json:"$type"`
	FolderID     string `json:"folderId"`
	OperationID  string `json:"operationId"`
	RevisionRKey string `json:"revisionRkey"`
}

type FolderOperationClaim struct {
	RKey   string                     `json:"rkey"`
	Record FolderOperationClaimRecord `json:"record"`
}

// VerifiedFolderSnapshot is a resource-scoped opaque capability created only
// while reducing a complete source-authenticated repository inventory. It has
// no public constructor or caller-supplied CAR path.
type VerifiedFolderSnapshot struct {
	snapshotID      string
	folderID        string
	revisionCount   int
	operationClaims map[string]string
	seal            [sha256.Size]byte
}

// VerifiedFolderSetSnapshot binds a complete set of reduced folder states to
// one source-authenticated repository snapshot. It is intentionally opaque and
// has no constructor outside this package.
type VerifiedFolderSetSnapshot struct {
	snapshotID   string
	repoDID      string
	folderCount  int
	stateDigests map[string]string
	seal         [sha256.Size]byte
}

type ReducedFolderState struct {
	FolderID      string   `json:"folderId"`
	SnapshotID    string   `json:"snapshotId"`
	Name          string   `json:"name"`
	Role          string   `json:"role,omitempty"`
	Tombstone     bool     `json:"tombstone"`
	Heads         []string `json:"heads"`
	HeadsDigest   string   `json:"headsDigest"`
	StateDigest   string   `json:"stateDigest"`
	Height        uint64   `json:"height"`
	RevisionCount int      `json:"revisionCount"`
}

func DecodeFolderRevisionRecord(encoded []byte) (FolderRevisionRecord, error) {
	if len(encoded) == 0 || len(encoded) > maxRevisionRecordBytes {
		return FolderRevisionRecord{}, ErrResourceLimit
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var record FolderRevisionRecord
	if err := decoder.Decode(&record); err != nil {
		return FolderRevisionRecord{}, fmt.Errorf("%w: decode folder revision: %v", ErrInvalidRevision, err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return FolderRevisionRecord{}, err
	}
	return record, nil
}

func DecodeFolderOperationClaimRecord(encoded []byte) (FolderOperationClaimRecord, error) {
	if len(encoded) == 0 || len(encoded) > maxRevisionRecordBytes {
		return FolderOperationClaimRecord{}, ErrResourceLimit
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var record FolderOperationClaimRecord
	if err := decoder.Decode(&record); err != nil {
		return FolderOperationClaimRecord{}, fmt.Errorf("%w: decode folder operation claim: %v", ErrInvalidRevision, err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return FolderOperationClaimRecord{}, err
	}
	return record, nil
}

func CanonicalFolderRevisionBytes(record FolderRevisionRecord) ([]byte, error) {
	if len(record.Type) > maxIdentifierBytes || len(record.FolderID) > maxIdentifierBytes ||
		len(record.OperationID) > maxOperationIDBytes || len(record.Parents) > maxParents ||
		len(record.Name) > 255 || len(record.Role) > 64 || len(record.CreatedAt) > maxIdentifierBytes {
		return nil, ErrResourceLimit
	}
	for _, value := range []string{record.Type, record.FolderID, record.OperationID, record.Name, record.Role, record.CreatedAt} {
		if !utf8.ValidString(value) {
			return nil, ErrInvalidRevision
		}
	}
	for _, parent := range record.Parents {
		if len(parent) > maxIdentifierBytes {
			return nil, ErrResourceLimit
		}
		if !utf8.ValidString(parent) {
			return nil, ErrInvalidRevision
		}
	}
	var encoded canonicalWriter
	encoded.raw("comail-folder-state-revision-canonical-v1\x00")
	encoded.string(record.Type)
	encoded.string(record.FolderID)
	encoded.string(record.OperationID)
	encoded.strings(record.Parents)
	encoded.uint64(record.Revision)
	encoded.string(record.Name)
	encoded.string(record.Role)
	encoded.boolean(record.Tombstone)
	encoded.boolean(record.Merge)
	encoded.string(record.CreatedAt)
	if len(encoded.bytes) > maxRevisionRecordBytes {
		return nil, ErrResourceLimit
	}
	return encoded.bytes, nil
}

func FolderRevisionRKey(repoDID string, record FolderRevisionRecord) (string, error) {
	if !validCanonicalDID(repoDID) || !validFolderID(record.FolderID) ||
		!validIdentifier(record.OperationID, maxOperationIDBytes) {
		return "", ErrInvalidRevision
	}
	encoded, err := CanonicalFolderRevisionBytes(record)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("comail-folder-state-revision-rkey-v1\x00"))
	_, _ = hash.Write([]byte(repoDID))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(encoded)
	return "folder-state-" + hex.EncodeToString(hash.Sum(nil)), nil
}

func FolderOperationClaimRKey(repoDID, folderID, operationID string) (string, error) {
	if !validCanonicalDID(repoDID) || !validFolderID(folderID) ||
		!validIdentifier(operationID, maxOperationIDBytes) {
		return "", ErrInvalidRevision
	}
	var encoded canonicalWriter
	encoded.raw("comail-folder-state-operation-v1\x00")
	encoded.string(repoDID)
	encoded.string(folderID)
	encoded.string(operationID)
	return "folder-operation-" + strings.TrimPrefix(digestBytes(encoded.bytes), "sha256-"), nil
}

// StandardFolderID returns the deterministic identity for one canonical role.
// Custom folder IDs use the same shape but are random or migration-source
// derived and must not collide with any standard-role identity.
func StandardFolderID(repoDID, role string) (string, error) {
	if !validCanonicalDID(repoDID) {
		return "", ErrInvalidRevision
	}
	if _, ok := standardFolderRoles[role]; !ok {
		return "", ErrInvalidRevision
	}
	var encoded canonicalWriter
	encoded.raw("comail-standard-folder-v1\x00")
	encoded.string(repoDID)
	encoded.string(role)
	return "folder-" + strings.TrimPrefix(digestBytes(encoded.bytes), "sha256-"), nil
}

func NewFolderOperationClaim(repoDID string, revision FolderStateRevision) (FolderOperationClaim, error) {
	revisionRKey, err := FolderRevisionRKey(repoDID, revision.Record)
	if err != nil || revision.RKey != revisionRKey {
		return FolderOperationClaim{}, ErrInvalidRevision
	}
	claimRKey, err := FolderOperationClaimRKey(repoDID, revision.Record.FolderID, revision.Record.OperationID)
	if err != nil {
		return FolderOperationClaim{}, err
	}
	return FolderOperationClaim{RKey: claimRKey, Record: FolderOperationClaimRecord{
		Type: FolderOperationCollection, FolderID: revision.Record.FolderID,
		OperationID: revision.Record.OperationID, RevisionRKey: revision.RKey,
	}}, nil
}

func VerifyFolderOperationClaimRetry(expected, stored FolderOperationClaim) error {
	if !reflect.DeepEqual(expected, stored) {
		return ErrOperationCollision
	}
	return nil
}

func VerifyFolderRevisionRetry(repoDID string, expected, stored FolderStateRevision) error {
	expectedKey, expectedErr := FolderRevisionRKey(repoDID, expected.Record)
	storedKey, storedErr := FolderRevisionRKey(repoDID, stored.Record)
	expectedRecord, storedRecord := expected.Record, stored.Record
	expectedRecord.CreatedAt, storedRecord.CreatedAt = "", ""
	if expectedErr != nil || storedErr != nil || expected.RKey != expectedKey || stored.RKey != storedKey ||
		!reflect.DeepEqual(expectedRecord, storedRecord) {
		return ErrOperationCollision
	}
	return nil
}

func ReduceFolder(repoDID, folderID string, revisions []FolderStateRevision, snapshot VerifiedFolderSnapshot) (ReducedFolderState, error) {
	if len(revisions) > maxRevisionCount {
		return ReducedFolderState{}, ErrResourceLimit
	}
	if !validCanonicalDID(repoDID) || !validFolderID(folderID) || len(revisions) == 0 {
		return ReducedFolderState{}, ErrInvalidRevision
	}
	if !snapshot.validFor(folderID, len(revisions)) {
		return ReducedFolderState{}, ErrIncompleteSnapshot
	}

	byKey := make(map[string]FolderStateRevision, len(revisions))
	operations := make(map[string]struct{}, len(revisions))
	totalBytes := 0
	for _, event := range revisions {
		if _, duplicate := operations[event.Record.OperationID]; duplicate {
			return ReducedFolderState{}, ErrOperationCollision
		}
		if _, duplicate := byKey[event.RKey]; duplicate {
			return ReducedFolderState{}, ErrInvalidRevision
		}
		encoded, err := CanonicalFolderRevisionBytes(event.Record)
		if err != nil {
			return ReducedFolderState{}, err
		}
		totalBytes += len(encoded)
		if totalBytes > maxRevisionInventoryBytes {
			return ReducedFolderState{}, ErrResourceLimit
		}
		if err := validateFolderRevision(repoDID, folderID, event); err != nil {
			return ReducedFolderState{}, err
		}
		claim, err := NewFolderOperationClaim(repoDID, event)
		if err != nil {
			return ReducedFolderState{}, err
		}
		claimedRevision, ok := snapshot.operationClaims[claim.RKey]
		if !ok {
			return ReducedFolderState{}, ErrIncompleteSnapshot
		}
		if claimedRevision != event.RKey {
			return ReducedFolderState{}, ErrOperationCollision
		}
		byKey[event.RKey] = event
		operations[event.Record.OperationID] = struct{}{}
	}

	parented := make(map[string]struct{}, len(revisions))
	roots := 0
	for _, event := range revisions {
		if len(event.Record.Parents) == 0 {
			roots++
			if event.Record.Revision != 1 || event.Record.Name == "" || event.Record.Tombstone || event.Record.Merge {
				return ReducedFolderState{}, ErrInvalidRevision
			}
			if role, standard := standardRoleForID(repoDID, folderID); standard {
				if event.Record.Role != role || event.Record.Name != standardFolderNames[role] {
					return ReducedFolderState{}, ErrInvalidRevision
				}
			} else if event.Record.Role != "" {
				return ReducedFolderState{}, ErrInvalidRevision
			}
			continue
		}
		var maxParentRevision uint64
		for _, parentRKey := range event.Record.Parents {
			parent, ok := byKey[parentRKey]
			if !ok {
				return ReducedFolderState{}, fmt.Errorf("%w: %s", ErrMissingParent, parentRKey)
			}
			if parent.Record.Revision >= event.Record.Revision {
				return ReducedFolderState{}, ErrInvalidRevision
			}
			maxParentRevision = max(maxParentRevision, parent.Record.Revision)
			parented[parentRKey] = struct{}{}
		}
		if event.Record.Revision != maxParentRevision+1 {
			return ReducedFolderState{}, ErrInvalidRevision
		}
	}
	if roots == 0 {
		return ReducedFolderState{}, ErrInvalidRevision
	}

	events := append([]FolderStateRevision(nil), revisions...)
	slices.SortFunc(events, func(left, right FolderStateRevision) int {
		if left.Record.Revision < right.Record.Revision {
			return -1
		}
		if left.Record.Revision > right.Record.Revision {
			return 1
		}
		return compareUTF8(left.Record.OperationID, right.Record.OperationID)
	})
	causalTombstone := make(map[string]bool, len(events))
	state := ReducedFolderState{FolderID: folderID, SnapshotID: snapshot.snapshotID, RevisionCount: len(events)}
	for _, event := range events {
		parentTombstoned := false
		for _, parent := range event.Record.Parents {
			parentTombstoned = parentTombstoned || causalTombstone[parent]
		}
		if parentTombstoned && (event.Record.Name != "" || event.Record.Role != "") {
			return ReducedFolderState{}, fmt.Errorf("%w: folder mutation follows tombstone", ErrInvalidRevision)
		}
		causalTombstone[event.RKey] = parentTombstoned || event.Record.Tombstone
		state.Height = max(state.Height, event.Record.Revision)
		if event.Record.Name != "" {
			state.Name = event.Record.Name
		}
		if event.Record.Role != "" {
			state.Role = event.Record.Role
		}
		state.Tombstone = state.Tombstone || event.Record.Tombstone
	}
	for _, event := range events {
		if _, ok := parented[event.RKey]; !ok {
			state.Heads = append(state.Heads, event.RKey)
		}
	}
	sortUTF8(state.Heads)
	state.HeadsDigest = digestStringList("comail-folder-state-heads-v1\x00", state.Heads)
	state.StateDigest = digestReducedFolderState(state)
	return state, nil
}

func digestReducedFolderState(state ReducedFolderState) string {
	var digest canonicalWriter
	digest.raw("comail-folder-state-reduced-v1\x00")
	digest.string(state.FolderID)
	digest.string(state.Name)
	digest.string(state.Role)
	digest.boolean(state.Tombstone)
	digest.strings(state.Heads)
	digest.string(state.HeadsDigest)
	digest.uint64(state.Height)
	digest.uint64(uint64(state.RevisionCount))
	return digestBytes(digest.bytes)
}

// ValidateFolderSet enforces mailbox-wide projection invariants over one
// complete, authenticated snapshot. Per-folder reducers cannot detect two live
// identities that converge on the same case-insensitive path, nor prove that
// every canonical standard role is present.
func ValidateFolderSet(repoDID string, states []ReducedFolderState, snapshot VerifiedFolderSetSnapshot) error {
	if len(states) > maxFolderCount {
		return ErrResourceLimit
	}
	if !snapshot.validFor(repoDID, len(states)) {
		return ErrIncompleteSnapshot
	}

	seenIDs := make(map[string]struct{}, len(states))
	liveNames := make(map[string]string, len(states))
	standardRoles := make(map[string]struct{}, len(standardFolderRoles))
	reservedNames := make(map[string]struct{}, len(standardFolderNames))
	for _, name := range standardFolderNames {
		reservedNames[foldFolderName(name)] = struct{}{}
	}
	for _, state := range states {
		if !validFolderID(state.FolderID) || state.SnapshotID != snapshot.snapshotID ||
			!validText(state.Name, 255) || !validSHA256Identifier(state.StateDigest) ||
			state.StateDigest != digestReducedFolderState(state) {
			return ErrInvalidReference
		}
		if _, duplicate := seenIDs[state.FolderID]; duplicate {
			return ErrIncompleteSnapshot
		}
		seenIDs[state.FolderID] = struct{}{}
		if snapshot.stateDigests[state.FolderID] != state.StateDigest {
			return ErrIncompleteSnapshot
		}

		role, standard := standardRoleForID(repoDID, state.FolderID)
		if standard {
			if state.Role != role || state.Name != standardFolderNames[role] || state.Tombstone {
				return ErrInvalidReference
			}
			standardRoles[role] = struct{}{}
		} else if state.Role != "" {
			return ErrInvalidReference
		}
		if state.Tombstone {
			continue
		}
		folded := foldFolderName(state.Name)
		if !standard {
			if _, reserved := reservedNames[folded]; reserved {
				return ErrFolderNameCollision
			}
		}
		if other, duplicate := liveNames[folded]; duplicate && other != state.FolderID {
			return ErrFolderNameCollision
		}
		liveNames[folded] = state.FolderID
	}
	if len(standardRoles) != len(standardFolderRoles) {
		return ErrIncompleteSnapshot
	}
	return nil
}

func (snapshot VerifiedFolderSetSnapshot) validFor(repoDID string, folderCount int) bool {
	return validCanonicalDID(repoDID) && snapshot.repoDID == repoDID &&
		validIdentifier(snapshot.snapshotID, maxIdentifierBytes) && snapshot.folderCount == folderCount &&
		folderCount > 0 && len(snapshot.stateDigests) == folderCount &&
		snapshot.seal == snapshot.snapshotSeal()
}

func (snapshot VerifiedFolderSetSnapshot) snapshotSeal() [sha256.Size]byte {
	var encoded canonicalWriter
	encoded.raw("comail-verified-folder-set-snapshot-v1\x00")
	encoded.string(snapshot.snapshotID)
	encoded.string(snapshot.repoDID)
	encoded.uint64(uint64(snapshot.folderCount))
	keys := sortedMapKeys(snapshot.stateDigests)
	encoded.uint64(uint64(len(keys)))
	for _, key := range keys {
		encoded.string(key)
		encoded.string(snapshot.stateDigests[key])
	}
	return sha256.Sum256(encoded.bytes)
}

func foldFolderName(value string) string {
	var folded strings.Builder
	folded.Grow(len(value))
	for _, current := range value {
		canonical := current
		for candidate := unicode.SimpleFold(current); candidate != current; candidate = unicode.SimpleFold(candidate) {
			if candidate < canonical {
				canonical = candidate
			}
		}
		folded.WriteRune(canonical)
	}
	return folded.String()
}

func validateFolderRevision(repoDID, folderID string, event FolderStateRevision) error {
	record := event.Record
	expectedRKey, err := FolderRevisionRKey(repoDID, record)
	if err != nil || event.RKey != expectedRKey || record.Type != FolderRevisionCollection ||
		record.FolderID != folderID || record.Parents == nil || record.Revision == 0 || record.Revision > maxPortableRevision ||
		!validIdentifier(record.OperationID, maxOperationIDBytes) || len(record.Parents) > maxParents {
		return ErrInvalidRevision
	}
	if _, err := time.Parse(time.RFC3339Nano, record.CreatedAt); err != nil || !strictlySortedFolderParents(record.Parents) {
		return ErrInvalidRevision
	}
	if record.Name != "" && !validText(record.Name, 255) {
		return ErrInvalidRevision
	}
	if !validFolderID(folderID) {
		return ErrInvalidRevision
	}
	role, standard := standardRoleForID(repoDID, folderID)
	if standard {
		if record.Tombstone || (record.Role != "" && record.Role != role) ||
			(len(record.Parents) > 0 && (record.Name != "" || record.Role != "")) {
			return ErrInvalidRevision
		}
	} else if record.Role != "" {
		return ErrInvalidRevision
	}
	mutates := record.Name != "" || record.Role != "" || record.Tombstone
	if record.Merge == mutates || (record.Merge && len(record.Parents) < 2) || (record.Tombstone && (record.Name != "" || record.Role != "")) {
		return ErrInvalidRevision
	}
	return nil
}

func standardRoleForID(repoDID, folderID string) (string, bool) {
	for role := range standardFolderRoles {
		candidate, err := StandardFolderID(repoDID, role)
		if err == nil && candidate == folderID {
			return role, true
		}
	}
	return "", false
}

func validFolderID(value string) bool {
	if len(value) != len("folder-")+sha256.Size*2 || !strings.HasPrefix(value, "folder-") {
		return false
	}
	decoded := strings.TrimPrefix(value, "folder-")
	_, err := hex.DecodeString(decoded)
	return err == nil && decoded == strings.ToLower(decoded)
}

func strictlySortedFolderParents(values []string) bool {
	for index, value := range values {
		if !validFolderStateRKey(value) || (index > 0 && compareUTF8(values[index-1], value) >= 0) {
			return false
		}
	}
	return true
}

func validFolderStateRKey(value string) bool {
	if len(value) != len("folder-state-")+sha256.Size*2 || !strings.HasPrefix(value, "folder-state-") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "folder-state-"))
	return err == nil
}

func (snapshot VerifiedFolderSnapshot) validFor(folderID string, revisionCount int) bool {
	return validIdentifier(snapshot.snapshotID, maxIdentifierBytes) && snapshot.folderID == folderID &&
		snapshot.revisionCount == revisionCount && revisionCount > 0 &&
		len(snapshot.operationClaims) == revisionCount && snapshot.seal == snapshot.snapshotSeal()
}

func (snapshot VerifiedFolderSnapshot) snapshotSeal() [sha256.Size]byte {
	var encoded canonicalWriter
	encoded.raw("comail-verified-folder-snapshot-v1\x00")
	encoded.string(snapshot.snapshotID)
	encoded.string(snapshot.folderID)
	encoded.uint64(uint64(snapshot.revisionCount))
	claimKeys := sortedMapKeys(snapshot.operationClaims)
	encoded.uint64(uint64(len(claimKeys)))
	for _, key := range claimKeys {
		encoded.string(key)
		encoded.string(snapshot.operationClaims[key])
	}
	return sha256.Sum256(encoded.bytes)
}
