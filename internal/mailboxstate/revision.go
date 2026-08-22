package mailboxstate

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/comail-atproto/comail-space-host/internal/mailbox"
)

const (
	MessageStateRevisionCollection         = mailbox.MessageStateRevisionCollection
	MessageStateOperationCollection        = mailbox.MessageStateOperationCollection
	maxParents                             = 64
	maxKeywords                            = 128
	maxMailboxes                           = 32
	maxIdentifierBytes                     = 512
	maxOperationIDBytes                    = 128
	maxRevisionCount                       = 4096
	maxRevisionRecordBytes                 = 128 * 1024
	maxRevisionInventoryBytes              = 8 * 1024 * 1024
	maxPortableRevision             uint64 = 9_007_199_254_740_991
)

var (
	ErrInvalidRevision    = errors.New("mailboxstate: invalid append-only revision")
	ErrMissingParent      = errors.New("mailboxstate: missing causal parent")
	ErrInvalidReference   = errors.New("mailboxstate: invalid inventory reference")
	ErrOperationCollision = errors.New("mailboxstate: operation id collision")
	ErrIncompleteSnapshot = errors.New("mailboxstate: incomplete repository snapshot")
	ErrResourceLimit      = errors.New("mailboxstate: revision resource limit exceeded")
)

// KeywordAssignment is a per-key register assignment. Resolving keywords
// independently prevents concurrent changes to unrelated flags from
// overwriting one another.
type KeywordAssignment struct {
	Name    string `json:"name"`
	Present bool   `json:"present"`
}

// RevisionRecord is an immutable, create-only mailbox-state event. CreatedAt
// is audit metadata only and never participates in conflict ordering.
type RevisionRecord struct {
	Type             string              `json:"$type"`
	LogicalMessageID string              `json:"logicalMessageId"`
	OperationID      string              `json:"operationId"`
	Parents          []string            `json:"parents"`
	Revision         uint64              `json:"revision"`
	Version          string              `json:"version,omitempty"`
	MailboxIDs       []string            `json:"mailboxIds,omitempty"`
	Keywords         []KeywordAssignment `json:"keywords,omitempty"`
	DeletePending    *bool               `json:"deletePending,omitempty"`
	Tombstone        bool                `json:"tombstone,omitempty"`
	Merge            bool                `json:"merge,omitempty"`
	CreatedAt        string              `json:"createdAt"`
}

type StateRevision struct {
	RKey   string         `json:"rkey"`
	Record RevisionRecord `json:"record"`
}

// OperationClaim is created atomically with its revision. Its rkey depends
// only on repository, logical message, and operation ID, so a reconstructed
// retry with changed time or payload collides before it can poison the
// append-only revision stream.
type OperationClaimRecord struct {
	Type             string `json:"$type"`
	LogicalMessageID string `json:"logicalMessageId"`
	OperationID      string `json:"operationId"`
	RevisionRKey     string `json:"revisionRkey"`
}

type OperationClaim struct {
	RKey   string               `json:"rkey"`
	Record OperationClaimRecord `json:"record"`
}

// VerifiedSnapshot is an opaque capability representing one authenticated,
// fully exhausted repository snapshot (for example a signature-checked commit
// and CAR). Callers outside this package cannot construct or mutate it. A
// repository verifier must bind all included maps and counts to snapshotID and
// seal the value before Reduce can consume it.
//
// There is no public constructor. The official Spaces bridge constructs this
// value only while reducing an opaque live-PDS source capability, so production
// code cannot self-assert completeness with a boolean, count, or saved CAR.
type VerifiedSnapshot struct {
	snapshotID       string
	logicalMessageID string
	revisionCount    int
	operationClaims  map[string]string
	versions         map[string]string
	folders          map[string]verifiedFolderReference
	seal             [sha256.Size]byte
}

type verifiedFolderReference struct {
	stateDigest string
	tombstone   bool
}

// DecodeRevisionRecord is the only supported wire decoder. Strict decoding is
// part of the payload commitment: silently dropped unknown properties would
// otherwise escape StateRevisionRKey verification.
func DecodeRevisionRecord(encoded []byte) (RevisionRecord, error) {
	if len(encoded) == 0 || len(encoded) > maxRevisionRecordBytes {
		return RevisionRecord{}, ErrResourceLimit
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var record RevisionRecord
	if err := decoder.Decode(&record); err != nil {
		return RevisionRecord{}, fmt.Errorf("%w: decode revision: %v", ErrInvalidRevision, err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return RevisionRecord{}, err
	}
	return record, nil
}

func DecodeOperationClaimRecord(encoded []byte) (OperationClaimRecord, error) {
	if len(encoded) == 0 || len(encoded) > maxRevisionRecordBytes {
		return OperationClaimRecord{}, ErrResourceLimit
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var record OperationClaimRecord
	if err := decoder.Decode(&record); err != nil {
		return OperationClaimRecord{}, fmt.Errorf("%w: decode operation claim: %v", ErrInvalidRevision, err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return OperationClaimRecord{}, err
	}
	return record, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing JSON value", ErrInvalidRevision)
	}
	return nil
}

type ReducedState struct {
	LogicalMessageID string   `json:"logicalMessageId"`
	SnapshotID       string   `json:"snapshotId"`
	Version          string   `json:"version"`
	MailboxIDs       []string `json:"mailboxIds"`
	Keywords         []string `json:"keywords"`
	DeletePending    bool     `json:"deletePending"`
	Tombstone        bool     `json:"tombstone"`
	Heads            []string `json:"heads"`
	HeadsDigest      string   `json:"headsDigest"`
	StateDigest      string   `json:"stateDigest"`
	Height           uint64   `json:"height"`
	RevisionCount    int      `json:"revisionCount"`
}

// CanonicalRevisionBytes returns the provider-neutral semantic commitment for
// a revision. The format is deliberately simpler than a language's JSON
// encoder: an ASCII domain/version prefix followed by fields in the order
// below. Strings are UTF-8 prefixed by unsigned LEB128 byte length; arrays are
// prefixed by unsigned LEB128 item count; integers are unsigned LEB128; booleans
// are one byte (0 or 1); optional values use an explicit presence byte. This is
// the interoperability contract used by every provider to derive the rkey.
func CanonicalRevisionBytes(record RevisionRecord) ([]byte, error) {
	if len(record.Type) > maxIdentifierBytes || len(record.LogicalMessageID) > maxIdentifierBytes ||
		len(record.OperationID) > maxOperationIDBytes || len(record.Parents) > maxParents ||
		len(record.Version) > maxIdentifierBytes || len(record.MailboxIDs) > maxMailboxes ||
		len(record.Keywords) > maxKeywords || len(record.CreatedAt) > maxIdentifierBytes {
		return nil, ErrResourceLimit
	}
	if !utf8.ValidString(record.Type) || !utf8.ValidString(record.LogicalMessageID) ||
		!utf8.ValidString(record.OperationID) || !utf8.ValidString(record.Version) ||
		!utf8.ValidString(record.CreatedAt) {
		return nil, ErrInvalidRevision
	}
	for _, value := range record.Parents {
		if len(value) > maxIdentifierBytes {
			return nil, ErrResourceLimit
		}
		if !utf8.ValidString(value) {
			return nil, ErrInvalidRevision
		}
	}
	for _, value := range record.MailboxIDs {
		if len(value) > maxIdentifierBytes {
			return nil, ErrResourceLimit
		}
		if !utf8.ValidString(value) {
			return nil, ErrInvalidRevision
		}
	}
	for _, keyword := range record.Keywords {
		if len(keyword.Name) > 255 {
			return nil, ErrResourceLimit
		}
		if !utf8.ValidString(keyword.Name) {
			return nil, ErrInvalidRevision
		}
	}

	var encoded canonicalWriter
	encoded.raw("comail-message-state-revision-canonical-v1\x00")
	encoded.string(record.Type)
	encoded.string(record.LogicalMessageID)
	encoded.string(record.OperationID)
	encoded.strings(record.Parents)
	encoded.uint64(record.Revision)
	encoded.string(record.Version)
	if record.MailboxIDs == nil {
		encoded.byte(0)
	} else {
		encoded.byte(1)
		encoded.strings(record.MailboxIDs)
	}
	encoded.uint64(uint64(len(record.Keywords)))
	for _, keyword := range record.Keywords {
		encoded.string(keyword.Name)
		encoded.boolean(keyword.Present)
	}
	switch {
	case record.DeletePending == nil:
		encoded.byte(0)
	case !*record.DeletePending:
		encoded.byte(1)
	default:
		encoded.byte(2)
	}
	encoded.boolean(record.Tombstone)
	encoded.boolean(record.Merge)
	encoded.string(record.CreatedAt)
	if len(encoded.bytes) > maxRevisionRecordBytes {
		return nil, ErrResourceLimit
	}
	return encoded.bytes, nil
}

// StateRevisionRKey commits to the complete canonical semantic event and exact
// author repository. Rewriting any event field under the same key is detected
// during every rebuild. The operation ID remains inside the commitment so an
// exact retry derives the same key.
func StateRevisionRKey(repoDID string, record RevisionRecord) (string, error) {
	if !validCanonicalDID(repoDID) || !validSHA256Identifier(record.LogicalMessageID) ||
		!validIdentifier(record.OperationID, maxOperationIDBytes) {
		return "", ErrInvalidRevision
	}
	encoded, err := CanonicalRevisionBytes(record)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("comail-message-state-revision-rkey-v1\x00"))
	_, _ = hash.Write([]byte(repoDID))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(encoded)
	return "state-" + hex.EncodeToString(hash.Sum(nil)), nil
}

func OperationClaimRKey(repoDID, logicalMessageID, operationID string) (string, error) {
	if !validCanonicalDID(repoDID) || !validSHA256Identifier(logicalMessageID) ||
		!validIdentifier(operationID, maxOperationIDBytes) {
		return "", ErrInvalidRevision
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("comail-message-state-operation-v1\x00"))
	_, _ = hash.Write([]byte(repoDID))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(logicalMessageID))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(operationID))
	return "operation-" + hex.EncodeToString(hash.Sum(nil)), nil
}

func NewOperationClaim(repoDID string, revision StateRevision) (OperationClaim, error) {
	revisionRKey, err := StateRevisionRKey(repoDID, revision.Record)
	if err != nil || revision.RKey != revisionRKey {
		return OperationClaim{}, ErrInvalidRevision
	}
	claimRKey, err := OperationClaimRKey(
		repoDID, revision.Record.LogicalMessageID, revision.Record.OperationID,
	)
	if err != nil {
		return OperationClaim{}, err
	}
	return OperationClaim{
		RKey: claimRKey,
		Record: OperationClaimRecord{
			Type: MessageStateOperationCollection, LogicalMessageID: revision.Record.LogicalMessageID,
			OperationID: revision.Record.OperationID, RevisionRKey: revision.RKey,
		},
	}, nil
}

func VerifyOperationClaimRetry(expected, stored OperationClaim) error {
	if !reflect.DeepEqual(expected, stored) {
		return ErrOperationCollision
	}
	return nil
}

// VerifyRevisionRetry accepts a semantic lost-response replay and rejects a
// changed payload that reuses the same operation ID. CreatedAt is assigned once
// by the successful writer and is audit metadata, so reconstructing an
// otherwise identical retry with a new timestamp returns the stored result.
func VerifyRevisionRetry(repoDID string, expected, stored StateRevision) error {
	expectedKey, expectedErr := StateRevisionRKey(repoDID, expected.Record)
	storedKey, storedErr := StateRevisionRKey(repoDID, stored.Record)
	expectedRecord, storedRecord := expected.Record, stored.Record
	expectedRecord.CreatedAt, storedRecord.CreatedAt = "", ""
	if expectedErr != nil || storedErr != nil || expected.RKey != expectedKey || stored.RKey != storedKey ||
		!reflect.DeepEqual(expectedRecord, storedRecord) {
		return ErrOperationCollision
	}
	return nil
}

// Reduce validates and deterministically reduces one complete revision
// inventory. Only an opaque snapshot sealed by this package's repository
// verifier is accepted: a parent-closed prefix is not evidence of the current
// repository state.
func Reduce(repoDID, logicalMessageID string, revisions []StateRevision, inventory VerifiedSnapshot) (ReducedState, error) {
	if len(revisions) > maxRevisionCount {
		return ReducedState{}, ErrResourceLimit
	}
	if !validCanonicalDID(repoDID) || !validSHA256Identifier(logicalMessageID) || len(revisions) == 0 {
		return ReducedState{}, ErrInvalidRevision
	}
	if !inventory.validFor(logicalMessageID, len(revisions)) {
		return ReducedState{}, ErrIncompleteSnapshot
	}

	byKey := make(map[string]StateRevision, len(revisions))
	operations := make(map[string]struct{}, len(revisions))
	totalBytes := 0
	for _, event := range revisions {
		if _, duplicate := operations[event.Record.OperationID]; duplicate {
			return ReducedState{}, ErrOperationCollision
		}
		if _, duplicate := byKey[event.RKey]; duplicate {
			return ReducedState{}, fmt.Errorf("%w: duplicate rkey", ErrInvalidRevision)
		}
		encoded, err := CanonicalRevisionBytes(event.Record)
		if err != nil {
			return ReducedState{}, fmt.Errorf("%w: encode revision", ErrInvalidRevision)
		}
		if len(encoded) > maxRevisionRecordBytes {
			return ReducedState{}, ErrResourceLimit
		}
		totalBytes += len(encoded)
		if totalBytes > maxRevisionInventoryBytes {
			return ReducedState{}, ErrResourceLimit
		}
		if err := validateRevision(repoDID, logicalMessageID, event, inventory); err != nil {
			return ReducedState{}, err
		}
		claim, err := NewOperationClaim(repoDID, event)
		if err != nil {
			return ReducedState{}, err
		}
		claimedRevision, ok := inventory.operationClaims[claim.RKey]
		if !ok {
			return ReducedState{}, ErrIncompleteSnapshot
		}
		if claimedRevision != event.RKey {
			return ReducedState{}, ErrOperationCollision
		}
		byKey[event.RKey] = event
		operations[event.Record.OperationID] = struct{}{}
	}
	if len(inventory.operationClaims) != len(revisions) {
		return ReducedState{}, ErrIncompleteSnapshot
	}

	parented := make(map[string]struct{}, len(revisions))
	roots := 0
	for _, event := range revisions {
		if len(event.Record.Parents) == 0 {
			roots++
			if event.Record.Revision != 1 || event.Record.Version == "" || event.Record.MailboxIDs == nil {
				return ReducedState{}, fmt.Errorf("%w: invalid initial revision", ErrInvalidRevision)
			}
			continue
		}
		var maxParentRevision uint64
		for _, parentKey := range event.Record.Parents {
			parent, ok := byKey[parentKey]
			if !ok {
				return ReducedState{}, fmt.Errorf("%w: %s", ErrMissingParent, parentKey)
			}
			if parent.Record.Revision >= event.Record.Revision {
				return ReducedState{}, fmt.Errorf("%w: non-causal parent", ErrInvalidRevision)
			}
			maxParentRevision = max(maxParentRevision, parent.Record.Revision)
			parented[parentKey] = struct{}{}
		}
		if event.Record.Revision != maxParentRevision+1 {
			return ReducedState{}, fmt.Errorf("%w: revision height mismatch", ErrInvalidRevision)
		}
	}
	if roots != 1 {
		return ReducedState{}, fmt.Errorf("%w: expected one initial revision", ErrInvalidRevision)
	}

	events := append([]StateRevision(nil), revisions...)
	slices.SortFunc(events, func(a, b StateRevision) int {
		if a.Record.Revision < b.Record.Revision {
			return -1
		}
		if a.Record.Revision > b.Record.Revision {
			return 1
		}
		return compareUTF8(a.Record.OperationID, b.Record.OperationID)
	})

	causalTombstone := make(map[string]bool, len(events))
	for _, event := range events {
		parentTombstoned := false
		for _, parent := range event.Record.Parents {
			parentTombstoned = parentTombstoned || causalTombstone[parent]
		}
		if parentTombstoned && hasLiveAssignments(event.Record) {
			return ReducedState{}, fmt.Errorf("%w: mutation follows observed tombstone", ErrInvalidRevision)
		}
		causalTombstone[event.RKey] = parentTombstoned || event.Record.Tombstone
	}

	state := ReducedState{
		LogicalMessageID: logicalMessageID,
		SnapshotID:       inventory.snapshotID,
		RevisionCount:    len(events),
	}
	keywordState := make(map[string]bool)
	for _, event := range events {
		record := event.Record
		state.Height = max(state.Height, record.Revision)
		if record.Version != "" {
			state.Version = record.Version
		}
		if record.MailboxIDs != nil {
			state.MailboxIDs = append(state.MailboxIDs[:0], record.MailboxIDs...)
		}
		for _, assignment := range record.Keywords {
			keywordState[assignment.Name] = assignment.Present
		}
		if record.DeletePending != nil {
			state.DeletePending = *record.DeletePending
		}
		state.Tombstone = state.Tombstone || record.Tombstone
	}
	if state.Tombstone {
		state.DeletePending = false
	} else {
		for _, folder := range state.MailboxIDs {
			if reference, ok := inventory.folders[folder]; !ok || reference.tombstone || !validSHA256Identifier(reference.stateDigest) {
				return ReducedState{}, fmt.Errorf("%w: live folder", ErrInvalidReference)
			}
		}
	}
	for keyword, present := range keywordState {
		if present {
			state.Keywords = append(state.Keywords, keyword)
		}
	}
	sortUTF8(state.Keywords)
	for _, event := range events {
		if _, ok := parented[event.RKey]; !ok {
			state.Heads = append(state.Heads, event.RKey)
		}
	}
	sortUTF8(state.Heads)
	state.HeadsDigest = digestStringList("comail-message-state-heads-v1\x00", state.Heads)
	state.StateDigest = digestReducedState(state)
	return state, nil
}

func validateRevision(repoDID, logicalMessageID string, event StateRevision, inventory VerifiedSnapshot) error {
	record := event.Record
	expectedRKey, err := StateRevisionRKey(repoDID, record)
	if record.Type != MessageStateRevisionCollection ||
		record.LogicalMessageID != logicalMessageID ||
		err != nil || event.RKey != expectedRKey ||
		!validIdentifier(record.OperationID, maxOperationIDBytes) ||
		record.Parents == nil || record.Revision == 0 || record.Revision > maxPortableRevision || len(record.Parents) > maxParents {
		return ErrInvalidRevision
	}
	if _, err := time.Parse(time.RFC3339Nano, record.CreatedAt); err != nil {
		return fmt.Errorf("%w: invalid createdAt", ErrInvalidRevision)
	}
	if !strictlySortedUnique(record.Parents) {
		return fmt.Errorf("%w: parents must be canonical", ErrInvalidRevision)
	}
	for _, parent := range record.Parents {
		if !validStateRKey(parent) || parent == event.RKey {
			return ErrInvalidRevision
		}
	}
	if record.Version != "" {
		if !validSHA256Identifier(record.Version) {
			return ErrInvalidRevision
		}
		if owner, ok := inventory.versions[record.Version]; !ok || owner != logicalMessageID {
			return fmt.Errorf("%w: message version", ErrInvalidReference)
		}
	}
	if record.MailboxIDs != nil {
		if len(record.MailboxIDs) == 0 || len(record.MailboxIDs) > maxMailboxes || !strictlySortedUnique(record.MailboxIDs) {
			return ErrInvalidRevision
		}
		for _, folder := range record.MailboxIDs {
			if !validFolderID(folder) {
				return ErrInvalidRevision
			}
			// Historical assignments remain valid after a later move and folder
			// deletion. The authenticated folder-state digest proves the folder
			// existed; Reduce separately requires the live message's final
			// assignments to reference folders that are not tombstoned.
			if reference, ok := inventory.folders[folder]; !ok || !validSHA256Identifier(reference.stateDigest) {
				return fmt.Errorf("%w: folder", ErrInvalidReference)
			}
		}
	}
	if len(record.Keywords) > maxKeywords {
		return ErrInvalidRevision
	}
	previousKeyword := ""
	for _, assignment := range record.Keywords {
		if !validText(assignment.Name, 255) || compareUTF8(assignment.Name, previousKeyword) <= 0 {
			return ErrInvalidRevision
		}
		previousKeyword = assignment.Name
	}
	if record.Tombstone && hasLiveAssignments(record) {
		return fmt.Errorf("%w: tombstone cannot carry live assignments", ErrInvalidRevision)
	}
	mutates := hasLiveAssignments(record) || record.Tombstone
	if record.Merge == mutates {
		return fmt.Errorf("%w: revision must mutate or explicitly merge", ErrInvalidRevision)
	}
	if record.Merge && len(record.Parents) < 2 {
		return fmt.Errorf("%w: merge requires multiple parents", ErrInvalidRevision)
	}
	return nil
}

func hasLiveAssignments(record RevisionRecord) bool {
	return record.Version != "" || record.MailboxIDs != nil || len(record.Keywords) > 0 ||
		record.DeletePending != nil
}

func validIdentifier(value string, limit int) bool {
	return value != "" && len(value) <= limit && utf8.ValidString(value) && !strings.ContainsAny(value, " \t\r\n\x00")
}

func validCanonicalDID(value string) bool {
	did, err := syntax.ParseDID(value)
	return err == nil && did.String() == value
}

func validSHA256Identifier(value string) bool {
	if len(value) != len("sha256-")+sha256.Size*2 || !strings.HasPrefix(value, "sha256-") {
		return false
	}
	encoded := strings.TrimPrefix(value, "sha256-")
	_, err := hex.DecodeString(encoded)
	return err == nil && encoded == strings.ToLower(encoded)
}

func validText(value string, limit int) bool {
	return value != "" && len(value) <= limit && utf8.ValidString(value) && !strings.ContainsAny(value, "\r\n\x00")
}

func validStateRKey(value string) bool {
	if len(value) != len("state-")+sha256.Size*2 || !strings.HasPrefix(value, "state-") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "state-"))
	return err == nil
}

func strictlySortedUnique(values []string) bool {
	for index, value := range values {
		if !validIdentifier(value, maxIdentifierBytes) || (index > 0 && compareUTF8(values[index-1], value) >= 0) {
			return false
		}
	}
	return true
}

func (inventory VerifiedSnapshot) validFor(logicalMessageID string, revisionCount int) bool {
	if !validIdentifier(inventory.snapshotID, maxIdentifierBytes) ||
		inventory.logicalMessageID != logicalMessageID || inventory.revisionCount != revisionCount ||
		revisionCount < 1 || len(inventory.operationClaims) != revisionCount {
		return false
	}
	return inventory.seal == inventory.snapshotSeal()
}

func (inventory VerifiedSnapshot) snapshotSeal() [sha256.Size]byte {
	var encoded canonicalWriter
	encoded.raw("comail-verified-mailbox-snapshot-v1\x00")
	encoded.string(inventory.snapshotID)
	encoded.string(inventory.logicalMessageID)
	encoded.uint64(uint64(inventory.revisionCount))
	claimKeys := sortedMapKeys(inventory.operationClaims)
	encoded.uint64(uint64(len(claimKeys)))
	for _, key := range claimKeys {
		encoded.string(key)
		encoded.string(inventory.operationClaims[key])
	}
	versionKeys := sortedMapKeys(inventory.versions)
	encoded.uint64(uint64(len(versionKeys)))
	for _, key := range versionKeys {
		encoded.string(key)
		encoded.string(inventory.versions[key])
	}
	folderKeys := make([]string, 0, len(inventory.folders))
	for key := range inventory.folders {
		folderKeys = append(folderKeys, key)
	}
	sortUTF8(folderKeys)
	encoded.uint64(uint64(len(folderKeys)))
	for _, key := range folderKeys {
		encoded.string(key)
		encoded.string(inventory.folders[key].stateDigest)
		encoded.boolean(inventory.folders[key].tombstone)
	}
	return sha256.Sum256(encoded.bytes)
}

func digestStringList(domain string, values []string) string {
	var encoded canonicalWriter
	encoded.raw(domain)
	encoded.strings(values)
	return digestBytes(encoded.bytes)
}

func digestReducedState(state ReducedState) string {
	var encoded canonicalWriter
	encoded.raw("comail-message-state-reduced-v1\x00")
	encoded.string(state.LogicalMessageID)
	encoded.string(state.Version)
	encoded.strings(state.MailboxIDs)
	encoded.strings(state.Keywords)
	encoded.boolean(state.DeletePending)
	encoded.boolean(state.Tombstone)
	encoded.strings(state.Heads)
	encoded.string(state.HeadsDigest)
	encoded.uint64(state.Height)
	encoded.uint64(uint64(state.RevisionCount))
	return digestBytes(encoded.bytes)
}

func digestBytes(encoded []byte) string {
	sum := sha256.Sum256(encoded)
	return "sha256-" + hex.EncodeToString(sum[:])
}

type canonicalWriter struct {
	bytes []byte
}

func (writer *canonicalWriter) raw(value string) {
	writer.bytes = append(writer.bytes, value...)
}

func (writer *canonicalWriter) byte(value byte) {
	writer.bytes = append(writer.bytes, value)
}

func (writer *canonicalWriter) boolean(value bool) {
	if value {
		writer.byte(1)
		return
	}
	writer.byte(0)
}

func (writer *canonicalWriter) uint64(value uint64) {
	var scratch [binary.MaxVarintLen64]byte
	length := binary.PutUvarint(scratch[:], value)
	writer.bytes = append(writer.bytes, scratch[:length]...)
}

func (writer *canonicalWriter) string(value string) {
	writer.uint64(uint64(len(value)))
	writer.bytes = append(writer.bytes, value...)
}

func (writer *canonicalWriter) strings(values []string) {
	writer.uint64(uint64(len(values)))
	for _, value := range values {
		writer.string(value)
	}
}

func sortedMapKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sortUTF8(keys)
	return keys
}

// compareUTF8 defines canonical ordering as unsigned lexicographic ordering of
// well-formed UTF-8 bytes. Providers must not substitute UTF-16 code-unit or
// locale-aware ordering.
func compareUTF8(left, right string) int {
	return bytes.Compare([]byte(left), []byte(right))
}

func sortUTF8(values []string) {
	slices.SortFunc(values, compareUTF8)
}
