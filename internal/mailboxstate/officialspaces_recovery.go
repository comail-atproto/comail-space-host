package mailboxstate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/comail-atproto/comail-space-host/internal/mailbox"
	"github.com/comail-atproto/comail-space-host/internal/providers/officialspaces"
	"github.com/ipfs/go-cid"
	"github.com/ipld/go-ipld-prime/codec/dagcbor"
	"github.com/ipld/go-ipld-prime/datamodel"
	cidlink "github.com/ipld/go-ipld-prime/linking/cid"
	"github.com/ipld/go-ipld-prime/node/basicnode"
	"github.com/multiformats/go-multihash"
)

const (
	maxOfficialSourceRecords         = 100_000
	maxOfficialFolderMessageBindings = 1_000_000
)

// ErrSourceReduction is the redacted public failure for reducing an official
// Spaces source capability. Detailed reducer errors can contain record keys,
// so the public source boundary deliberately does not wrap them.
var ErrSourceReduction = errors.New("mailboxstate: official source reduction failed")

// MessageVersion is immutable message metadata from the source-authenticated
// repository. The referenced blob bytes are not part of the CAR and still
// require an exact-target fetch plus mailbox.ValidateStoredMessage before any
// projection may consume the message.
type MessageVersion struct {
	RKey   string
	CID    string
	Record mailbox.MessageRecord
}

// ReducedSourceState is an opaque, sealed reduction of one complete official
// Spaces source read. It proves repository metadata/state consistency under
// the authenticated PDS source. It is not a provider certificate, activation
// admission, or proof of the separately fetched message blob bytes.
type ReducedSourceState struct {
	target        officialspaces.Target
	revision      string
	snapshotID    string
	commitCID     string
	indexCID      string
	messages      []MessageVersion
	messageStates []ReducedState
	folders       []ReducedFolderState
	seal          [sha256.Size]byte
}

func (state *ReducedSourceState) Target() officialspaces.Target {
	if !state.valid() {
		return officialspaces.Target{}
	}
	return state.target
}

func (state *ReducedSourceState) Revision() string {
	if !state.valid() {
		return ""
	}
	return state.revision
}

func (state *ReducedSourceState) SnapshotID() string {
	if !state.valid() {
		return ""
	}
	return state.snapshotID
}

func (state *ReducedSourceState) CommitCID() string {
	if !state.valid() {
		return ""
	}
	return state.commitCID
}

func (state *ReducedSourceState) IndexCID() string {
	if !state.valid() {
		return ""
	}
	return state.indexCID
}

func (state *ReducedSourceState) Messages() []MessageVersion {
	if !state.valid() {
		return nil
	}
	return cloneMessageVersions(state.messages)
}

func (state *ReducedSourceState) MessageStates() []ReducedState {
	if !state.valid() {
		return nil
	}
	return cloneReducedStates(state.messageStates)
}

func (state *ReducedSourceState) Folders() []ReducedFolderState {
	if !state.valid() {
		return nil
	}
	return cloneReducedFolders(state.folders)
}

// ValidateSeal checks only this derived value's in-memory integrity. It does
// not contact the PDS, re-resolve the DID, verify blob bytes, or independently
// prove repository authorship.
func (state *ReducedSourceState) ValidateSeal() error {
	if !state.valid() {
		return ErrSourceReduction
	}
	return nil
}

func (state *ReducedSourceState) String() string {
	return "mailboxstate.ReducedSourceState(redacted)"
}

func (state *ReducedSourceState) GoString() string { return state.String() }

func (state *ReducedSourceState) valid() bool {
	return state != nil && state.target.Epoch == officialspaces.PinnedEpoch &&
		validCanonicalDID(state.target.RepoDID) && validSHA256Identifier(state.snapshotID) &&
		state.revision != "" && state.commitCID != "" && state.indexCID != "" &&
		len(state.folders) > 0 && state.seal == state.snapshotSeal()
}

func (state *ReducedSourceState) snapshotSeal() [sha256.Size]byte {
	digest := sha256.New()
	_, _ = io.WriteString(digest, "comail-official-source-reduction-v1\x00")
	writeSourceSealString(digest, state.target.Origin)
	writeSourceSealString(digest, state.target.SpaceURI)
	writeSourceSealString(digest, state.target.RepoDID)
	writeSourceSealString(digest, state.target.Epoch)
	writeSourceSealString(digest, state.revision)
	writeSourceSealString(digest, state.snapshotID)
	writeSourceSealString(digest, state.commitCID)
	writeSourceSealString(digest, state.indexCID)
	writeSourceSealUint64(digest, uint64(len(state.messages)))
	for _, message := range state.messages {
		writeSourceSealString(digest, message.RKey)
		writeSourceSealString(digest, message.CID)
		writeSourceSealJSON(digest, message.Record)
	}
	writeSourceSealUint64(digest, uint64(len(state.messageStates)))
	for _, reduced := range state.messageStates {
		writeSourceSealJSON(digest, reduced)
	}
	writeSourceSealUint64(digest, uint64(len(state.folders)))
	for _, folder := range state.folders {
		writeSourceSealJSON(digest, folder)
	}
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result
}

func writeSourceSealJSON(writer hash.Hash, value any) {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic("mailboxstate: impossible JSON encoding failure")
	}
	writeSourceSealUint64(writer, uint64(len(encoded)))
	_, _ = writer.Write(encoded)
}

func writeSourceSealString(writer hash.Hash, value string) {
	writeSourceSealUint64(writer, uint64(len(value)))
	_, _ = io.WriteString(writer, value)
}

func writeSourceSealUint64(writer hash.Hash, value uint64) {
	var encoded [binary.MaxVarintLen64]byte
	length := binary.PutUvarint(encoded[:], value)
	_, _ = writer.Write(encoded[:length])
}

func cloneMessageVersions(input []MessageVersion) []MessageVersion {
	result := make([]MessageVersion, len(input))
	for index, message := range input {
		result[index] = message
		result[index].Record.References = append([]string(nil), message.Record.References...)
	}
	return result
}

func cloneReducedStates(input []ReducedState) []ReducedState {
	result := make([]ReducedState, len(input))
	for index, state := range input {
		result[index] = state
		result[index].MailboxIDs = append([]string(nil), state.MailboxIDs...)
		result[index].Keywords = append([]string(nil), state.Keywords...)
		result[index].Heads = append([]string(nil), state.Heads...)
	}
	return result
}

func cloneReducedFolders(input []ReducedFolderState) []ReducedFolderState {
	result := make([]ReducedFolderState, len(input))
	for index, folder := range input {
		result[index] = folder
		result[index].Heads = append([]string(nil), folder.Heads...)
	}
	return result
}

type officialSpacesInventory struct {
	target     officialspaces.Target
	revision   string
	snapshotID string
	commitCID  string
	indexCID   string
	records    []officialspaces.SourceRecord
}

// ReduceOfficialSpacesSource is the sole production constructor for a reduced
// official Spaces repository. It accepts only the opaque source-authenticated
// live-read capability; there is intentionally no CAR, record-list, or
// snapshot-ID alternative.
func ReduceOfficialSpacesSource(ctx context.Context, source *officialspaces.SourceAuthenticatedRepository) (*ReducedSourceState, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if source == nil || source.ValidateSeal() != nil {
		return nil, ErrSourceReduction
	}
	input := officialSpacesInventory{
		target: source.Target(), revision: source.Revision(), snapshotID: source.SnapshotID(),
		commitCID: source.CommitCID(), indexCID: source.IndexCID(), records: source.Records(),
	}
	result, err := reduceOfficialSpacesInventory(ctx, input)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		return nil, ErrSourceReduction
	}
	if source.ValidateSeal() != nil {
		return nil, ErrSourceReduction
	}
	return result, nil
}

func reduceOfficialSpacesInventory(ctx context.Context, input officialSpacesInventory) (*ReducedSourceState, error) {
	if err := validateOfficialInventoryIdentity(input); err != nil {
		return nil, err
	}

	messages := make([]MessageVersion, 0)
	versionOwners := make(map[string]string)
	versionsByLogical := make(map[string]map[string]string)
	messageRevisions := make(map[string][]StateRevision)
	messageClaims := make(map[string]map[string]string)
	folderRevisions := make(map[string][]FolderStateRevision)
	folderClaims := make(map[string]map[string]string)
	seenPaths := make(map[string]struct{}, len(input.records))

	for _, source := range input.records {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		path := source.Collection + "/" + source.RKey
		if _, duplicate := seenPaths[path]; duplicate {
			return nil, ErrIncompleteSnapshot
		}
		seenPaths[path] = struct{}{}
		if err := validateOfficialSourceRecord(source); err != nil {
			return nil, err
		}

		switch source.Collection {
		case mailbox.MessageCollection:
			record, err := decodeOfficialMessage(source.Value)
			if err != nil || validateOfficialMessage(input.target.RepoDID, source.RKey, record) != nil {
				return nil, mailbox.ErrIntegrity
			}
			if _, duplicate := versionOwners[source.RKey]; duplicate {
				return nil, ErrIncompleteSnapshot
			}
			versionOwners[source.RKey] = record.LogicalMessageID
			if versionsByLogical[record.LogicalMessageID] == nil {
				versionsByLogical[record.LogicalMessageID] = make(map[string]string)
			}
			versionsByLogical[record.LogicalMessageID][source.RKey] = record.LogicalMessageID
			messages = append(messages, MessageVersion{RKey: source.RKey, CID: source.CID, Record: record})

		case MessageStateRevisionCollection:
			record, err := decodeOfficialMessageRevision(source.Value)
			if err != nil {
				return nil, err
			}
			messageRevisions[record.LogicalMessageID] = append(messageRevisions[record.LogicalMessageID], StateRevision{RKey: source.RKey, Record: record})

		case MessageStateOperationCollection:
			record, err := decodeOfficialMessageClaim(source.Value)
			if err != nil || record.Type != MessageStateOperationCollection {
				return nil, ErrInvalidRevision
			}
			expected, keyErr := OperationClaimRKey(input.target.RepoDID, record.LogicalMessageID, record.OperationID)
			if keyErr != nil || expected != source.RKey {
				return nil, ErrOperationCollision
			}
			if messageClaims[record.LogicalMessageID] == nil {
				messageClaims[record.LogicalMessageID] = make(map[string]string)
			}
			messageClaims[record.LogicalMessageID][source.RKey] = record.RevisionRKey

		case FolderRevisionCollection:
			record, err := decodeOfficialFolderRevision(source.Value)
			if err != nil {
				return nil, err
			}
			folderRevisions[record.FolderID] = append(folderRevisions[record.FolderID], FolderStateRevision{RKey: source.RKey, Record: record})

		case FolderOperationCollection:
			record, err := decodeOfficialFolderClaim(source.Value)
			if err != nil || record.Type != FolderOperationCollection {
				return nil, ErrInvalidRevision
			}
			expected, keyErr := FolderOperationClaimRKey(input.target.RepoDID, record.FolderID, record.OperationID)
			if keyErr != nil || expected != source.RKey {
				return nil, ErrOperationCollision
			}
			if folderClaims[record.FolderID] == nil {
				folderClaims[record.FolderID] = make(map[string]string)
			}
			folderClaims[record.FolderID][source.RKey] = record.RevisionRKey

		default:
			return nil, ErrIncompleteSnapshot
		}
	}

	folders, references, err := reduceOfficialFolders(ctx, input.target.RepoDID, input.snapshotID, folderRevisions, folderClaims)
	if err != nil {
		return nil, err
	}
	states, referencedVersions, err := reduceOfficialMessages(
		ctx, input.target.RepoDID, input.snapshotID, versionsByLogical,
		messageRevisions, messageClaims, references,
	)
	if err != nil {
		return nil, err
	}
	if len(states) != len(versionsByLogical) {
		return nil, ErrIncompleteSnapshot
	}
	for version := range versionOwners {
		if _, referenced := referencedVersions[version]; !referenced {
			return nil, ErrIncompleteSnapshot
		}
	}

	slices.SortFunc(messages, func(left, right MessageVersion) int { return compareUTF8(left.RKey, right.RKey) })
	slices.SortFunc(states, func(left, right ReducedState) int { return compareUTF8(left.LogicalMessageID, right.LogicalMessageID) })
	slices.SortFunc(folders, func(left, right ReducedFolderState) int { return compareUTF8(left.FolderID, right.FolderID) })
	result := &ReducedSourceState{
		target: input.target, revision: input.revision, snapshotID: input.snapshotID,
		commitCID: input.commitCID, indexCID: input.indexCID,
		messages: messages, messageStates: states, folders: folders,
	}
	result.seal = result.snapshotSeal()
	return result, nil
}

func validateOfficialInventoryIdentity(input officialSpacesInventory) error {
	if input.target.Epoch != officialspaces.PinnedEpoch || input.target.Origin == "" || input.target.SpaceURI == "" ||
		!validCanonicalDID(input.target.RepoDID) || !validSHA256Identifier(input.snapshotID) ||
		len(input.records) > maxOfficialSourceRecords {
		return ErrIncompleteSnapshot
	}
	if _, err := syntax.ParseTID(input.revision); err != nil {
		return ErrIncompleteSnapshot
	}
	for _, encoded := range []string{input.commitCID, input.indexCID} {
		parsed, err := cid.Parse(encoded)
		if err != nil || !validOfficialRecordCID(parsed) {
			return ErrIncompleteSnapshot
		}
	}
	return nil
}

func validateOfficialSourceRecord(record officialspaces.SourceRecord) error {
	if record.Collection == "" || record.RKey == "" || len(record.Value) == 0 {
		return ErrIncompleteSnapshot
	}
	if _, err := syntax.ParseRecordKey(record.RKey); err != nil {
		return ErrIncompleteSnapshot
	}
	parsed, err := cid.Parse(record.CID)
	if err != nil || !validOfficialRecordCID(parsed) {
		return ErrIncompleteSnapshot
	}
	recomputed, err := parsed.Prefix().Sum(record.Value)
	if err != nil || !recomputed.Equals(parsed) {
		return ErrIncompleteSnapshot
	}
	return nil
}

func validOfficialRecordCID(value cid.Cid) bool {
	prefix := value.Prefix()
	return value.Version() == 1 && prefix.Codec == cid.DagCBOR &&
		prefix.MhType == multihash.SHA2_256 && prefix.MhLength == sha256.Size
}

func reduceOfficialFolders(
	ctx context.Context,
	repoDID, snapshotID string,
	revisions map[string][]FolderStateRevision,
	claims map[string]map[string]string,
) ([]ReducedFolderState, map[string]verifiedFolderReference, error) {
	if len(revisions) == 0 || len(revisions) > maxFolderCount || len(claims) != len(revisions) {
		return nil, nil, ErrIncompleteSnapshot
	}
	folderIDs := sortedOfficialKeys(revisions)
	states := make([]ReducedFolderState, 0, len(folderIDs))
	for _, folderID := range folderIDs {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		folderClaims, exists := claims[folderID]
		if !exists || len(folderClaims) != len(revisions[folderID]) {
			return nil, nil, ErrIncompleteSnapshot
		}
		snapshot := VerifiedFolderSnapshot{
			snapshotID: snapshotID, folderID: folderID,
			revisionCount: len(revisions[folderID]), operationClaims: cloneStringMap(folderClaims),
		}
		snapshot.seal = snapshot.snapshotSeal()
		state, err := ReduceFolder(repoDID, folderID, revisions[folderID], snapshot)
		if err != nil {
			return nil, nil, err
		}
		states = append(states, state)
	}
	stateDigests := make(map[string]string, len(states))
	for _, state := range states {
		stateDigests[state.FolderID] = state.StateDigest
	}
	setSnapshot := VerifiedFolderSetSnapshot{
		snapshotID: snapshotID, repoDID: repoDID, folderCount: len(states), stateDigests: stateDigests,
	}
	setSnapshot.seal = setSnapshot.snapshotSeal()
	if err := ValidateFolderSet(repoDID, states, setSnapshot); err != nil {
		return nil, nil, err
	}
	references := make(map[string]verifiedFolderReference, len(states))
	for _, state := range states {
		references[state.FolderID] = verifiedFolderReference{stateDigest: state.StateDigest, tombstone: state.Tombstone}
	}
	return states, references, nil
}

func reduceOfficialMessages(
	ctx context.Context,
	repoDID, snapshotID string,
	versions map[string]map[string]string,
	revisions map[string][]StateRevision,
	claims map[string]map[string]string,
	folders map[string]verifiedFolderReference,
) ([]ReducedState, map[string]struct{}, error) {
	if len(revisions) != len(versions) || len(claims) != len(revisions) {
		return nil, nil, ErrIncompleteSnapshot
	}
	// Every message snapshot binds the complete folder set so a live state
	// cannot reference an omitted or tombstoned folder. Bound that cross
	// product explicitly: the independent record/byte limits otherwise admit
	// a valid but computationally explosive many-folder/many-message source.
	if len(folders) > 0 && len(revisions) > maxOfficialFolderMessageBindings/len(folders) {
		return nil, nil, ErrResourceLimit
	}
	logicalIDs := sortedOfficialKeys(revisions)
	states := make([]ReducedState, 0, len(logicalIDs))
	referencedVersions := make(map[string]struct{})
	for _, logicalID := range logicalIDs {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		logicalVersions, hasVersions := versions[logicalID]
		logicalClaims, hasClaims := claims[logicalID]
		if !hasVersions || !hasClaims || len(logicalClaims) != len(revisions[logicalID]) {
			return nil, nil, ErrIncompleteSnapshot
		}
		for _, revision := range revisions[logicalID] {
			if revision.Record.Version != "" {
				referencedVersions[revision.Record.Version] = struct{}{}
			}
		}
		snapshot := VerifiedSnapshot{
			snapshotID: snapshotID, logicalMessageID: logicalID,
			revisionCount: len(revisions[logicalID]), operationClaims: cloneStringMap(logicalClaims),
			versions: cloneStringMap(logicalVersions), folders: folders,
		}
		snapshot.seal = snapshot.snapshotSeal()
		state, err := Reduce(repoDID, logicalID, revisions[logicalID], snapshot)
		if err != nil {
			return nil, nil, err
		}
		states = append(states, state)
	}
	return states, referencedVersions, nil
}

func cloneStringMap(input map[string]string) map[string]string {
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func sortedOfficialKeys[V any](input map[string]V) []string {
	keys := make([]string, 0, len(input))
	for key := range input {
		keys = append(keys, key)
	}
	sortUTF8(keys)
	return keys
}

func decodeOfficialMessage(encoded []byte) (mailbox.MessageRecord, error) {
	jsonValue, node, err := officialRecordJSON(encoded)
	if err != nil {
		return mailbox.MessageRecord{}, err
	}
	raw, err := node.LookupByString("raw")
	if err != nil || raw.Kind() != datamodel.Kind_Map {
		return mailbox.MessageRecord{}, mailbox.ErrIntegrity
	}
	ref, err := raw.LookupByString("ref")
	if err != nil || ref.Kind() != datamodel.Kind_Link {
		return mailbox.MessageRecord{}, mailbox.ErrIntegrity
	}
	var record mailbox.MessageRecord
	if err := decodeOfficialStrictJSON(jsonValue, &record); err != nil {
		return mailbox.MessageRecord{}, mailbox.ErrIntegrity
	}
	return record, nil
}

func decodeOfficialMessageRevision(encoded []byte) (RevisionRecord, error) {
	jsonValue, _, err := officialRecordJSON(encoded)
	if err != nil {
		return RevisionRecord{}, err
	}
	return DecodeRevisionRecord(jsonValue)
}

func decodeOfficialMessageClaim(encoded []byte) (OperationClaimRecord, error) {
	jsonValue, _, err := officialRecordJSON(encoded)
	if err != nil {
		return OperationClaimRecord{}, err
	}
	return DecodeOperationClaimRecord(jsonValue)
}

func decodeOfficialFolderRevision(encoded []byte) (FolderRevisionRecord, error) {
	jsonValue, _, err := officialRecordJSON(encoded)
	if err != nil {
		return FolderRevisionRecord{}, err
	}
	return DecodeFolderRevisionRecord(jsonValue)
}

func decodeOfficialFolderClaim(encoded []byte) (FolderOperationClaimRecord, error) {
	jsonValue, _, err := officialRecordJSON(encoded)
	if err != nil {
		return FolderOperationClaimRecord{}, err
	}
	return DecodeFolderOperationClaimRecord(jsonValue)
}

func officialRecordJSON(encoded []byte) ([]byte, datamodel.Node, error) {
	if len(encoded) == 0 || len(encoded) > maxRevisionRecordBytes {
		return nil, nil, ErrResourceLimit
	}
	builder := basicnode.Prototype.Any.NewBuilder()
	if err := (dagcbor.DecodeOptions{AllowLinks: true}).Decode(builder, bytes.NewReader(encoded)); err != nil {
		return nil, nil, ErrInvalidRevision
	}
	node := builder.Build()
	if node.Kind() != datamodel.Kind_Map {
		return nil, nil, ErrInvalidRevision
	}
	lexValue, err := officialNodeToLexJSON(node, 0)
	if err != nil {
		return nil, nil, err
	}
	jsonValue, err := json.Marshal(lexValue)
	if err != nil || len(jsonValue) > maxRevisionRecordBytes {
		return nil, nil, ErrResourceLimit
	}
	return jsonValue, node, nil
}

func officialNodeToLexJSON(node datamodel.Node, depth int) (any, error) {
	if node == nil || depth > 128 {
		return nil, ErrResourceLimit
	}
	switch node.Kind() {
	case datamodel.Kind_Map:
		result := make(map[string]any, node.Length())
		iterator := node.MapIterator()
		for !iterator.Done() {
			keyNode, valueNode, err := iterator.Next()
			if err != nil {
				return nil, ErrInvalidRevision
			}
			key, err := keyNode.AsString()
			if err != nil {
				return nil, ErrInvalidRevision
			}
			value, err := officialNodeToLexJSON(valueNode, depth+1)
			if err != nil {
				return nil, err
			}
			result[key] = value
		}
		return result, nil
	case datamodel.Kind_List:
		result := make([]any, 0, node.Length())
		iterator := node.ListIterator()
		for !iterator.Done() {
			_, valueNode, err := iterator.Next()
			if err != nil {
				return nil, ErrInvalidRevision
			}
			value, err := officialNodeToLexJSON(valueNode, depth+1)
			if err != nil {
				return nil, err
			}
			result = append(result, value)
		}
		return result, nil
	case datamodel.Kind_Bool:
		return node.AsBool()
	case datamodel.Kind_Int:
		return node.AsInt()
	case datamodel.Kind_String:
		return node.AsString()
	case datamodel.Kind_Link:
		link, err := node.AsLink()
		if err != nil {
			return nil, ErrInvalidRevision
		}
		var linkCID cid.Cid
		switch value := link.(type) {
		case cidlink.Link:
			linkCID = value.Cid
		case *cidlink.Link:
			linkCID = value.Cid
		default:
			return nil, ErrInvalidRevision
		}
		if !linkCID.Defined() {
			return nil, ErrInvalidRevision
		}
		return map[string]string{"$link": linkCID.String()}, nil
	default:
		// None of the five mailbox record schemas admits null, floats, or
		// byte strings. Reject rather than allowing optional-null ambiguity.
		return nil, ErrInvalidRevision
	}
}

func decodeOfficialStrictJSON(encoded []byte, output any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalidRevision
	}
	return nil
}

func validateOfficialMessage(repoDID, rkey string, record mailbox.MessageRecord) error {
	if record.Type != mailbox.MessageCollection || !validSHA256Identifier(rkey) ||
		record.DeliveryFingerprint != rkey || !validSHA256Identifier(record.LogicalMessageID) ||
		record.LogicalMessageID != mailbox.LogicalMessageID(repoDID, record.SourceKey, rkey) ||
		record.Raw.Type != "blob" || record.Raw.MIMEType != mailbox.MessageMIMEType ||
		record.Raw.Size != record.Size || record.Size < 1 || record.Size > mailbox.MaxRawMessageBytes ||
		!validLowerHex(record.SHA256, sha256.Size) || !validText(record.InitialMailbox, 255) ||
		len(record.SourceKey) > 512 || !utf8.ValidString(record.SourceKey) ||
		!validOptionalText(record.SourceMessageID, 998) || !validOptionalText(record.InReplyTo, 998) ||
		len(record.References) > 100 {
		return mailbox.ErrIntegrity
	}
	for _, reference := range record.References {
		if !validOptionalText(reference, 998) || reference == "" {
			return mailbox.ErrIntegrity
		}
	}
	for _, value := range []string{record.DeliveredAt, record.MessageDate} {
		if value != "" {
			if _, err := time.Parse(time.RFC3339Nano, value); err != nil {
				return mailbox.ErrIntegrity
			}
		}
	}
	blobCID, err := cid.Parse(record.Raw.Ref.Link)
	if err != nil {
		return mailbox.ErrIntegrity
	}
	prefix := blobCID.Prefix()
	if blobCID.Version() != 1 || prefix.Codec != cid.Raw ||
		prefix.MhType != multihash.SHA2_256 || prefix.MhLength != sha256.Size {
		return mailbox.ErrIntegrity
	}
	claimedHash, err := hex.DecodeString(record.SHA256)
	if err != nil {
		return mailbox.ErrIntegrity
	}
	decodedHash, err := multihash.Decode(blobCID.Hash())
	if err != nil || !bytes.Equal(decodedHash.Digest, claimedHash) {
		return mailbox.ErrIntegrity
	}
	return nil
}

func validLowerHex(value string, byteLength int) bool {
	if len(value) != byteLength*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == byteLength
}

func validOptionalText(value string, limit int) bool {
	return len(value) <= limit && utf8.ValidString(value) && !strings.ContainsAny(value, "\r\n\x00")
}
