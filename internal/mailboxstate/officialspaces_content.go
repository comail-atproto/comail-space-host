package mailboxstate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"sort"
	"sync"

	"github.com/comail-atproto/comail-space-host/internal/mailbox"
	"github.com/comail-atproto/comail-space-host/internal/providers/officialspaces"
	"github.com/comail-atproto/comail-space-host/internal/repository"
	"github.com/ipfs/go-cid"
)

const maxContentVerifiedBytes int64 = 64 << 20

// ErrContentVerification is the redacted public failure for a complete
// source-authenticated metadata and message-byte read.
var ErrContentVerification = errors.New("mailboxstate: official content verification failed")

// ContentVerificationSummary contains bounded, content-free evidence about a
// ContentVerifiedSource. It intentionally contains no record keys or CIDs.
type ContentVerificationSummary struct {
	Target          officialspaces.Target
	Revision        string
	SnapshotID      string
	MessageVersions int
	UniqueBlobs     int
	TotalBytes      int64
	ManifestSHA256  string
}

// ContentVerifiedSource is an opaque, closeable capability for one fresh,
// commit-stable official Spaces recovery read. It owns at most 64 MiB of
// validated synthetic-or-member message bytes and is not an authority
// certificate, activation admission, or provider registration.
type ContentVerifiedSource struct {
	mu             sync.Mutex
	state          *ReducedSourceState
	blobs          map[string][]byte
	totalBytes     int64
	manifestSHA256 string
	seal           [sha256.Size]byte
	closed         bool
	activeVisits   int
	closePending   bool
}

// ContentVerifiedMessage is an ephemeral sealed message supplied only by a
// valid ContentVerifiedSource visitation. Open returns defensive copies while
// the callback is active; retained values fail closed after it returns.
type ContentVerifiedMessage struct {
	target     officialspaces.Target
	snapshotID string
	version    MessageVersion
	raw        []byte
	seal       [sha256.Size]byte
}

// ReadOfficialSpacesRecoverySource is the sole production constructor for a
// byte-complete official Spaces recovery capability. Its only authority input
// is the exact-target client: source read, reduction, blob selection, and byte
// validation all happen internally.
func ReadOfficialSpacesRecoverySource(ctx context.Context, client *officialspaces.Client) (*ContentVerifiedSource, error) {
	result, err := readOfficialSpacesRecoverySource(ctx, client)
	if err != nil {
		return nil, normalizeContentVerificationError(err)
	}
	return result, nil
}

func readOfficialSpacesRecoverySource(ctx context.Context, client *officialspaces.Client) (*ContentVerifiedSource, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if client == nil {
		return nil, ErrContentVerification
	}
	source, err := client.ReadSourceAuthenticatedRepository(ctx)
	if err != nil {
		return nil, err
	}
	reduced, err := ReduceOfficialSpacesSource(ctx, source)
	if err != nil {
		return nil, err
	}
	cids, groups, declaredTotal, err := prepareOfficialContent(reduced.messages)
	if err != nil {
		return nil, err
	}

	blobs := make(map[string][]byte, len(cids))
	clearBlobs := func() {
		for blobCID, raw := range blobs {
			clear(raw)
			delete(blobs, blobCID)
		}
	}
	var actualTotal int64
	err = client.StreamSourceMessageBlobs(ctx, source, cids, func(index int, blobCID string, raw []byte) error {
		if index < 0 || index >= len(cids) || cids[index] != blobCID || !validOfficialContentCID(blobCID, raw) {
			return mailbox.ErrIntegrity
		}
		for _, version := range groups[blobCID] {
			if err := mailbox.ValidateStoredMessage(reduced.target.RepoDID, version.RKey, version.Record, raw); err != nil {
				return mailbox.ErrIntegrity
			}
		}
		if int64(len(raw)) > maxContentVerifiedBytes-actualTotal {
			return ErrResourceLimit
		}
		actualTotal += int64(len(raw))
		blobs[blobCID] = bytes.Clone(raw)
		return nil
	})
	if err != nil {
		clearBlobs()
		return nil, err
	}
	if actualTotal != declaredTotal || source.ValidateSeal() != nil || reduced.ValidateSeal() != nil {
		clearBlobs()
		return nil, ErrContentVerification
	}

	result := &ContentVerifiedSource{
		state: reduced, blobs: blobs, totalBytes: actualTotal,
		manifestSHA256: officialContentManifest(reduced, blobs),
	}
	result.seal = result.snapshotSealLocked()
	return result, nil
}

func prepareOfficialContent(messages []MessageVersion) ([]string, map[string][]MessageVersion, int64, error) {
	groups := make(map[string][]MessageVersion)
	declaredSizes := make(map[string]int64)
	var total int64
	for _, message := range messages {
		blobCID := message.Record.Raw.Ref.Link
		size := message.Record.Size
		if blobCID == "" || size < 1 || size > mailbox.MaxRawMessageBytes {
			return nil, nil, 0, mailbox.ErrIntegrity
		}
		if prior, exists := declaredSizes[blobCID]; exists {
			if prior != size {
				return nil, nil, 0, mailbox.ErrIntegrity
			}
		} else {
			if size > maxContentVerifiedBytes-total {
				return nil, nil, 0, ErrResourceLimit
			}
			declaredSizes[blobCID] = size
			total += size
		}
		groups[blobCID] = append(groups[blobCID], message)
	}
	cids := make([]string, 0, len(groups))
	for blobCID := range groups {
		cids = append(cids, blobCID)
	}
	sort.Strings(cids)
	return cids, groups, total, nil
}

func validOfficialContentCID(blobCID string, raw []byte) bool {
	parsed, err := cid.Parse(blobCID)
	if err != nil || parsed.String() != blobCID {
		return false
	}
	actual, err := parsed.Prefix().Sum(raw)
	return err == nil && actual.Equals(parsed)
}

func officialContentManifest(state *ReducedSourceState, blobs map[string][]byte) string {
	digest := sha256.New()
	_, _ = io.WriteString(digest, "comail-official-content-manifest-v1\x00")
	writeSourceSealString(digest, state.target.Origin)
	writeSourceSealString(digest, state.target.SpaceURI)
	writeSourceSealString(digest, state.target.RepoDID)
	writeSourceSealString(digest, state.target.Epoch)
	writeSourceSealString(digest, state.revision)
	writeSourceSealString(digest, state.snapshotID)
	writeSourceSealUint64(digest, uint64(len(state.messages)))
	for _, message := range state.messages {
		writeSourceSealString(digest, message.RKey)
		writeSourceSealString(digest, message.CID)
		writeSourceSealString(digest, message.Record.Raw.Ref.Link)
		writeSourceSealString(digest, message.Record.SHA256)
		writeSourceSealUint64(digest, uint64(message.Record.Size))
	}
	writeSourceSealUint64(digest, uint64(len(blobs)))
	return "sha256-" + hex.EncodeToString(digest.Sum(nil))
}

func (source *ContentVerifiedSource) Summary() ContentVerificationSummary {
	if source == nil {
		return ContentVerificationSummary{}
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if !source.validLocked() {
		return ContentVerificationSummary{}
	}
	return ContentVerificationSummary{
		Target: source.state.target, Revision: source.state.revision, SnapshotID: source.state.snapshotID,
		MessageVersions: len(source.state.messages), UniqueBlobs: len(source.blobs),
		TotalBytes: source.totalBytes, ManifestSHA256: source.manifestSHA256,
	}
}

func (source *ContentVerifiedSource) Folders() []ReducedFolderState {
	if source == nil {
		return nil
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if !source.validLocked() {
		return nil
	}
	return cloneReducedFolders(source.state.folders)
}

func (source *ContentVerifiedSource) MessageStates() []ReducedState {
	if source == nil {
		return nil
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if !source.validLocked() {
		return nil
	}
	return cloneReducedStates(source.state.messageStates)
}

func (source *ContentVerifiedSource) VisitMessages(ctx context.Context, visit func(ContentVerifiedMessage) error) error {
	if source == nil || ctx == nil || visit == nil {
		return ErrContentVerification
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	source.mu.Lock()
	if !source.validLocked() {
		source.mu.Unlock()
		return ErrContentVerification
	}
	source.activeVisits++
	state, blobs := source.state, source.blobs
	source.mu.Unlock()
	defer source.finishVisit()

	for _, stored := range state.messages {
		if err := ctx.Err(); err != nil {
			return err
		}
		version := cloneMessageVersions([]MessageVersion{stored})[0]
		raw := bytes.Clone(blobs[version.Record.Raw.Ref.Link])
		message := ContentVerifiedMessage{
			target: state.target, snapshotID: state.snapshotID,
			version: version, raw: raw,
		}
		message.seal = message.snapshotSeal()
		visitErr := visit(message)
		clear(message.raw)
		if visitErr != nil {
			if errors.Is(visitErr, context.Canceled) {
				return context.Canceled
			}
			if errors.Is(visitErr, context.DeadlineExceeded) {
				return context.DeadlineExceeded
			}
			return ErrContentVerification
		}
	}
	return nil
}

func (source *ContentVerifiedSource) ValidateSeal() error {
	if source == nil {
		return ErrContentVerification
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if !source.validLocked() {
		return ErrContentVerification
	}
	return nil
}

func (source *ContentVerifiedSource) Close() {
	if source == nil {
		return
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.closed {
		return
	}
	source.closed = true
	if source.activeVisits > 0 {
		source.closePending = true
		return
	}
	source.clearLocked()
}

func (source *ContentVerifiedSource) finishVisit() {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.activeVisits--
	if source.activeVisits == 0 && source.closePending {
		source.clearLocked()
	}
}

func (source *ContentVerifiedSource) clearLocked() {
	for blobCID, raw := range source.blobs {
		clear(raw)
		delete(source.blobs, blobCID)
	}
	source.state = nil
	source.totalBytes = 0
	source.manifestSHA256 = ""
	source.seal = [sha256.Size]byte{}
	source.closePending = false
}

func (source *ContentVerifiedSource) String() string {
	return "mailboxstate.ContentVerifiedSource(redacted)"
}

func (source *ContentVerifiedSource) GoString() string { return source.String() }

func (source *ContentVerifiedSource) validLocked() bool {
	return source != nil && !source.closed && source.state != nil && source.state.valid() &&
		len(source.manifestSHA256) > 0 && validSHA256Identifier(source.manifestSHA256) &&
		source.totalBytes >= 0 && source.totalBytes <= maxContentVerifiedBytes &&
		source.seal == source.snapshotSealLocked()
}

func (source *ContentVerifiedSource) snapshotSealLocked() [sha256.Size]byte {
	digest := sha256.New()
	_, _ = io.WriteString(digest, "comail-official-content-source-v1\x00")
	if source.state != nil {
		_, _ = digest.Write(source.state.seal[:])
	}
	writeSourceSealString(digest, source.manifestSHA256)
	writeSourceSealUint64(digest, uint64(source.totalBytes))
	cids := make([]string, 0, len(source.blobs))
	for blobCID := range source.blobs {
		cids = append(cids, blobCID)
	}
	sort.Strings(cids)
	writeSourceSealUint64(digest, uint64(len(cids)))
	for _, blobCID := range cids {
		writeSourceSealString(digest, blobCID)
		writeSourceSealUint64(digest, uint64(len(source.blobs[blobCID])))
		_, _ = digest.Write(source.blobs[blobCID])
	}
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result
}

func (message ContentVerifiedMessage) Open() (MessageVersion, []byte, error) {
	if !message.valid() {
		return MessageVersion{}, nil, ErrContentVerification
	}
	return cloneMessageVersions([]MessageVersion{message.version})[0], bytes.Clone(message.raw), nil
}

func (message ContentVerifiedMessage) String() string {
	return "mailboxstate.ContentVerifiedMessage(redacted)"
}

func (message ContentVerifiedMessage) GoString() string { return message.String() }

func (message ContentVerifiedMessage) valid() bool {
	return message.target.Epoch == officialspaces.PinnedEpoch && validSHA256Identifier(message.snapshotID) &&
		mailbox.ValidateStoredMessage(message.target.RepoDID, message.version.RKey, message.version.Record, message.raw) == nil &&
		validOfficialContentCID(message.version.Record.Raw.Ref.Link, message.raw) && message.seal == message.snapshotSeal()
}

func (message ContentVerifiedMessage) snapshotSeal() [sha256.Size]byte {
	digest := sha256.New()
	_, _ = io.WriteString(digest, "comail-official-content-message-v1\x00")
	writeSourceSealString(digest, message.target.Origin)
	writeSourceSealString(digest, message.target.SpaceURI)
	writeSourceSealString(digest, message.target.RepoDID)
	writeSourceSealString(digest, message.target.Epoch)
	writeSourceSealString(digest, message.snapshotID)
	writeSourceSealString(digest, message.version.RKey)
	writeSourceSealString(digest, message.version.CID)
	writeSourceSealJSON(digest, message.version.Record)
	writeSourceSealUint64(digest, uint64(len(message.raw)))
	_, _ = digest.Write(message.raw)
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result
}

func normalizeContentVerificationError(err error) error {
	for _, sentinel := range []error{
		context.Canceled, context.DeadlineExceeded, officialspaces.ErrReauthorizationRequired,
		repository.ErrUnauthorized, repository.ErrRevoked, repository.ErrNotFound, repository.ErrTarget,
	} {
		if errors.Is(err, sentinel) {
			return sentinel
		}
	}
	return ErrContentVerification
}
