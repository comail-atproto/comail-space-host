package officialspaces

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/comail-atproto/comail-space-host/internal/repository"
	"github.com/ipfs/go-cid"
	"github.com/ipld/go-ipld-prime/codec"
	"github.com/ipld/go-ipld-prime/codec/dagcbor"
	"github.com/ipld/go-ipld-prime/datamodel"
	cidlink "github.com/ipld/go-ipld-prime/linking/cid"
	"github.com/ipld/go-ipld-prime/node/basicnode"
	"github.com/multiformats/go-multihash"
	"lukechampine.com/blake3"
)

const (
	commitVersion          = 1
	commitContextDomain    = "atproto-space-v1"
	ltHashStateBytes       = 2048
	maxCARHeaderBytes      = 64 * 1024
	maxCommitBlockBytes    = 64 * 1024
	maxIndexBlockBytes     = 64 * 1024 * 1024
	maxRecordBlockBytes    = 1 * 1024 * 1024
	maxRetainedRecordBytes = 64 * 1024 * 1024
	maxRepoRecords         = 100_000
	maxCBORNestingDepth    = 128
	maxCBORDataItems       = 350_000
)

var ErrSnapshotVerification = errors.New("officialspaces: source snapshot verification failed")

// repoSigningKeyResolver is intentionally narrower than the credential-key
// resolver. Official repo commits are signed by the member's exact #atproto
// key, never the authority's optional #atproto_space key.
type repoSigningKeyResolver interface {
	ResolveRepoSource(context.Context, syntax.DID, bool) (string, atcrypto.PublicKey, error)
}

type signedRepoCommit struct {
	Version   int64
	Hash      []byte
	IKM       []byte
	Signature []byte
	MAC       []byte
	Revision  string
}

type strictJSONBytes []byte

func (value *strictJSONBytes) UnmarshalJSON(encoded []byte) error {
	var envelope struct {
		Bytes string `json:"$bytes"`
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) || envelope.Bytes == "" {
		return errors.New("invalid lex bytes")
	}
	decoded, err := base64.RawStdEncoding.DecodeString(envelope.Bytes)
	if err != nil || base64.RawStdEncoding.EncodeToString(decoded) != envelope.Bytes {
		return errors.New("invalid lex bytes")
	}
	*value = append((*value)[:0], decoded...)
	return nil
}

type indexedRecord struct {
	collection string
	rkey       string
	cid        cid.Cid
	value      []byte
}

// SourceRecord is one immutable defensive copy from a stable, exact-origin
// PDS read. Value is canonical DAG-CBOR, not JSON.
type SourceRecord struct {
	Collection string
	RKey       string
	CID        string
	Value      []byte
}

// SourceAuthenticatedRepository is an opaque capability for a full CAR read
// performed directly from the exact OAuth/DPoP-authenticated PDS source. The
// alpha commit signature does not sign the repo hash; this value therefore
// must never be reconstructed from an uploaded, cached, or offline CAR.
type SourceAuthenticatedRepository struct {
	target     Target
	revision   string
	snapshotID string
	commitCID  string
	indexCID   string
	repoHash   []byte
	records    []SourceRecord
	seal       [sha256.Size]byte
}

func (r *SourceAuthenticatedRepository) Target() Target {
	if !r.valid() {
		return Target{}
	}
	return r.target
}

func (r *SourceAuthenticatedRepository) Revision() string {
	if !r.valid() {
		return ""
	}
	return r.revision
}

func (r *SourceAuthenticatedRepository) SnapshotID() string {
	if !r.valid() {
		return ""
	}
	return r.snapshotID
}

func (r *SourceAuthenticatedRepository) CommitCID() string {
	if !r.valid() {
		return ""
	}
	return r.commitCID
}

func (r *SourceAuthenticatedRepository) IndexCID() string {
	if !r.valid() {
		return ""
	}
	return r.indexCID
}

func (r *SourceAuthenticatedRepository) Records() []SourceRecord {
	if !r.valid() {
		return nil
	}
	return cloneSourceRecords(r.records)
}

// ValidateSeal checks only that this in-memory capability has not been
// mutated since its authenticated source read. It does not contact the PDS,
// re-resolve the DID, or independently prove authorship.
func (r *SourceAuthenticatedRepository) ValidateSeal() error {
	if !r.valid() {
		return ErrSnapshotVerification
	}
	return nil
}

func (r *SourceAuthenticatedRepository) String() string {
	return "officialspaces.SourceAuthenticatedRepository(redacted)"
}

func (r *SourceAuthenticatedRepository) GoString() string { return r.String() }

func (r *SourceAuthenticatedRepository) valid() bool {
	return r != nil && r.snapshotID != "" && r.commitCID != "" && r.indexCID != "" &&
		len(r.repoHash) == sha256.Size && r.target.Epoch == PinnedEpoch && r.seal == r.snapshotSeal()
}

func (r *SourceAuthenticatedRepository) snapshotSeal() [sha256.Size]byte {
	hash := sha256.New()
	writeSnapshotField(hash, "comail-official-source-snapshot-v1")
	writeSnapshotField(hash, r.target.Origin)
	writeSnapshotField(hash, r.target.SpaceURI)
	writeSnapshotField(hash, r.target.RepoDID)
	writeSnapshotField(hash, r.target.Epoch)
	writeSnapshotField(hash, r.revision)
	writeSnapshotField(hash, r.snapshotID)
	writeSnapshotField(hash, r.commitCID)
	writeSnapshotField(hash, r.indexCID)
	var repoHashSize [8]byte
	binary.BigEndian.PutUint64(repoHashSize[:], uint64(len(r.repoHash)))
	_, _ = hash.Write(repoHashSize[:])
	_, _ = hash.Write(r.repoHash)
	var count [8]byte
	binary.BigEndian.PutUint64(count[:], uint64(len(r.records)))
	_, _ = hash.Write(count[:])
	for _, record := range r.records {
		writeSnapshotField(hash, record.Collection)
		writeSnapshotField(hash, record.RKey)
		writeSnapshotField(hash, record.CID)
		var valueSize [8]byte
		binary.BigEndian.PutUint64(valueSize[:], uint64(len(record.Value)))
		_, _ = hash.Write(valueSize[:])
		_, _ = hash.Write(record.Value)
	}
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func writeSnapshotField(writer io.Writer, value string) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = writer.Write(size[:])
	_, _ = io.WriteString(writer, value)
}

func cloneSourceRecords(input []SourceRecord) []SourceRecord {
	result := make([]SourceRecord, len(input))
	for index, record := range input {
		result[index] = record
		result[index].Value = append([]byte(nil), record.Value...)
	}
	return result
}

// ReadSourceAuthenticatedRepository performs one stable read under one scoped
// credential. Before/CAR/after agreement makes torn or stale multi-request
// reads fail closed. CAR checks are defense in depth under the authenticated
// PDS trust root; they are not a standalone author commitment.
func (c *Client) ReadSourceAuthenticatedRepository(ctx context.Context) (*SourceAuthenticatedRepository, error) {
	if c.repoKeys == nil {
		return nil, fmt.Errorf("%w: repo signing-key resolver is unavailable", ErrSnapshotVerification)
	}
	if err := c.validateRepoSourceOrigin(ctx); err != nil {
		return nil, err
	}
	var result *SourceAuthenticatedRepository
	err := c.withReader(ctx, func(credential ScopedDoer) error {
		before, err := c.readSourceCommit(ctx, credential)
		if err != nil {
			return err
		}
		if err := verifyCommitConsistency(ctx, before, c.target, c.repoKeys); err != nil {
			return err
		}

		carSnapshot, err := c.readSourceCAR(ctx, credential)
		if err != nil {
			return err
		}
		if !sameRepoState(before, carSnapshot.commit) {
			return fmt.Errorf("%w: pre-read state did not match CAR", ErrSnapshotVerification)
		}

		after, err := c.readSourceCommit(ctx, credential)
		if err != nil {
			return err
		}
		if err := verifyCommitConsistency(ctx, after, c.target, c.repoKeys); err != nil {
			return err
		}
		if !sameRepoState(carSnapshot.commit, after) {
			return fmt.Errorf("%w: source changed during full read", ErrSnapshotVerification)
		}

		snapshotID := sourceSnapshotID(c.target, carSnapshot)
		records := make([]SourceRecord, len(carSnapshot.records))
		for index, record := range carSnapshot.records {
			records[index] = SourceRecord{
				Collection: record.collection, RKey: record.rkey,
				CID: record.cid.String(), Value: append([]byte(nil), record.value...),
			}
		}
		result = &SourceAuthenticatedRepository{
			target: c.target, revision: carSnapshot.commit.Revision, snapshotID: snapshotID,
			commitCID: carSnapshot.commitCID.String(), indexCID: carSnapshot.indexCID.String(),
			repoHash: append([]byte(nil), carSnapshot.commit.Hash...), records: records,
		}
		result.seal = result.snapshotSeal()
		return nil
	})
	if err != nil {
		return nil, normalizeSnapshotError(err)
	}
	return result, nil
}

func (r *SourceAuthenticatedRepository) matchesCommit(commit signedRepoCommit) bool {
	return r != nil && commit.Version == commitVersion && commit.Revision == r.revision &&
		len(r.repoHash) == sha256.Size && hmac.Equal(commit.Hash, r.repoHash)
}

func (c *Client) validateRepoSourceOrigin(ctx context.Context) error {
	if c.repoKeys == nil {
		return fmt.Errorf("%w: repo signing-key resolver is unavailable", ErrSnapshotVerification)
	}
	repoDID, err := syntax.ParseDID(c.target.RepoDID)
	if err != nil {
		return fmt.Errorf("%w: invalid repo DID", ErrSnapshotVerification)
	}
	repoHost, _, err := c.repoKeys.ResolveRepoSource(ctx, repoDID, true)
	if err != nil {
		return fmt.Errorf("%w: resolve repo PDS", ErrSnapshotVerification)
	}
	cleanRepoHost, err := cleanOrigin(repoHost, true)
	if err != nil || cleanRepoHost != c.origin {
		return repository.ErrTarget
	}
	return nil
}

func (c *Client) readSourceCommit(ctx context.Context, credential ScopedDoer) (signedRepoCommit, error) {
	response, err := c.request(ctx, credential, http.MethodGet, getLatestCommitEndpoint, targetQuery(c.target), nil, "", "application/json")
	if err != nil {
		return signedRepoCommit{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return signedRepoCommit{}, decodeProviderError(response)
	}
	var output struct {
		Commit struct {
			Version   int64           `json:"ver"`
			Hash      strictJSONBytes `json:"hash"`
			IKM       strictJSONBytes `json:"ikm"`
			Signature strictJSONBytes `json:"sig"`
			MAC       strictJSONBytes `json:"mac"`
			Revision  string          `json:"rev"`
		} `json:"commit"`
	}
	if err := decodeStrictBounded(response.Body, maxCommitBytes, &output); err != nil {
		return signedRepoCommit{}, fmt.Errorf("%w: invalid latest commit", ErrSnapshotVerification)
	}
	return signedRepoCommit{
		Version: output.Commit.Version, Hash: append([]byte(nil), output.Commit.Hash...),
		IKM: append([]byte(nil), output.Commit.IKM...), Signature: append([]byte(nil), output.Commit.Signature...),
		MAC: append([]byte(nil), output.Commit.MAC...), Revision: output.Commit.Revision,
	}, nil
}

func (c *Client) readSourceCAR(ctx context.Context, credential ScopedDoer) (verifiedCAR, error) {
	query := targetQuery(c.target)
	query.Set("excludeValues", "false")
	response, err := c.request(ctx, credential, http.MethodGet, getRepoEndpoint, query, nil, "", "application/vnd.ipld.car")
	if err != nil {
		return verifiedCAR{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return verifiedCAR{}, decodeProviderError(response)
	}
	mediaType, _, parseErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if parseErr != nil || !strings.EqualFold(mediaType, "application/vnd.ipld.car") {
		return verifiedCAR{}, fmt.Errorf("%w: repo export media type mismatch", ErrSnapshotVerification)
	}
	limited := &io.LimitedReader{R: response.Body, N: maxRepoStreamBytes + 1}
	snapshot, err := verifyFullSourceCAR(ctx, limited, c.target, c.repoKeys)
	if err != nil {
		return verifiedCAR{}, err
	}
	if limited.N <= 0 {
		return verifiedCAR{}, fmt.Errorf("%w: repo export exceeds safety bound", ErrSnapshotVerification)
	}
	return snapshot, nil
}

func sameRepoState(left, right signedRepoCommit) bool {
	return left.Version == right.Version && left.Revision == right.Revision && hmac.Equal(left.Hash, right.Hash)
}

type verifiedCAR struct {
	commit    signedRepoCommit
	commitCID cid.Cid
	indexCID  cid.Cid
	records   []indexedRecord
}

func verifyFullSourceCAR(ctx context.Context, input io.Reader, target Target, resolver repoSigningKeyResolver) (verifiedCAR, error) {
	reader := bufio.NewReaderSize(input, 64*1024)
	headerBytes, err := readCARSection(reader, maxCARHeaderBytes)
	if err != nil {
		return verifiedCAR{}, fmt.Errorf("%w: invalid CAR header", ErrSnapshotVerification)
	}
	commitRoot, indexRoot, err := parseCARHeader(headerBytes)
	if err != nil {
		return verifiedCAR{}, err
	}

	commitCID, commitBytes, err := readCARBlock(reader, maxCommitBlockBytes)
	if err != nil || !commitCID.Equals(commitRoot) {
		return verifiedCAR{}, fmt.Errorf("%w: commit block must lead CAR", ErrSnapshotVerification)
	}
	commit, err := parseSignedCommit(commitBytes)
	if err != nil {
		return verifiedCAR{}, err
	}
	if err := verifyCommitConsistency(ctx, commit, target, resolver); err != nil {
		return verifiedCAR{}, err
	}

	indexCID, indexBytes, err := readCARBlock(reader, maxIndexBlockBytes)
	if err != nil || !indexCID.Equals(indexRoot) {
		return verifiedCAR{}, fmt.Errorf("%w: index block must follow commit", ErrSnapshotVerification)
	}
	entries, setHash, err := parseRepoIndex(indexBytes)
	if err != nil {
		return verifiedCAR{}, err
	}
	if !hmac.Equal(setHash[:], commit.Hash) {
		return verifiedCAR{}, fmt.Errorf("%w: index set hash did not match commit", ErrSnapshotVerification)
	}

	records := make([]indexedRecord, 0, len(entries))
	retainedBytes := 0
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return verifiedCAR{}, err
		}
		blockCID, value, err := readCARBlock(reader, maxRecordBlockBytes)
		if err != nil || !blockCID.Equals(entry.cid) {
			return verifiedCAR{}, fmt.Errorf("%w: record block order or CID mismatch", ErrSnapshotVerification)
		}
		node, err := decodeCanonicalDAGCBOR(value)
		if err != nil || !recordTypeMatchesNode(node, entry.collection) {
			return verifiedCAR{}, fmt.Errorf("%w: record block is not canonical path-matching data", ErrSnapshotVerification)
		}
		retainedBytes += len(value)
		if retainedBytes > maxRetainedRecordBytes {
			return verifiedCAR{}, fmt.Errorf("%w: retained record bytes exceeded limit", ErrSnapshotVerification)
		}
		entry.value = append([]byte(nil), value...)
		records = append(records, entry)
	}
	if _, err := readCARSection(reader, maxRecordBlockBytes); !errors.Is(err, io.EOF) {
		return verifiedCAR{}, fmt.Errorf("%w: CAR contains extra or malformed blocks", ErrSnapshotVerification)
	}
	return verifiedCAR{commit: commit, commitCID: commitCID, indexCID: indexCID, records: records}, nil
}

func parseCARHeader(encoded []byte) (cid.Cid, cid.Cid, error) {
	node, err := decodeCanonicalDAGCBOR(encoded)
	if err != nil || node.Kind() != datamodel.Kind_Map || node.Length() != 2 || !exactMapKeys(node, "roots", "version") {
		return cid.Undef, cid.Undef, fmt.Errorf("%w: malformed CAR header", ErrSnapshotVerification)
	}
	versionNode, _ := node.LookupByString("version")
	version, err := versionNode.AsInt()
	if err != nil || version != 1 {
		return cid.Undef, cid.Undef, fmt.Errorf("%w: unsupported CAR version", ErrSnapshotVerification)
	}
	roots, _ := node.LookupByString("roots")
	if roots.Kind() != datamodel.Kind_List || roots.Length() != 2 {
		return cid.Undef, cid.Undef, fmt.Errorf("%w: CAR must have two ordered roots", ErrSnapshotVerification)
	}
	first, _ := roots.LookupByIndex(0)
	second, _ := roots.LookupByIndex(1)
	commitCID, okCommit := nodeCID(first)
	indexCID, okIndex := nodeCID(second)
	if !okCommit || !okIndex || !validDAGCBORCID(commitCID) || !validDAGCBORCID(indexCID) {
		return cid.Undef, cid.Undef, fmt.Errorf("%w: invalid CAR roots", ErrSnapshotVerification)
	}
	return commitCID, indexCID, nil
}

func parseSignedCommit(encoded []byte) (signedRepoCommit, error) {
	node, err := decodeCanonicalDAGCBOR(encoded)
	if err != nil {
		return signedRepoCommit{}, fmt.Errorf("%w: non-canonical signed commit: %v", ErrSnapshotVerification, err)
	}
	if node.Kind() != datamodel.Kind_Map || node.Length() != 6 || !exactMapKeys(node, "ver", "hash", "ikm", "sig", "mac", "rev") {
		return signedRepoCommit{}, fmt.Errorf("%w: malformed signed commit map", ErrSnapshotVerification)
	}
	versionNode, _ := node.LookupByString("ver")
	version, err := versionNode.AsInt()
	if err != nil {
		return signedRepoCommit{}, fmt.Errorf("%w: malformed signed commit version", ErrSnapshotVerification)
	}
	result := signedRepoCommit{Version: version}
	for name, destination := range map[string]*[]byte{
		"hash": &result.Hash, "ikm": &result.IKM, "sig": &result.Signature, "mac": &result.MAC,
	} {
		value, _ := node.LookupByString(name)
		decoded, err := value.AsBytes()
		if err != nil {
			return signedRepoCommit{}, fmt.Errorf("%w: malformed signed commit bytes", ErrSnapshotVerification)
		}
		*destination = append([]byte(nil), decoded...)
	}
	revisionNode, _ := node.LookupByString("rev")
	result.Revision, err = revisionNode.AsString()
	if err != nil {
		return signedRepoCommit{}, fmt.Errorf("%w: malformed signed commit revision", ErrSnapshotVerification)
	}
	return result, nil
}

func parseRepoIndex(encoded []byte) ([]indexedRecord, [sha256.Size]byte, error) {
	node, err := decodeCanonicalDAGCBOR(encoded)
	if err != nil || node.Kind() != datamodel.Kind_Map || node.Length() > maxRepoRecords {
		return nil, [sha256.Size]byte{}, fmt.Errorf("%w: malformed or oversized repo index", ErrSnapshotVerification)
	}
	entries := make([]indexedRecord, 0, node.Length())
	setHash := newLtHash()
	iterator := node.MapIterator()
	for !iterator.Done() {
		keyNode, valueNode, err := iterator.Next()
		if err != nil {
			return nil, [sha256.Size]byte{}, fmt.Errorf("%w: malformed repo index entry", ErrSnapshotVerification)
		}
		path, err := keyNode.AsString()
		if err != nil {
			return nil, [sha256.Size]byte{}, fmt.Errorf("%w: non-string repo path", ErrSnapshotVerification)
		}
		collection, rkey, ok := parseRecordPath(path)
		recordCID, cidOK := nodeCID(valueNode)
		if !ok || !allowedCollection(collection) || !cidOK || !validDAGCBORCID(recordCID) {
			return nil, [sha256.Size]byte{}, fmt.Errorf("%w: invalid repo index path or CID", ErrSnapshotVerification)
		}
		entries = append(entries, indexedRecord{collection: collection, rkey: rkey, cid: recordCID})
		setHash.add(path + "/" + recordCID.String())
	}
	return entries, setHash.digest(), nil
}

func parseRecordPath(path string) (string, string, bool) {
	collection, rkey, found := strings.Cut(path, "/")
	if !found || collection == "" || rkey == "" || strings.Contains(rkey, "/") {
		return "", "", false
	}
	if _, err := syntax.ParseNSID(collection); err != nil {
		return "", "", false
	}
	if _, err := syntax.ParseRecordKey(rkey); err != nil {
		return "", "", false
	}
	return collection, rkey, true
}

func verifyCommitConsistency(ctx context.Context, commit signedRepoCommit, target Target, resolver repoSigningKeyResolver) error {
	if commit.Version != commitVersion || len(commit.Hash) != sha256.Size || len(commit.IKM) != sha256.Size ||
		len(commit.MAC) != sha256.Size || len(commit.Signature) != 64 || resolver == nil {
		return fmt.Errorf("%w: malformed commit", ErrSnapshotVerification)
	}
	if _, err := syntax.ParseTID(commit.Revision); err != nil {
		return fmt.Errorf("%w: malformed commit revision", ErrSnapshotVerification)
	}
	did, err := syntax.ParseDID(target.RepoDID)
	if err != nil || target.Epoch != PinnedEpoch || target.SpaceURI == "" || len(target.SpaceURI) > 0xffff || len(target.RepoDID) > 0xffff || len(commit.Revision) > 0xffff {
		return fmt.Errorf("%w: commit target mismatch", ErrSnapshotVerification)
	}
	contextBytes := commitContext(target.SpaceURI, target.RepoDID, commit.Revision, commit.IKM)
	wantMAC := computeCommitMAC(commit.IKM, contextBytes, commit.Hash)
	if !hmac.Equal(wantMAC, commit.MAC) {
		return fmt.Errorf("%w: commit MAC mismatch", ErrSnapshotVerification)
	}
	repoHost, key, err := resolver.ResolveRepoSource(ctx, did, true)
	cleanRepoHost, hostErr := cleanOrigin(repoHost, true)
	if err != nil || hostErr != nil || cleanRepoHost != target.Origin || key == nil {
		return fmt.Errorf("%w: repo source identity mismatch", ErrSnapshotVerification)
	}
	if err := key.HashAndVerify(contextBytes, commit.Signature); err != nil {
		return fmt.Errorf("%w: invalid commit signature", ErrSnapshotVerification)
	}
	return nil
}

func commitContext(space, author, revision string, ikm []byte) []byte {
	result := make([]byte, 0, len(commitContextDomain)+8+len(space)+len(author)+len(revision)+len(ikm))
	result = append(result, commitContextDomain...)
	for _, field := range [][]byte{[]byte(space), []byte(author), []byte(revision), ikm} {
		result = binary.BigEndian.AppendUint16(result, uint16(len(field)))
		result = append(result, field...)
	}
	return result
}

func computeCommitMAC(ikm, contextBytes, hash []byte) []byte {
	// The pinned alpha calls noble's HKDF Expand directly, treating IKM as the
	// pseudorandom key. One SHA-256 output block is sufficient for 32 bytes.
	expander := hmac.New(sha256.New, ikm)
	_, _ = expander.Write(contextBytes)
	_, _ = expander.Write([]byte{1})
	key := expander.Sum(nil)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(hash)
	return mac.Sum(nil)
}

type ltHash struct {
	state [ltHashStateBytes]byte
}

func newLtHash() *ltHash { return &ltHash{} }

func (hash *ltHash) add(element string) {
	digest := blake3.New(0, nil)
	_, _ = io.WriteString(digest, element)
	xof := digest.XOF()
	var expanded [ltHashStateBytes]byte
	_, _ = io.ReadFull(xof, expanded[:])
	for offset := 0; offset < ltHashStateBytes; offset += 2 {
		current := binary.LittleEndian.Uint16(hash.state[offset : offset+2])
		addition := binary.LittleEndian.Uint16(expanded[offset : offset+2])
		binary.LittleEndian.PutUint16(hash.state[offset:offset+2], current+addition)
	}
}

func (hash *ltHash) digest() [sha256.Size]byte { return sha256.Sum256(hash.state[:]) }

func ltHashDigest(elements []string) [sha256.Size]byte {
	hash := newLtHash()
	for _, element := range elements {
		hash.add(element)
	}
	return hash.digest()
}

func readCARSection(reader *bufio.Reader, limit int) ([]byte, error) {
	length, err := readCanonicalUvarint(reader)
	if err != nil {
		return nil, err
	}
	if length == 0 || length > uint64(limit) {
		return nil, ErrSnapshotVerification
	}
	encoded := make([]byte, int(length))
	if _, err := io.ReadFull(reader, encoded); err != nil {
		return nil, err
	}
	return encoded, nil
}

func readCanonicalUvarint(reader *bufio.Reader) (uint64, error) {
	var encoded [binary.MaxVarintLen64]byte
	for index := range encoded {
		value, err := reader.ReadByte()
		if err != nil {
			return 0, err
		}
		encoded[index] = value
		if value&0x80 != 0 {
			continue
		}
		length := index + 1
		decoded, consumed := binary.Uvarint(encoded[:length])
		if consumed != length {
			return 0, ErrSnapshotVerification
		}
		var canonical [binary.MaxVarintLen64]byte
		canonicalLength := binary.PutUvarint(canonical[:], decoded)
		if canonicalLength != length || !bytes.Equal(canonical[:canonicalLength], encoded[:length]) {
			return 0, ErrSnapshotVerification
		}
		return decoded, nil
	}
	return 0, ErrSnapshotVerification
}

func readCARBlock(reader *bufio.Reader, dataLimit int) (cid.Cid, []byte, error) {
	section, err := readCARSection(reader, dataLimit+256)
	if err != nil {
		return cid.Undef, nil, err
	}
	consumed, blockCID, err := cid.CidFromBytes(section)
	if err != nil || consumed <= 0 || consumed >= len(section) || !validDAGCBORCID(blockCID) {
		return cid.Undef, nil, ErrSnapshotVerification
	}
	data := section[consumed:]
	if len(data) > dataLimit {
		return cid.Undef, nil, ErrSnapshotVerification
	}
	recomputed, err := blockCID.Prefix().Sum(data)
	if err != nil || !recomputed.Equals(blockCID) {
		return cid.Undef, nil, ErrSnapshotVerification
	}
	return blockCID, data, nil
}

func decodeCanonicalDAGCBOR(encoded []byte) (datamodel.Node, error) {
	// Bound structural nesting before the recursive DAG-CBOR decoder sees
	// source-controlled bytes. Per-section byte limits alone do not bound the
	// decoder stack: a small payload can contain a very deep container chain.
	if err := preflightCBORStructure(encoded, maxCBORNestingDepth, maxCBORDataItems); err != nil {
		return nil, err
	}
	builder := basicnode.Prototype.Any.NewBuilder()
	// go-ipld-prime v0.21's experimental ordering check incorrectly also
	// requires lexical order across differently sized keys. Decode normally,
	// then enforce canonicality by exact RFC7049 re-encoding below.
	if err := (dagcbor.DecodeOptions{AllowLinks: true}).Decode(builder, bytes.NewReader(encoded)); err != nil {
		return nil, err
	}
	node := builder.Build()
	if !validLexNode(node) {
		return nil, ErrSnapshotVerification
	}
	var canonical bytes.Buffer
	if err := (dagcbor.EncodeOptions{AllowLinks: true, MapSortMode: codec.MapSortMode_RFC7049}).Encode(node, &canonical); err != nil || !bytes.Equal(encoded, canonical.Bytes()) {
		return nil, ErrSnapshotVerification
	}
	return node, nil
}

// preflightCBORStructure walks definite-length CBOR without recursion. The
// canonical DAG-CBOR decoder below remains authoritative for data-model and
// encoding rules; this pass exists only to reject dangerous nesting before
// that recursive decoder is invoked.
func preflightCBORStructure(encoded []byte, maxDepth, maxItems int) error {
	if len(encoded) == 0 || maxDepth < 1 || maxItems < 1 {
		return ErrSnapshotVerification
	}
	remaining := []uint64{1}
	offset := 0
	items := 0
	for len(remaining) > 0 {
		last := len(remaining) - 1
		if remaining[last] == 0 {
			remaining = remaining[:last]
			continue
		}
		remaining[last]--
		items++
		if items > maxItems {
			return ErrSnapshotVerification
		}
		if offset >= len(encoded) {
			return ErrSnapshotVerification
		}
		initial := encoded[offset]
		offset++
		major := initial >> 5
		argument, consumed, err := readCBORArgument(initial&0x1f, encoded[offset:])
		if err != nil {
			return err
		}
		offset += consumed

		switch major {
		case 0, 1, 7:
			// Integers and simple values have no children. DAG-CBOR's decoder
			// and the lexical-node check reject unsupported simple values.
		case 2, 3:
			if argument > uint64(len(encoded)-offset) {
				return ErrSnapshotVerification
			}
			offset += int(argument)
		case 4:
			if argument > 0 {
				if len(remaining) > maxDepth {
					return ErrSnapshotVerification
				}
				remaining = append(remaining, argument)
			}
		case 5:
			if argument > ^uint64(0)/2 {
				return ErrSnapshotVerification
			}
			children := argument * 2
			if children > 0 {
				if len(remaining) > maxDepth {
					return ErrSnapshotVerification
				}
				remaining = append(remaining, children)
			}
		case 6:
			if len(remaining) > maxDepth {
				return ErrSnapshotVerification
			}
			remaining = append(remaining, 1)
		default:
			return ErrSnapshotVerification
		}
	}
	if offset != len(encoded) {
		return ErrSnapshotVerification
	}
	return nil
}

func readCBORArgument(additional byte, input []byte) (uint64, int, error) {
	switch {
	case additional < 24:
		return uint64(additional), 0, nil
	case additional == 24:
		if len(input) < 1 {
			return 0, 0, ErrSnapshotVerification
		}
		return uint64(input[0]), 1, nil
	case additional == 25:
		if len(input) < 2 {
			return 0, 0, ErrSnapshotVerification
		}
		return uint64(binary.BigEndian.Uint16(input[:2])), 2, nil
	case additional == 26:
		if len(input) < 4 {
			return 0, 0, ErrSnapshotVerification
		}
		return uint64(binary.BigEndian.Uint32(input[:4])), 4, nil
	case additional == 27:
		if len(input) < 8 {
			return 0, 0, ErrSnapshotVerification
		}
		return binary.BigEndian.Uint64(input[:8]), 8, nil
	default:
		// Indefinite-length and reserved encodings are not DAG-CBOR.
		return 0, 0, ErrSnapshotVerification
	}
}

func validLexNode(node datamodel.Node) bool {
	switch node.Kind() {
	case datamodel.Kind_Map:
		iterator := node.MapIterator()
		for !iterator.Done() {
			key, value, err := iterator.Next()
			if err != nil || key.Kind() != datamodel.Kind_String || !validLexNode(value) {
				return false
			}
		}
		return true
	case datamodel.Kind_List:
		iterator := node.ListIterator()
		for !iterator.Done() {
			_, value, err := iterator.Next()
			if err != nil || !validLexNode(value) {
				return false
			}
		}
		return true
	case datamodel.Kind_Null, datamodel.Kind_Bool, datamodel.Kind_Int, datamodel.Kind_String, datamodel.Kind_Bytes, datamodel.Kind_Link:
		return true
	default:
		return false
	}
}

func exactMapKeys(node datamodel.Node, expected ...string) bool {
	want := make(map[string]struct{}, len(expected))
	for _, key := range expected {
		want[key] = struct{}{}
	}
	iterator := node.MapIterator()
	for !iterator.Done() {
		keyNode, _, err := iterator.Next()
		if err != nil {
			return false
		}
		key, err := keyNode.AsString()
		if err != nil {
			return false
		}
		if _, ok := want[key]; !ok {
			return false
		}
		delete(want, key)
	}
	return len(want) == 0
}

func nodeCID(node datamodel.Node) (cid.Cid, bool) {
	link, err := node.AsLink()
	if err != nil {
		return cid.Undef, false
	}
	switch value := link.(type) {
	case cidlink.Link:
		return value.Cid, true
	case *cidlink.Link:
		return value.Cid, true
	default:
		return cid.Undef, false
	}
}

func validDAGCBORCID(value cid.Cid) bool {
	prefix := value.Prefix()
	return value.Version() == 1 && prefix.Codec == cid.DagCBOR && prefix.MhType == multihash.SHA2_256 && prefix.MhLength == sha256.Size
}

func recordTypeMatchesNode(node datamodel.Node, collection string) bool {
	if node == nil || node.Kind() != datamodel.Kind_Map {
		return false
	}
	typeNode, err := node.LookupByString("$type")
	if err != nil {
		return false
	}
	recordType, err := typeNode.AsString()
	return err == nil && recordType == collection
}

func sourceSnapshotID(target Target, snapshot verifiedCAR) string {
	hash := sha256.New()
	writeSnapshotField(hash, "comail-official-source-root-v1")
	writeSnapshotField(hash, target.Origin)
	writeSnapshotField(hash, target.SpaceURI)
	writeSnapshotField(hash, target.RepoDID)
	writeSnapshotField(hash, target.Epoch)
	writeSnapshotField(hash, snapshot.commit.Revision)
	writeSnapshotField(hash, snapshot.commitCID.String())
	writeSnapshotField(hash, snapshot.indexCID.String())
	return "sha256-" + hex.EncodeToString(hash.Sum(nil))
}

func normalizeSnapshotError(err error) error {
	if err == nil {
		return nil
	}
	for _, sentinel := range []error{
		context.Canceled, context.DeadlineExceeded, repository.ErrUnauthorized,
		repository.ErrRevoked, repository.ErrNotFound, repository.ErrTarget,
	} {
		if errors.Is(err, sentinel) {
			return err
		}
	}
	if errors.Is(err, ErrSnapshotVerification) {
		return err
	}
	return fmt.Errorf("%w: source read failed", ErrSnapshotVerification)
}
