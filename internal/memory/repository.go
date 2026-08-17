package memory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/comail-atproto/comail-space-host/internal/mailbox"
	"github.com/comail-atproto/comail-space-host/internal/repository"
)

type storedRecord struct {
	uri   string
	cid   string
	value json.RawMessage
}

type spaceState struct {
	target   repository.Target
	records  map[string]map[string]map[string]storedRecord
	blobRefs map[string]map[string]int
	rev      uint64
}

type Backend struct {
	mu     sync.RWMutex
	spaces map[string]*spaceState
	blobs  map[string]map[string][]byte
}

func NewBackend() *Backend {
	return &Backend{
		spaces: make(map[string]*spaceState),
		blobs:  make(map[string]map[string][]byte),
	}
}

type Session struct {
	backend         *Backend
	did             string
	credentialSpace string
	owner           bool
	revoked         atomic.Bool
}

func (b *Backend) OwnerSession(did string) *Session {
	return &Session{backend: b, did: did, owner: true}
}

func (b *Backend) SpaceCredentialSession(did, spaceURI string) *Session {
	return &Session{backend: b, did: did, credentialSpace: spaceURI}
}

func (s *Session) Revoke() { s.revoked.Store(true) }

func (s *Session) ProviderID() string { return "memory-v1" }

func (s *Session) Capabilities(context.Context) (repository.Capabilities, error) {
	if err := s.checkActive(); err != nil {
		return repository.Capabilities{}, err
	}
	return repository.Capabilities{
		AtomicApplyWrites: true,
		CompareAndSwap:    true,
		ReferencedBlobs:   true,
	}, nil
}

func (s *Session) EnsureMailbox(_ context.Context, recipientDID, key string) (repository.Target, error) {
	if err := s.checkActive(); err != nil {
		return repository.Target{}, err
	}
	if !s.owner || recipientDID == "" || recipientDID != s.did {
		return repository.Target{}, repository.ErrUnauthorized
	}
	if !validKey(key) {
		return repository.Target{}, fmt.Errorf("%w: invalid mailbox space key", repository.ErrTarget)
	}
	uri := fmt.Sprintf("at://%s/space/%s/%s", recipientDID, mailbox.MailboxSpaceType, key)
	target := repository.Target{
		ProviderOrigin: "memory://local",
		SpaceURI:       uri,
		RepoDID:        recipientDID,
		Epoch:          "memory-v1",
	}
	s.backend.mu.Lock()
	defer s.backend.mu.Unlock()
	if existing, ok := s.backend.spaces[uri]; ok {
		if existing.target != target {
			return repository.Target{}, repository.ErrTarget
		}
		return target, nil
	}
	s.backend.spaces[uri] = &spaceState{
		target:   target,
		records:  make(map[string]map[string]map[string]storedRecord),
		blobRefs: make(map[string]map[string]int),
	}
	return target, nil
}

func (s *Session) UploadBlob(_ context.Context, target repository.Target, data []byte, mimeType string) (mailbox.BlobRef, error) {
	if err := s.checkActive(); err != nil {
		return mailbox.BlobRef{}, err
	}
	if mimeType == "" || len(data) == 0 {
		return mailbox.BlobRef{}, fmt.Errorf("%w: empty blob or MIME type", mailbox.ErrInvalidRecord)
	}
	s.backend.mu.Lock()
	defer s.backend.mu.Unlock()
	if _, err := s.authWriteLocked(target); err != nil {
		return mailbox.BlobRef{}, err
	}
	sum := sha256.Sum256(data)
	cid := "bafk-lab-sha256-" + hex.EncodeToString(sum[:])
	if s.backend.blobs[target.RepoDID] == nil {
		s.backend.blobs[target.RepoDID] = make(map[string][]byte)
	}
	s.backend.blobs[target.RepoDID][cid] = append([]byte(nil), data...)
	return mailbox.BlobRef{
		Type: "blob", Ref: mailbox.CIDLink{Link: cid}, MIMEType: mimeType, Size: int64(len(data)),
	}, nil
}

func (s *Session) ApplyWrites(_ context.Context, target repository.Target, writes []repository.Write) (repository.Commit, error) {
	if err := s.checkActive(); err != nil {
		return repository.Commit{}, err
	}
	if len(writes) == 0 {
		return repository.Commit{}, fmt.Errorf("%w: empty write batch", mailbox.ErrInvalidRecord)
	}
	s.backend.mu.Lock()
	defer s.backend.mu.Unlock()
	space, err := s.authWriteLocked(target)
	if err != nil {
		return repository.Commit{}, err
	}
	next := cloneSpace(space)
	results := make([]repository.WriteResult, 0, len(writes))
	for _, write := range writes {
		result, err := s.applyOneLocked(next, target, write)
		if err != nil {
			return repository.Commit{}, err
		}
		results = append(results, result)
	}
	next.rev++
	s.backend.spaces[target.SpaceURI] = next
	return repository.Commit{Rev: fmt.Sprintf("mem-%d", next.rev), Hash: spaceHash(next), Results: results}, nil
}

func (s *Session) PutRecordCAS(_ context.Context, target repository.Target, collection, rkey string, value any, expectedCID string) (repository.Record, error) {
	if err := s.checkActive(); err != nil {
		return repository.Record{}, err
	}
	s.backend.mu.Lock()
	defer s.backend.mu.Unlock()
	space, err := s.authWriteLocked(target)
	if err != nil {
		return repository.Record{}, err
	}
	current, ok := lookupRecord(space, target.RepoDID, collection, rkey)
	if !ok || expectedCID == "" || current.cid != expectedCID {
		return repository.Record{}, repository.ErrConflict
	}
	next := cloneSpace(space)
	result, err := s.applyOneLocked(next, target, repository.Write{
		Action: repository.Update, Collection: collection, RKey: rkey, Value: value, SwapCID: expectedCID,
	})
	if err != nil {
		return repository.Record{}, err
	}
	next.rev++
	s.backend.spaces[target.SpaceURI] = next
	record, _ := lookupRecord(next, target.RepoDID, collection, rkey)
	return exportRecord(collection, rkey, record, result), nil
}

func (s *Session) GetRecord(_ context.Context, target repository.Target, collection, rkey string) (repository.Record, error) {
	if err := s.checkActive(); err != nil {
		return repository.Record{}, err
	}
	s.backend.mu.RLock()
	defer s.backend.mu.RUnlock()
	space, err := s.authReadLocked(target)
	if err != nil {
		return repository.Record{}, err
	}
	record, ok := lookupRecord(space, target.RepoDID, collection, rkey)
	if !ok {
		return repository.Record{}, repository.ErrNotFound
	}
	return exportRecord(collection, rkey, record, repository.WriteResult{}), nil
}

func (s *Session) ListRecords(_ context.Context, target repository.Target, collection string) ([]repository.Record, error) {
	if err := s.checkActive(); err != nil {
		return nil, err
	}
	s.backend.mu.RLock()
	defer s.backend.mu.RUnlock()
	space, err := s.authReadLocked(target)
	if err != nil {
		return nil, err
	}
	collectionRecords := space.records[target.RepoDID][collection]
	keys := make([]string, 0, len(collectionRecords))
	for rkey := range collectionRecords {
		keys = append(keys, rkey)
	}
	sort.Strings(keys)
	out := make([]repository.Record, 0, len(keys))
	for _, rkey := range keys {
		out = append(out, exportRecord(collection, rkey, collectionRecords[rkey], repository.WriteResult{}))
	}
	return out, nil
}

func (s *Session) GetBlob(_ context.Context, target repository.Target, cid string) ([]byte, error) {
	if err := s.checkActive(); err != nil {
		return nil, err
	}
	s.backend.mu.RLock()
	defer s.backend.mu.RUnlock()
	space, err := s.authReadLocked(target)
	if err != nil {
		return nil, err
	}
	if space.blobRefs[target.RepoDID][cid] <= 0 {
		return nil, repository.ErrNotFound
	}
	data, ok := s.backend.blobs[target.RepoDID][cid]
	if !ok {
		return nil, repository.ErrNotFound
	}
	return append([]byte(nil), data...), nil
}

func (s *Session) checkActive() error {
	if s == nil || s.backend == nil {
		return repository.ErrUnauthorized
	}
	if s.revoked.Load() {
		return repository.ErrRevoked
	}
	return nil
}

func (s *Session) authWriteLocked(target repository.Target) (*spaceState, error) {
	if !s.owner || target.RepoDID != s.did {
		return nil, repository.ErrUnauthorized
	}
	space, ok := s.backend.spaces[target.SpaceURI]
	if !ok {
		return nil, repository.ErrNotFound
	}
	if space.target != target || !strings.HasPrefix(target.SpaceURI, "at://"+s.did+"/space/") {
		return nil, repository.ErrTarget
	}
	return space, nil
}

func (s *Session) authReadLocked(target repository.Target) (*spaceState, error) {
	space, ok := s.backend.spaces[target.SpaceURI]
	if !ok {
		return nil, repository.ErrNotFound
	}
	if space.target != target {
		return nil, repository.ErrTarget
	}
	if s.owner && target.RepoDID == s.did {
		return space, nil
	}
	if s.credentialSpace == target.SpaceURI {
		return space, nil
	}
	return nil, repository.ErrUnauthorized
}

func (s *Session) applyOneLocked(space *spaceState, target repository.Target, write repository.Write) (repository.WriteResult, error) {
	if !validCollection(write.Collection) || !validKey(write.RKey) {
		return repository.WriteResult{}, fmt.Errorf("%w: invalid collection or rkey", mailbox.ErrInvalidRecord)
	}
	existing, exists := lookupRecord(space, target.RepoDID, write.Collection, write.RKey)
	switch write.Action {
	case repository.Create:
		if write.SwapCID != "" {
			return repository.WriteResult{}, mailbox.ErrInvalidRecord
		}
		if exists {
			return repository.WriteResult{}, repository.ErrExists
		}
	case repository.Update:
		if !exists {
			return repository.WriteResult{}, repository.ErrNotFound
		}
		if write.SwapCID != "" && existing.cid != write.SwapCID {
			return repository.WriteResult{}, repository.ErrConflict
		}
	case repository.Delete:
		if !exists {
			return repository.WriteResult{}, repository.ErrNotFound
		}
		if write.SwapCID != "" && existing.cid != write.SwapCID {
			return repository.WriteResult{}, repository.ErrConflict
		}
		removeBlobRefs(space, target.RepoDID, existing.value)
		delete(space.records[target.RepoDID][write.Collection], write.RKey)
		return repository.WriteResult{}, nil
	default:
		return repository.WriteResult{}, fmt.Errorf("%w: unknown action %q", mailbox.ErrInvalidRecord, write.Action)
	}
	value, err := json.Marshal(write.Value)
	if err != nil {
		return repository.WriteResult{}, fmt.Errorf("marshal record: %w", err)
	}
	blobCIDs, err := findBlobCIDs(value)
	if err != nil {
		return repository.WriteResult{}, err
	}
	for _, cid := range blobCIDs {
		if _, ok := s.backend.blobs[target.RepoDID][cid]; !ok {
			return repository.WriteResult{}, fmt.Errorf("%w: record references missing blob %s", repository.ErrNotFound, cid)
		}
	}
	if exists {
		removeBlobRefs(space, target.RepoDID, existing.value)
	}
	addBlobRefs(space, target.RepoDID, blobCIDs)
	if space.records[target.RepoDID] == nil {
		space.records[target.RepoDID] = make(map[string]map[string]storedRecord)
	}
	if space.records[target.RepoDID][write.Collection] == nil {
		space.records[target.RepoDID][write.Collection] = make(map[string]storedRecord)
	}
	uri := target.SpaceURI + "/" + target.RepoDID + "/" + write.Collection + "/" + write.RKey
	cid := recordCID(value)
	space.records[target.RepoDID][write.Collection][write.RKey] = storedRecord{uri: uri, cid: cid, value: append(json.RawMessage(nil), value...)}
	return repository.WriteResult{URI: uri, CID: cid}, nil
}

func lookupRecord(space *spaceState, repo, collection, rkey string) (storedRecord, bool) {
	if space == nil || space.records[repo] == nil || space.records[repo][collection] == nil {
		return storedRecord{}, false
	}
	record, ok := space.records[repo][collection][rkey]
	return record, ok
}

func exportRecord(collection, rkey string, record storedRecord, result repository.WriteResult) repository.Record {
	uri, cid := record.uri, record.cid
	if result.URI != "" {
		uri = result.URI
	}
	if result.CID != "" {
		cid = result.CID
	}
	return repository.Record{URI: uri, Collection: collection, RKey: rkey, CID: cid, Value: append(json.RawMessage(nil), record.value...)}
}

func cloneSpace(in *spaceState) *spaceState {
	out := &spaceState{
		target: in.target, rev: in.rev,
		records:  make(map[string]map[string]map[string]storedRecord, len(in.records)),
		blobRefs: make(map[string]map[string]int, len(in.blobRefs)),
	}
	for repo, collections := range in.records {
		out.records[repo] = make(map[string]map[string]storedRecord, len(collections))
		for collection, records := range collections {
			out.records[repo][collection] = make(map[string]storedRecord, len(records))
			for rkey, record := range records {
				record.value = append(json.RawMessage(nil), record.value...)
				out.records[repo][collection][rkey] = record
			}
		}
	}
	for repo, refs := range in.blobRefs {
		out.blobRefs[repo] = make(map[string]int, len(refs))
		for cid, count := range refs {
			out.blobRefs[repo][cid] = count
		}
	}
	return out
}

func findBlobCIDs(value []byte) ([]string, error) {
	var decoded any
	if err := json.Unmarshal(value, &decoded); err != nil {
		return nil, fmt.Errorf("decode record: %w", err)
	}
	var out []string
	var walk func(any) error
	walk = func(node any) error {
		switch typed := node.(type) {
		case map[string]any:
			if typed["$type"] == "blob" {
				ref, ok := typed["ref"].(map[string]any)
				if !ok {
					return fmt.Errorf("%w: malformed blob reference", mailbox.ErrInvalidRecord)
				}
				cid, ok := ref["$link"].(string)
				if !ok || cid == "" {
					return fmt.Errorf("%w: empty blob CID", mailbox.ErrInvalidRecord)
				}
				out = append(out, cid)
			}
			for _, child := range typed {
				if err := walk(child); err != nil {
					return err
				}
			}
		case []any:
			for _, child := range typed {
				if err := walk(child); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(decoded); err != nil {
		return nil, err
	}
	return out, nil
}

func addBlobRefs(space *spaceState, repo string, cids []string) {
	if space.blobRefs[repo] == nil {
		space.blobRefs[repo] = make(map[string]int)
	}
	for _, cid := range cids {
		space.blobRefs[repo][cid]++
	}
}

func removeBlobRefs(space *spaceState, repo string, value []byte) {
	cids, _ := findBlobCIDs(value)
	for _, cid := range cids {
		space.blobRefs[repo][cid]--
		if space.blobRefs[repo][cid] <= 0 {
			delete(space.blobRefs[repo], cid)
		}
	}
}

func recordCID(value []byte) string {
	sum := sha256.Sum256(value)
	return "bafy-lab-record-" + hex.EncodeToString(sum[:])
}

func spaceHash(space *spaceState) string {
	var entries []string
	for repo, collections := range space.records {
		for collection, records := range collections {
			for rkey, record := range records {
				entries = append(entries, repo+"\x00"+collection+"\x00"+rkey+"\x00"+record.cid)
			}
		}
	}
	sort.Strings(entries)
	sum := sha256.Sum256([]byte(strings.Join(entries, "\n")))
	return hex.EncodeToString(sum[:])
}

func validCollection(value string) bool {
	return strings.Count(value, ".") >= 2 && !strings.ContainsAny(value, "/?# ")
}

func validKey(value string) bool {
	if value == "" || len(value) > 512 || value == "." || value == ".." {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("._~:-", r) {
			continue
		}
		return false
	}
	return true
}

var _ repository.Repository = (*Session)(nil)
