package happyview

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"reflect"
	"strings"

	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/comail-atproto/comail-space-host/internal/mailbox"
	"github.com/comail-atproto/comail-space-host/internal/repository"
)

const (
	CertifiedEpoch         = "f50b2afdaf207a2ba91d76cdad7a981a87785294"
	BlobChunkCollection    = "email.atmos.blobChunk"
	BlobManifestCollection = "email.atmos.blobManifest"
	BlobIndexCollection    = "email.atmos.blobIndex"

	createSpaceNSID  = "com.atproto.simplespace.createSpace"
	listMembersNSID  = "com.atproto.simplespace.listMembers"
	listSpacesNSID   = "com.atproto.space.listSpaces"
	getSpaceNSID     = "com.atproto.space.getSpace"
	applyWritesNSID  = "com.atproto.space.applyWrites"
	putRecordNSID    = "com.atproto.space.putRecord"
	getRecordNSID    = "com.atproto.space.getRecord"
	listRecordsNSID  = "com.atproto.space.listRecords"
	latestCommitNSID = "com.atproto.space.getLatestCommit"

	chunkSize       = 384 * 1024
	maxJSONResponse = 2 * 1024 * 1024
	maxListRecords  = 1_000_000
)

type Doer interface {
	Do(context.Context, *http.Request, string) (*http.Response, error)
}

type Config struct {
	Origin            string
	DID               string
	Epoch             string
	RequiredWriterDID string
	AllowHTTP         bool
	AllowWrites       bool
}

type Client struct {
	origin            string
	did               string
	epoch             string
	requiredWriterDID string
	doer              Doer
	allowWrites       bool
}

type ProviderError struct {
	Status int
	Code   string
}

func (e *ProviderError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("happyview: HTTP %d", e.Status)
	}
	return fmt.Sprintf("happyview: HTTP %d (%s)", e.Status, e.Code)
}

type chunkRecord struct {
	Type       string `json:"$type"`
	SHA256     string `json:"sha256"`
	Size       int    `json:"size"`
	DataBase64 string `json:"dataBase64"`
}

type chunkReference struct {
	RKey   string `json:"rkey"`
	SHA256 string `json:"sha256"`
	Size   int    `json:"size"`
}

type manifestRecord struct {
	Type     string           `json:"$type"`
	SHA256   string           `json:"sha256"`
	Size     int              `json:"size"`
	MIMEType string           `json:"mimeType"`
	Chunks   []chunkReference `json:"chunks"`
}

type indexRecord struct {
	Type         string `json:"$type"`
	ManifestRKey string `json:"manifestRKey"`
	ManifestCID  string `json:"manifestCid"`
}

func New(cfg Config, doer Doer) (*Client, error) {
	if doer == nil {
		return nil, errors.New("happyview: authenticated request doer is required")
	}
	origin, err := cleanOrigin(cfg.Origin, cfg.AllowHTTP)
	if err != nil {
		return nil, err
	}
	if _, err := syntax.ParseDID(cfg.DID); err != nil {
		return nil, errors.New("happyview: exact account DID is required")
	}
	if cfg.RequiredWriterDID != "" {
		writer, err := syntax.ParseDID(cfg.RequiredWriterDID)
		if err != nil || writer.String() != cfg.RequiredWriterDID {
			return nil, errors.New("happyview: exact required writer DID is invalid")
		}
	}
	if cfg.Epoch != CertifiedEpoch {
		return nil, fmt.Errorf("%w: HappyView epoch is not certified", repository.ErrUnsupported)
	}
	return &Client{
		origin: origin, did: cfg.DID, epoch: cfg.Epoch, requiredWriterDID: cfg.RequiredWriterDID,
		doer: doer, allowWrites: cfg.AllowWrites,
	}, nil
}

func (c *Client) ProviderID() string { return "happyview@" + c.epoch }

func (c *Client) Capabilities(context.Context) (repository.Capabilities, error) {
	return repository.Capabilities{AtomicApplyWrites: true, CompareAndSwap: true, ReferencedBlobs: true, RepoOplog: true, CARExport: true, Notifications: true}, nil
}

func (c *Client) EnsureMailbox(ctx context.Context, recipientDID, key string) (repository.Target, error) {
	if err := c.requireWrites(); err != nil {
		return repository.Target{}, err
	}
	if recipientDID != c.did || !validKey(key) {
		return repository.Target{}, repository.ErrTarget
	}
	target := repository.Target{ProviderOrigin: c.origin, SpaceURI: fmt.Sprintf("at://%s/space/%s/%s", c.did, mailbox.MailboxSpaceType, key), RepoDID: c.did, Epoch: c.epoch}
	spaces, err := c.listSpaces(ctx)
	if err != nil {
		return repository.Target{}, err
	}
	for _, space := range spaces {
		if space.URI == target.SpaceURI {
			if !space.IsOwner {
				return repository.Target{}, fmt.Errorf("%w: mailbox exists without owner binding", repository.ErrTarget)
			}
			if err := c.verifyMailboxSpace(ctx, target); err != nil {
				return repository.Target{}, err
			}
			return target, nil
		}
	}
	var out struct {
		URI string `json:"uri"`
	}
	err = c.doJSON(ctx, http.MethodPost, createSpaceNSID, nil, map[string]any{
		"type":       mailbox.MailboxSpaceType,
		"skey":       key,
		"mintPolicy": "member-list",
		"appAccess":  map[string]any{"type": "open"},
		"config": map[string]any{
			"membershipPublic":   false,
			"recordsPublic":      false,
			"allowedCollections": []string{mailbox.FolderCollection, mailbox.MessageCollection, mailbox.MessageStateCollection, BlobChunkCollection, BlobManifestCollection, BlobIndexCollection},
		},
	}, &out)
	if err != nil {
		if errors.Is(err, repository.ErrExists) || errors.Is(err, repository.ErrConflict) {
			spaces, listErr := c.listSpaces(ctx)
			if listErr != nil {
				return repository.Target{}, errors.Join(err, listErr)
			}
			for _, space := range spaces {
				if space.URI == target.SpaceURI && space.IsOwner {
					if verifyErr := c.verifyMailboxSpace(ctx, target); verifyErr != nil {
						return repository.Target{}, errors.Join(err, verifyErr)
					}
					return target, nil
				}
			}
		}
		return repository.Target{}, err
	}
	if out.URI != target.SpaceURI {
		return repository.Target{}, fmt.Errorf("%w: createSpace returned unexpected URI", repository.ErrTarget)
	}
	if err := c.verifyMailboxSpace(ctx, target); err != nil {
		return repository.Target{}, err
	}
	return target, nil
}

// OpenMailbox verifies an already-provisioned mailbox without attempting to
// create it. Production adapters use this with a service-auth identity that is
// an explicit write member of the user's private space; initial ownership and
// membership grants remain user-controlled operations.
func (c *Client) OpenMailbox(ctx context.Context, recipientDID, key string) (repository.Target, error) {
	if err := c.requireWrites(); err != nil {
		return repository.Target{}, err
	}
	if recipientDID != c.did || !validKey(key) || c.requiredWriterDID == "" {
		return repository.Target{}, repository.ErrTarget
	}
	target := repository.Target{ProviderOrigin: c.origin, SpaceURI: fmt.Sprintf("at://%s/space/%s/%s", c.did, mailbox.MailboxSpaceType, key), RepoDID: c.did, Epoch: c.epoch}
	if err := c.verifyMailboxSpace(ctx, target); err != nil {
		return repository.Target{}, err
	}
	if err := c.verifyRequiredWriter(ctx, target); err != nil {
		return repository.Target{}, err
	}
	return target, nil
}

func (c *Client) verifyRequiredWriter(ctx context.Context, target repository.Target) error {
	var out struct {
		Members []struct {
			DID    string `json:"did"`
			Access string `json:"access"`
		} `json:"members"`
	}
	if err := c.doJSON(ctx, http.MethodGet, listMembersNSID, url.Values{"space": {target.SpaceURI}}, nil, &out); err != nil {
		return err
	}
	matches := 0
	for _, member := range out.Members {
		if member.DID != c.requiredWriterDID {
			continue
		}
		matches++
		if member.Access != "write" {
			return repository.ErrUnauthorized
		}
	}
	if matches != 1 {
		return repository.ErrUnauthorized
	}
	return nil
}

func (c *Client) verifyMailboxSpace(ctx context.Context, target repository.Target) error {
	var out struct {
		URI   string `json:"uri"`
		Space struct {
			DID          string         `json:"did"`
			AuthorityDID string         `json:"authority_did"`
			CreatorDID   string         `json:"creator_did"`
			Type         string         `json:"type"`
			SKey         string         `json:"skey"`
			MintPolicy   string         `json:"mint_policy"`
			AppAccess    map[string]any `json:"app_access"`
			Config       map[string]any `json:"config"`
		} `json:"space"`
	}
	if err := c.doJSON(ctx, http.MethodGet, getSpaceNSID, url.Values{"space": {target.SpaceURI}}, nil, &out); err != nil {
		return err
	}
	space := out.Space
	if out.URI != target.SpaceURI || space.DID != c.did || space.AuthorityDID != c.did || space.CreatorDID != c.did ||
		space.Type != mailbox.MailboxSpaceType || space.SKey == "" || target.SpaceURI != fmt.Sprintf("at://%s/space/%s/%s", c.did, space.Type, space.SKey) ||
		space.MintPolicy != "member-list" || space.AppAccess["type"] != "open" {
		return fmt.Errorf("%w: mailbox space identity or policy mismatch", repository.ErrTarget)
	}
	membershipPublic, membershipPresent := space.Config["membership_public"].(bool)
	recordsPublic, recordsPresent := space.Config["records_public"].(bool)
	if !membershipPresent || !recordsPresent || membershipPublic || recordsPublic {
		return fmt.Errorf("%w: mailbox space is not explicitly private", repository.ErrTarget)
	}
	allowed, ok := space.Config["allowedCollections"].([]any)
	if !ok {
		return fmt.Errorf("%w: mailbox space lacks an exact collection allowlist", repository.ErrTarget)
	}
	want := map[string]bool{
		mailbox.FolderCollection:       true,
		mailbox.MessageCollection:      true,
		mailbox.MessageStateCollection: true,
		BlobChunkCollection:            true,
		BlobManifestCollection:         true,
		BlobIndexCollection:            true,
	}
	if len(allowed) != len(want) {
		return fmt.Errorf("%w: mailbox space collection allowlist mismatch", repository.ErrTarget)
	}
	for _, value := range allowed {
		collection, ok := value.(string)
		if !ok || !want[collection] {
			return fmt.Errorf("%w: mailbox space collection allowlist mismatch", repository.ErrTarget)
		}
		delete(want, collection)
	}
	if len(want) != 0 {
		return fmt.Errorf("%w: mailbox space collection allowlist mismatch", repository.ErrTarget)
	}
	return nil
}

func (c *Client) UploadBlob(ctx context.Context, target repository.Target, data []byte, mimeType string) (mailbox.BlobRef, error) {
	if err := c.requireWrites(); err != nil {
		return mailbox.BlobRef{}, err
	}
	if err := c.validateTarget(target); err != nil {
		return mailbox.BlobRef{}, err
	}
	if len(data) == 0 || mimeType != mailbox.MessageMIMEType {
		return mailbox.BlobRef{}, mailbox.ErrInvalidRecord
	}
	if len(data) > mailbox.MaxRawMessageBytes {
		return mailbox.BlobRef{}, mailbox.ErrMessageTooLarge
	}

	refs := make([]chunkReference, 0, (len(data)+chunkSize-1)/chunkSize)
	for offset := 0; offset < len(data); offset += chunkSize {
		end := offset + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk := data[offset:end]
		rkey := chunkKey(chunk)
		record := chunkRecord{Type: BlobChunkCollection, SHA256: mailbox.RawSHA256(chunk), Size: len(chunk), DataBase64: encodeBase64(chunk)}
		if _, err := c.ensureRecord(ctx, target, BlobChunkCollection, rkey, record); err != nil {
			return mailbox.BlobRef{}, fmt.Errorf("happyview: store private blob chunk: %w", err)
		}
		refs = append(refs, chunkReference{RKey: rkey, SHA256: record.SHA256, Size: record.Size})
	}

	manifestRKey := manifestKey(data)
	manifest := manifestRecord{Type: BlobManifestCollection, SHA256: mailbox.RawSHA256(data), Size: len(data), MIMEType: mimeType, Chunks: refs}
	manifestCID, err := c.ensureRecord(ctx, target, BlobManifestCollection, manifestRKey, manifest)
	if err != nil {
		return mailbox.BlobRef{}, fmt.Errorf("happyview: store private blob manifest: %w", err)
	}
	index := indexRecord{Type: BlobIndexCollection, ManifestRKey: manifestRKey, ManifestCID: manifestCID}
	if _, err := c.ensureRecord(ctx, target, BlobIndexCollection, indexKey(manifestCID), index); err != nil {
		return mailbox.BlobRef{}, fmt.Errorf("happyview: store private blob index: %w", err)
	}
	return mailbox.BlobRef{Type: "blob", Ref: mailbox.CIDLink{Link: manifestCID}, MIMEType: mimeType, Size: int64(len(data))}, nil
}

func (c *Client) ApplyWrites(ctx context.Context, target repository.Target, writes []repository.Write) (repository.Commit, error) {
	if err := c.requireWrites(); err != nil {
		return repository.Commit{}, err
	}
	if err := c.validateTarget(target); err != nil {
		return repository.Commit{}, err
	}
	results, err := c.applyRaw(ctx, target, writes)
	if err != nil {
		return repository.Commit{}, err
	}
	rev, hash, err := c.latestCommit(ctx, target)
	if err != nil {
		return repository.Commit{}, err
	}
	return repository.Commit{Rev: rev, Hash: hash, Results: results}, nil
}

func (c *Client) PutRecordCAS(ctx context.Context, target repository.Target, collection, rkey string, value any, expectedCID string) (repository.Record, error) {
	if err := c.requireWrites(); err != nil {
		return repository.Record{}, err
	}
	if err := c.validateTarget(target); err != nil {
		return repository.Record{}, err
	}
	if !validCollection(collection) || !validKey(rkey) || value == nil || expectedCID == "" {
		return repository.Record{}, mailbox.ErrInvalidRecord
	}
	var out struct {
		URI string `json:"uri"`
		CID string `json:"cid"`
	}
	err := c.doJSON(ctx, http.MethodPost, putRecordNSID, nil, map[string]any{"space": target.SpaceURI, "collection": collection, "rkey": rkey, "record": value, "swapRecord": expectedCID}, &out)
	if err != nil {
		return repository.Record{}, err
	}
	if out.URI != recordURI(target, collection, rkey) || out.CID == "" {
		return repository.Record{}, fmt.Errorf("%w: putRecord result target mismatch", repository.ErrTarget)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return repository.Record{}, err
	}
	return repository.Record{URI: out.URI, Collection: collection, RKey: rkey, CID: out.CID, Value: encoded}, nil
}

func (c *Client) GetRecord(ctx context.Context, target repository.Target, collection, rkey string) (repository.Record, error) {
	if err := c.validateTarget(target); err != nil {
		return repository.Record{}, err
	}
	if !validCollection(collection) || !validKey(rkey) {
		return repository.Record{}, mailbox.ErrInvalidRecord
	}
	var out struct {
		URI   string          `json:"uri"`
		CID   string          `json:"cid"`
		Value json.RawMessage `json:"value"`
	}
	err := c.doJSON(ctx, http.MethodGet, getRecordNSID, url.Values{"space": {target.SpaceURI}, "collection": {collection}, "rkey": {rkey}}, nil, &out)
	if err != nil {
		return repository.Record{}, err
	}
	if out.URI != recordURI(target, collection, rkey) || out.CID == "" || len(out.Value) == 0 {
		return repository.Record{}, fmt.Errorf("%w: getRecord result target mismatch", repository.ErrTarget)
	}
	return repository.Record{URI: out.URI, Collection: collection, RKey: rkey, CID: out.CID, Value: out.Value}, nil
}

func (c *Client) ListRecords(ctx context.Context, target repository.Target, collection string) ([]repository.Record, error) {
	if err := c.validateTarget(target); err != nil {
		return nil, err
	}
	if collection != "" && !validCollection(collection) {
		return nil, mailbox.ErrInvalidRecord
	}
	params := url.Values{"space": {target.SpaceURI}, "repo": {target.RepoDID}, "limit": {"100"}}
	if collection != "" {
		params.Set("collection", collection)
	}
	var records []repository.Record
	seen := map[string]bool{}
	for {
		var out struct {
			Cursor  string `json:"cursor"`
			Records []struct {
				Collection string `json:"collection"`
				RKey       string `json:"rkey"`
				CID        string `json:"cid"`
			} `json:"records"`
		}
		if err := c.doJSON(ctx, http.MethodGet, listRecordsNSID, params, nil, &out); err != nil {
			return nil, err
		}
		for _, item := range out.Records {
			if item.CID == "" || !validCollection(item.Collection) || !validKey(item.RKey) || (collection != "" && item.Collection != collection) {
				return nil, fmt.Errorf("%w: malformed HappyView record listing", mailbox.ErrIntegrity)
			}
			record, err := c.GetRecord(ctx, target, item.Collection, item.RKey)
			if err != nil {
				return nil, err
			}
			if record.CID != item.CID {
				return nil, fmt.Errorf("%w: listed record changed during snapshot", mailbox.ErrIntegrity)
			}
			records = append(records, record)
			if len(records) > maxListRecords {
				return nil, fmt.Errorf("%w: record inventory exceeds safety bound", mailbox.ErrInvalidRecord)
			}
		}
		if out.Cursor == "" {
			return records, nil
		}
		if seen[out.Cursor] {
			return nil, fmt.Errorf("%w: provider repeated cursor", mailbox.ErrIntegrity)
		}
		seen[out.Cursor] = true
		params.Set("cursor", out.Cursor)
	}
}

func (c *Client) GetBlob(ctx context.Context, target repository.Target, cid string) ([]byte, error) {
	if err := c.validateTarget(target); err != nil {
		return nil, err
	}
	if cid == "" || strings.ContainsAny(cid, " /?#") {
		return nil, mailbox.ErrInvalidRecord
	}
	indexStored, err := c.GetRecord(ctx, target, BlobIndexCollection, indexKey(cid))
	if err != nil {
		return nil, err
	}
	var index indexRecord
	if json.Unmarshal(indexStored.Value, &index) != nil || index.Type != BlobIndexCollection || index.ManifestCID != cid || !validKey(index.ManifestRKey) {
		return nil, fmt.Errorf("%w: corrupt private blob index", mailbox.ErrIntegrity)
	}
	manifestStored, err := c.GetRecord(ctx, target, BlobManifestCollection, index.ManifestRKey)
	if err != nil {
		return nil, err
	}
	if manifestStored.CID != cid {
		return nil, fmt.Errorf("%w: private blob manifest CID mismatch", mailbox.ErrIntegrity)
	}
	var manifest manifestRecord
	if json.Unmarshal(manifestStored.Value, &manifest) != nil || manifest.Type != BlobManifestCollection || manifest.MIMEType != mailbox.MessageMIMEType || manifest.Size <= 0 || manifest.Size > mailbox.MaxRawMessageBytes || len(manifest.Chunks) == 0 || len(manifest.Chunks) > 32 {
		return nil, fmt.Errorf("%w: invalid private blob manifest", mailbox.ErrIntegrity)
	}
	data := make([]byte, 0, manifest.Size)
	for _, ref := range manifest.Chunks {
		if !validKey(ref.RKey) || ref.Size <= 0 || ref.Size > chunkSize {
			return nil, fmt.Errorf("%w: invalid private blob chunk reference", mailbox.ErrIntegrity)
		}
		stored, err := c.GetRecord(ctx, target, BlobChunkCollection, ref.RKey)
		if err != nil {
			return nil, err
		}
		var chunk chunkRecord
		if json.Unmarshal(stored.Value, &chunk) != nil || chunk.Type != BlobChunkCollection || chunk.SHA256 != ref.SHA256 || chunk.Size != ref.Size {
			return nil, fmt.Errorf("%w: private blob chunk metadata mismatch", mailbox.ErrIntegrity)
		}
		decoded, err := base64.StdEncoding.Strict().DecodeString(chunk.DataBase64)
		if err != nil || len(decoded) != chunk.Size || mailbox.RawSHA256(decoded) != chunk.SHA256 || len(data)+len(decoded) > mailbox.MaxRawMessageBytes {
			return nil, fmt.Errorf("%w: private blob chunk integrity mismatch", mailbox.ErrIntegrity)
		}
		data = append(data, decoded...)
	}
	if len(data) != manifest.Size || mailbox.RawSHA256(data) != manifest.SHA256 {
		return nil, fmt.Errorf("%w: reconstructed private blob mismatch", mailbox.ErrIntegrity)
	}
	return data, nil
}

func (c *Client) ensureRecord(ctx context.Context, target repository.Target, collection, rkey string, value any) (string, error) {
	want, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	existing, err := c.GetRecord(ctx, target, collection, rkey)
	if err == nil {
		if !jsonEqual(existing.Value, want) {
			return "", fmt.Errorf("%w: deterministic private blob record differs", mailbox.ErrIntegrity)
		}
		return existing.CID, nil
	}
	if !errors.Is(err, repository.ErrNotFound) {
		return "", err
	}
	results, err := c.applyRaw(ctx, target, []repository.Write{{Action: repository.Create, Collection: collection, RKey: rkey, Value: value}})
	if err != nil {
		if errors.Is(err, repository.ErrExists) || errors.Is(err, repository.ErrConflict) {
			existing, getErr := c.GetRecord(ctx, target, collection, rkey)
			if getErr != nil {
				return "", errors.Join(err, getErr)
			}
			if !jsonEqual(existing.Value, want) {
				return "", fmt.Errorf("%w: concurrent private blob record differs", mailbox.ErrIntegrity)
			}
			return existing.CID, nil
		}
		return "", err
	}
	if len(results) != 1 || results[0].CID == "" {
		return "", fmt.Errorf("%w: incomplete private blob receipt", mailbox.ErrIntegrity)
	}
	if _, _, err := c.latestCommit(ctx, target); err != nil {
		return "", err
	}
	return results[0].CID, nil
}

func (c *Client) applyRaw(ctx context.Context, target repository.Target, writes []repository.Write) ([]repository.WriteResult, error) {
	if len(writes) == 0 || len(writes) > 200 {
		return nil, mailbox.ErrInvalidRecord
	}
	wire := make([]map[string]any, 0, len(writes))
	for _, write := range writes {
		if !validCollection(write.Collection) || !validKey(write.RKey) {
			return nil, mailbox.ErrInvalidRecord
		}
		item := map[string]any{"action": string(write.Action), "collection": write.Collection, "rkey": write.RKey}
		if write.SwapCID != "" {
			item["swapRecord"] = write.SwapCID
		}
		switch write.Action {
		case repository.Create, repository.Update:
			if write.Value == nil {
				return nil, mailbox.ErrInvalidRecord
			}
			item["value"] = write.Value
		case repository.Delete:
		default:
			return nil, mailbox.ErrInvalidRecord
		}
		wire = append(wire, item)
	}
	var out struct {
		Results []struct {
			URI string `json:"uri"`
			CID string `json:"cid"`
		} `json:"results"`
	}
	if err := c.doJSON(ctx, http.MethodPost, applyWritesNSID, nil, map[string]any{"space": target.SpaceURI, "writes": wire}, &out); err != nil {
		return nil, err
	}
	if len(out.Results) != len(writes) {
		return nil, fmt.Errorf("%w: incomplete applyWrites receipt", mailbox.ErrIntegrity)
	}
	results := make([]repository.WriteResult, len(writes))
	for i, result := range out.Results {
		if writes[i].Action != repository.Delete && (result.URI != recordURI(target, writes[i].Collection, writes[i].RKey) || result.CID == "") {
			return nil, fmt.Errorf("%w: applyWrites result target mismatch", repository.ErrTarget)
		}
		results[i] = repository.WriteResult{URI: result.URI, CID: result.CID}
	}
	return results, nil
}

func (c *Client) latestCommit(ctx context.Context, target repository.Target) (string, string, error) {
	var out struct {
		Rev    string `json:"rev"`
		Commit *struct {
			Hash string `json:"hash"`
		} `json:"commit"`
	}
	if err := c.doJSON(ctx, http.MethodGet, latestCommitNSID, url.Values{"space": {target.SpaceURI}, "did": {target.RepoDID}}, nil, &out); err != nil {
		return "", "", err
	}
	if out.Rev == "" || out.Commit == nil || out.Commit.Hash == "" {
		return "", "", fmt.Errorf("%w: incomplete HappyView commit", mailbox.ErrIntegrity)
	}
	return out.Rev, out.Commit.Hash, nil
}

type spaceView struct {
	URI     string `json:"uri"`
	IsOwner bool   `json:"isOwner"`
}

func (c *Client) listSpaces(ctx context.Context) ([]spaceView, error) {
	params := url.Values{"did": {c.did}, "limit": {"100"}}
	var spaces []spaceView
	seen := map[string]bool{}
	for {
		var out struct {
			Cursor string      `json:"cursor"`
			Spaces []spaceView `json:"spaces"`
		}
		if err := c.doJSON(ctx, http.MethodGet, listSpacesNSID, params, nil, &out); err != nil {
			return nil, err
		}
		spaces = append(spaces, out.Spaces...)
		if out.Cursor == "" {
			return spaces, nil
		}
		if seen[out.Cursor] {
			return nil, fmt.Errorf("%w: provider repeated space cursor", mailbox.ErrIntegrity)
		}
		seen[out.Cursor] = true
		params.Set("cursor", out.Cursor)
	}
}

func (c *Client) doJSON(ctx context.Context, method, endpoint string, query url.Values, body, out any) error {
	var data []byte
	var err error
	if body != nil {
		data, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	u, err := url.Parse(c.origin + "/xrpc/" + endpoint)
	if err != nil {
		return err
	}
	if query != nil {
		u.RawQuery = query.Encode()
	}
	var reader io.Reader
	if data != nil {
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), reader)
	if err != nil {
		return err
	}
	if data != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cache-Control", "no-store")
	resp, err := c.doer.Do(ctx, req, endpoint)
	if err != nil {
		return err
	}
	if resp == nil || resp.Body == nil || resp.Request == nil || !sameOrigin(resp.Request.URL, c.origin) {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		return fmt.Errorf("%w: authenticated response escaped pinned origin", repository.ErrTarget)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return decodeProviderError(resp)
	}
	responseData, err := io.ReadAll(io.LimitReader(resp.Body, maxJSONResponse+1))
	if err != nil {
		return err
	}
	if len(responseData) > maxJSONResponse {
		return errors.New("happyview: JSON response exceeded safety bound")
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(responseData, out); err != nil {
		return fmt.Errorf("happyview: decode %s response: %w", endpoint, err)
	}
	return nil
}

func decodeProviderError(resp *http.Response) error {
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	var body struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(data, &body)
	providerErr := &ProviderError{Status: resp.StatusCode, Code: body.Error}
	var sentinel error
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		sentinel = repository.ErrUnauthorized
	case resp.StatusCode == http.StatusNotFound:
		sentinel = repository.ErrNotFound
	case resp.StatusCode == http.StatusConflict && strings.Contains(strings.ToLower(body.Error), "already exists"):
		sentinel = repository.ErrExists
	case resp.StatusCode == http.StatusConflict:
		sentinel = repository.ErrConflict
	}
	if sentinel == nil {
		return providerErr
	}
	return fmt.Errorf("%w: %v", sentinel, providerErr)
}

func (c *Client) validateTarget(target repository.Target) error {
	if err := target.ValidateFor(c.did); err != nil {
		return err
	}
	if target.ProviderOrigin != c.origin || target.Epoch != c.epoch {
		return repository.ErrTarget
	}
	authority, spaceType, key, ok := parseSpaceURI(target.SpaceURI)
	if !ok || authority != c.did || spaceType != mailbox.MailboxSpaceType || !validKey(key) {
		return repository.ErrTarget
	}
	return nil
}

func (c *Client) requireWrites() error {
	if !c.allowWrites {
		return fmt.Errorf("%w: HappyView client is read-only without explicit --commit", repository.ErrUnsupported)
	}
	return nil
}

func chunkKey(data []byte) string     { return "chunk-" + mailbox.RawSHA256(data) }
func manifestKey(data []byte) string  { return "blob-" + mailbox.RawSHA256(data) }
func indexKey(cid string) string      { return "cid-" + cid }
func encodeBase64(data []byte) string { return base64.StdEncoding.EncodeToString(data) }

func jsonEqual(a, b []byte) bool {
	var av, bv any
	return json.Unmarshal(a, &av) == nil && json.Unmarshal(b, &bv) == nil && reflect.DeepEqual(av, bv)
}

func recordURI(target repository.Target, collection, rkey string) string {
	return target.SpaceURI + "/" + target.RepoDID + "/" + collection + "/" + rkey
}

func parseSpaceURI(raw string) (authority, spaceType, key string, ok bool) {
	parts := strings.Split(strings.TrimPrefix(raw, "at://"), "/")
	if !strings.HasPrefix(raw, "at://") || len(parts) != 4 || parts[1] != "space" || !strings.HasPrefix(parts[0], "did:") {
		return "", "", "", false
	}
	return parts[0], parts[2], parts[3], true
}

func cleanOrigin(raw string, allowHTTP bool) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" ||
		(u.Path != "" && (u.Path == "/" || path.Clean(u.Path) != u.Path || strings.HasSuffix(u.Path, "/"))) {
		return "", errors.New("happyview: provider origin must be a clean HTTPS base URL")
	}
	if u.Scheme != "https" && (!allowHTTP || u.Scheme != "http" || !isLoopbackHost(u.Hostname())) {
		return "", errors.New("happyview: provider origin must use HTTPS (HTTP is loopback-only)")
	}
	return strings.TrimSuffix(u.String(), "/"), nil
}

func sameOrigin(u *url.URL, rawOrigin string) bool {
	origin, err := url.Parse(rawOrigin)
	return err == nil && u != nil && strings.EqualFold(u.Scheme, origin.Scheme) && strings.EqualFold(u.Hostname(), origin.Hostname()) && effectivePort(u) == effectivePort(origin)
}

func effectivePort(u *url.URL) string {
	if u.Port() != "" {
		return u.Port()
	}
	if u.Scheme == "https" {
		return "443"
	}
	if u.Scheme == "http" {
		return "80"
	}
	return ""
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validCollection(value string) bool {
	_, err := syntax.ParseNSID(value)
	return err == nil
}

func validKey(value string) bool {
	_, err := syntax.ParseRecordKey(value)
	return err == nil
}

var _ repository.Repository = (*Client)(nil)
