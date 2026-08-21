// Package officialspaces implements the production-dark transport for the
// pinned AT Protocol Spaces alpha. It is deliberately append-only and does
// not implement repository.Repository: official member repositories have no
// compare-and-swap mutation path in Comail's v3 authority model.
package officialspaces

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/comail-atproto/comail-space-host/internal/mailbox"
	"github.com/comail-atproto/comail-space-host/internal/oauthclient"
	"github.com/comail-atproto/comail-space-host/internal/repository"
	"github.com/comail-atproto/comail-space-host/internal/spacecredential"
	cidlib "github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"
)

const (
	PinnedEpoch = "atproto-89deb9faca20e56fa2a262fe9746ed52bc1095ba"

	uploadBlobEndpoint      = "com.atproto.repo.uploadBlob"
	applyWritesEndpoint     = "com.atproto.space.applyWrites"
	getRecordEndpoint       = "com.atproto.space.getRecord"
	listRecordsEndpoint     = "com.atproto.space.listRecords"
	listBlobsEndpoint       = "com.atproto.space.listBlobs"
	getBlobEndpoint         = "com.atproto.space.getBlob"
	getRepoEndpoint         = "com.atproto.space.getRepo"
	getLatestCommitEndpoint = "com.atproto.space.getLatestCommit"

	createType       = applyWritesEndpoint + "#create"
	createResultType = applyWritesEndpoint + "#createResult"

	maxWrites          = 200
	maxWriteRequest    = 1_000_000
	maxJSONResponse    = 2 * 1024 * 1024
	maxErrorResponse   = 64 * 1024
	maxCursorBytes     = 2048
	maxInventoryItems  = 100_000
	maxInventoryBytes  = 64 * 1024 * 1024
	maxInventoryPages  = 1000
	maxCommitBytes     = 64 * 1024
	maxRepoStreamBytes = 512 << 20
)

var allowedCollections = map[string]struct{}{
	mailbox.MessageCollection:               {},
	mailbox.MessageStateRevisionCollection:  {},
	mailbox.MessageStateOperationCollection: {},
	mailbox.FolderRevisionCollection:        {},
	mailbox.FolderOperationCollection:       {},
}

var knownProviderErrorCodes = map[string]struct{}{
	"BlobNotFound":        {},
	"RecordAlreadyExists": {},
	"RecordNotFound":      {},
	"RepoDeactivated":     {},
	"RepoNotFound":        {},
	"RepoSuspended":       {},
	"RepoTakendown":       {},
	"SpaceNotFound":       {},
}

// Doer sends one member-OAuth-authenticated request. Its implementation must
// bind the proof to the endpoint, refuse redirects before forwarding auth,
// and return only redacted errors.
type Doer interface {
	Do(context.Context, *http.Request, string) (*http.Response, error)
}

// ScopedDoer is one short-lived, target-bound authenticated capability. Close
// destroys or releases its token and DPoP key material.
type ScopedDoer interface {
	Doer
	Close()
}

// Target is the exact transport destination supplied to both authentication
// lanes. It is wire configuration, not a provider registration or authority
// certificate.
type Target struct {
	Origin   string
	SpaceURI string
	RepoDID  string
	Epoch    string
}

// WriterSource lends a member-OAuth writer for one operation. The source owns
// encrypted session lifecycle; browser OAuth material must never cross this
// boundary or remain stored on Client.
type WriterSource interface {
	AcquireWriter(context.Context, Target) (ScopedDoer, error)
}

// CredentialSource acquires a fresh delegated read credential for one
// complete read or recovery operation.
type CredentialSource interface {
	AcquireReader(context.Context, Target) (ScopedDoer, error)
}

type Config struct {
	Origin            string
	SpaceAuthorityDID string
	RepoDID           string
	SpaceKey          string
	Epoch             string
	AllowHTTP         bool
	RepoSigningKeys   *spacecredential.PLCSigningKeyResolver
}

type Client struct {
	origin   string
	target   Target
	writer   WriterSource
	reader   CredentialSource
	repoKeys repoSigningKeyResolver
}

// Create is one append-only permissioned-repo record creation. Value must be
// one complete JSON record whose $type exactly equals Collection.
type Create struct {
	Collection string
	RKey       string
	Value      json.RawMessage
}

type CreateResult struct {
	URI string `json:"uri"`
	CID string `json:"cid"`
}

// UnverifiedRecord is one query response bound to the transport target but not
// to a signed, complete commit/CAR. It must not be passed to v3 reducers as
// authority evidence.
type UnverifiedRecord struct {
	URI        string
	Collection string
	RKey       string
	CID        string
	Value      json.RawMessage
}

type ProviderError struct {
	Status int
	Code   string
}

func (e *ProviderError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("officialspaces: HTTP %d", e.Status)
	}
	return fmt.Sprintf("officialspaces: HTTP %d (%s)", e.Status, e.Code)
}

// ErrReauthorizationRequired is the OAuth manager's fail-closed signal. The
// transport aliases it so broker and request errors retain errors.Is identity.
var ErrReauthorizationRequired = oauthclient.ErrReauthorizationRequired

func New(config Config, writer WriterSource, reader CredentialSource) (*Client, error) {
	if writer == nil {
		return nil, errors.New("officialspaces: member OAuth doer is required")
	}
	if reader == nil {
		return nil, errors.New("officialspaces: read credential source is required")
	}
	if config.Epoch != PinnedEpoch {
		return nil, fmt.Errorf("%w: official Spaces pinned epoch mismatch", repository.ErrUnsupported)
	}
	spaceDID, err := syntax.ParseDID(config.SpaceAuthorityDID)
	if err != nil {
		return nil, errors.New("officialspaces: exact space authority DID is required")
	}
	repoDID, err := syntax.ParseDID(config.RepoDID)
	if err != nil {
		return nil, errors.New("officialspaces: exact member repo DID is required")
	}
	key, err := syntax.ParseRecordKey(config.SpaceKey)
	if err != nil || key.String() == "*" {
		return nil, errors.New("officialspaces: exact mailbox space key is required")
	}
	origin, err := cleanOrigin(config.Origin, config.AllowHTTP)
	if err != nil {
		return nil, err
	}
	target := Target{
		Origin:   origin,
		SpaceURI: "at://" + spaceDID.String() + "/space/" + mailbox.MailboxSpaceType + "/" + key.String(),
		RepoDID:  repoDID.String(),
		Epoch:    PinnedEpoch,
	}
	if err := target.repositoryTarget().ValidateFor(repoDID.String()); err != nil {
		return nil, repository.ErrTarget
	}
	return &Client{origin: origin, target: target, writer: writer, reader: reader, repoKeys: config.RepoSigningKeys}, nil
}

// TransportID identifies wire compatibility only. It is not a provider
// registration or authority certificate.
func (c *Client) TransportID() string { return "official-spaces-transport@" + PinnedEpoch }

func (c *Client) UploadMessageBlob(ctx context.Context, raw []byte) (mailbox.BlobRef, error) {
	if len(raw) == 0 {
		return mailbox.BlobRef{}, mailbox.ErrInvalidRecord
	}
	if len(raw) > mailbox.MaxRawMessageBytes {
		return mailbox.BlobRef{}, mailbox.ErrMessageTooLarge
	}
	var blob mailbox.BlobRef
	err := c.withWriter(ctx, func(writer ScopedDoer) error {
		response, err := c.request(ctx, writer, http.MethodPost, uploadBlobEndpoint, nil, raw, mailbox.MessageMIMEType, "application/json")
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return decodeProviderError(response)
		}
		var output struct {
			Blob mailbox.BlobRef `json:"blob"`
		}
		if err := decodeStrictBounded(response.Body, maxJSONResponse, &output); err != nil {
			return err
		}
		if output.Blob.Type != "blob" || output.Blob.MIMEType != mailbox.MessageMIMEType || output.Blob.Size != int64(len(raw)) {
			return fmt.Errorf("%w: upload receipt metadata mismatch", mailbox.ErrIntegrity)
		}
		if !validBlobCID(output.Blob.Ref.Link, raw) {
			return fmt.Errorf("%w: upload receipt CID is invalid", mailbox.ErrIntegrity)
		}
		blob = output.Blob
		return nil
	})
	return blob, err
}

func (c *Client) CreateBatch(ctx context.Context, creates []Create) ([]CreateResult, error) {
	if len(creates) == 0 || len(creates) > maxWrites {
		return nil, mailbox.ErrInvalidRecord
	}
	writes := make([]wireCreate, len(creates))
	seen := make(map[string]struct{}, len(creates))
	for index, create := range creates {
		if err := validateCreate(create); err != nil {
			return nil, err
		}
		identity := create.Collection + "\x00" + create.RKey
		if _, duplicate := seen[identity]; duplicate {
			return nil, fmt.Errorf("%w: duplicate record creation", mailbox.ErrInvalidRecord)
		}
		seen[identity] = struct{}{}
		writes[index] = wireCreate{Type: createType, Collection: create.Collection, RKey: create.RKey, Value: create.Value}
	}
	validate := true
	input := struct {
		Space    string       `json:"space"`
		Repo     string       `json:"repo"`
		Validate *bool        `json:"validate"`
		Writes   []wireCreate `json:"writes"`
	}{Space: c.target.SpaceURI, Repo: c.target.RepoDID, Validate: &validate, Writes: writes}
	body, err := json.Marshal(input)
	if err != nil {
		return nil, errors.New("officialspaces: encode create batch")
	}
	if len(body) > maxWriteRequest {
		return nil, fmt.Errorf("%w: create batch exceeds provider limit", mailbox.ErrInvalidRecord)
	}
	var results []CreateResult
	err = c.withWriter(ctx, func(writer ScopedDoer) error {
		response, err := c.request(ctx, writer, http.MethodPost, applyWritesEndpoint, nil, body, "application/json", "application/json")
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return decodeProviderError(response)
		}
		var output struct {
			Results []wireCreateResult `json:"results"`
		}
		if err := decodeStrictBounded(response.Body, maxJSONResponse, &output); err != nil {
			return err
		}
		if output.Results == nil || len(output.Results) != len(creates) {
			return fmt.Errorf("%w: incomplete create receipt", mailbox.ErrIntegrity)
		}
		results = make([]CreateResult, len(output.Results))
		for index, result := range output.Results {
			expectedURI, uriErr := repository.RecordURI(c.target.repositoryTarget(), creates[index].Collection, creates[index].RKey)
			if uriErr != nil || result.Type != createResultType || result.URI != expectedURI || result.ValidationStatus != "valid" {
				return fmt.Errorf("%w: create receipt target or validation mismatch", mailbox.ErrIntegrity)
			}
			if !validRecordCID(result.CID) {
				return fmt.Errorf("%w: create receipt CID is invalid", mailbox.ErrIntegrity)
			}
			results[index] = CreateResult{URI: result.URI, CID: result.CID}
		}
		return nil
	})
	return results, err
}

func (c *Client) InspectRecord(ctx context.Context, collection, rkey string) (UnverifiedRecord, error) {
	if !allowedCollection(collection) || !validRecordKey(rkey) {
		return UnverifiedRecord{}, mailbox.ErrInvalidRecord
	}
	var record UnverifiedRecord
	err := c.withReader(ctx, func(credential ScopedDoer) error {
		query := targetQuery(c.target)
		query.Set("collection", collection)
		query.Set("rkey", rkey)
		response, err := c.request(ctx, credential, http.MethodGet, getRecordEndpoint, query, nil, "", "application/json")
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return decodeProviderError(response)
		}
		var output struct {
			URI   string          `json:"uri"`
			CID   string          `json:"cid"`
			Value json.RawMessage `json:"value"`
		}
		if err := decodeStrictBounded(response.Body, maxJSONResponse, &output); err != nil {
			return err
		}
		expectedURI, _ := repository.RecordURI(c.target.repositoryTarget(), collection, rkey)
		if output.URI != expectedURI {
			return repository.ErrTarget
		}
		if !validRecordCID(output.CID) || !recordTypeMatches(output.Value, collection) {
			return fmt.Errorf("%w: record target or content mismatch", mailbox.ErrIntegrity)
		}
		record = UnverifiedRecord{URI: output.URI, Collection: collection, RKey: rkey, CID: output.CID, Value: output.Value}
		return nil
	})
	return record, err
}

// InspectRecords exhausts the bounded query pagination for diagnostics and
// retry inspection. Pages are not commit-pinned, so this inventory must never
// be treated as a verified authority snapshot.
func (c *Client) InspectRecords(ctx context.Context, collection string, excludeValues bool) ([]UnverifiedRecord, error) {
	if collection != "" && !allowedCollection(collection) {
		return nil, mailbox.ErrInvalidRecord
	}
	var records []UnverifiedRecord
	err := c.withReader(ctx, func(credential ScopedDoer) error {
		query := targetQuery(c.target)
		query.Set("limit", "1000")
		query.Set("excludeValues", fmt.Sprint(excludeValues))
		if collection != "" {
			query.Set("collection", collection)
		}
		seenCursors := make(map[string]struct{})
		seenRecords := make(map[string]struct{})
		inventoryBytes := 0
		pages := 0
		for {
			pages++
			if pages > maxInventoryPages {
				return fmt.Errorf("%w: record inventory exceeds page bound", mailbox.ErrInvalidRecord)
			}
			response, err := c.request(ctx, credential, http.MethodGet, listRecordsEndpoint, query, nil, "", "application/json")
			if err != nil {
				return err
			}
			if response.StatusCode != http.StatusOK {
				err := decodeProviderError(response)
				_ = response.Body.Close()
				return err
			}
			var output struct {
				Cursor  string `json:"cursor,omitempty"`
				Records []struct {
					Collection string          `json:"collection"`
					RKey       string          `json:"rkey"`
					CID        string          `json:"cid"`
					Value      json.RawMessage `json:"value,omitempty"`
				} `json:"records"`
			}
			pageBytes, decodeErr := decodeStrictBoundedCount(response.Body, maxJSONResponse, &output)
			_ = response.Body.Close()
			if decodeErr != nil {
				return decodeErr
			}
			inventoryBytes += pageBytes
			if inventoryBytes > maxInventoryBytes {
				return fmt.Errorf("%w: record inventory exceeds byte bound", mailbox.ErrInvalidRecord)
			}
			if output.Records == nil {
				return fmt.Errorf("%w: record inventory is missing", mailbox.ErrIntegrity)
			}
			for _, item := range output.Records {
				if !allowedCollection(item.Collection) || (collection != "" && item.Collection != collection) || !validRecordKey(item.RKey) || !validRecordCID(item.CID) {
					return fmt.Errorf("%w: malformed record inventory", mailbox.ErrIntegrity)
				}
				if excludeValues {
					if item.Value != nil {
						return fmt.Errorf("%w: metadata listing included a value", mailbox.ErrIntegrity)
					}
				} else if !recordTypeMatches(item.Value, item.Collection) {
					return fmt.Errorf("%w: record inventory content mismatch", mailbox.ErrIntegrity)
				}
				uri, _ := repository.RecordURI(c.target.repositoryTarget(), item.Collection, item.RKey)
				if _, duplicate := seenRecords[uri]; duplicate {
					return fmt.Errorf("%w: duplicate record inventory item", mailbox.ErrIntegrity)
				}
				seenRecords[uri] = struct{}{}
				records = append(records, UnverifiedRecord{URI: uri, Collection: item.Collection, RKey: item.RKey, CID: item.CID, Value: item.Value})
				if len(records) > maxInventoryItems {
					return fmt.Errorf("%w: record inventory exceeds safety bound", mailbox.ErrInvalidRecord)
				}
			}
			if output.Cursor == "" {
				return nil
			}
			if len(output.Cursor) > maxCursorBytes || strings.ContainsAny(output.Cursor, "\r\n") || len(output.Records) == 0 {
				return fmt.Errorf("%w: malformed record cursor", mailbox.ErrIntegrity)
			}
			expectedCursor := records[len(records)-1].URI
			if output.Cursor != expectedCursor {
				return repository.ErrTarget
			}
			if _, repeated := seenCursors[output.Cursor]; repeated {
				return fmt.Errorf("%w: repeated record cursor", mailbox.ErrIntegrity)
			}
			seenCursors[output.Cursor] = struct{}{}
			query.Set("cursor", output.Cursor)
		}
	})
	return records, err
}

func (c *Client) ListBlobs(ctx context.Context, since string) ([]string, error) {
	if since != "" {
		if _, err := syntax.ParseTID(since); err != nil {
			return nil, mailbox.ErrInvalidRecord
		}
	}
	var cids []string
	err := c.withReader(ctx, func(credential ScopedDoer) error {
		query := targetQuery(c.target)
		query.Set("limit", "1000")
		if since != "" {
			query.Set("since", since)
		}
		seenCursors := make(map[string]struct{})
		seenCIDs := make(map[string]struct{})
		inventoryBytes := 0
		pages := 0
		for {
			pages++
			if pages > maxInventoryPages {
				return fmt.Errorf("%w: blob inventory exceeds page bound", mailbox.ErrInvalidRecord)
			}
			response, err := c.request(ctx, credential, http.MethodGet, listBlobsEndpoint, query, nil, "", "application/json")
			if err != nil {
				return err
			}
			if response.StatusCode != http.StatusOK {
				err := decodeProviderError(response)
				_ = response.Body.Close()
				return err
			}
			var output struct {
				Cursor string   `json:"cursor,omitempty"`
				CIDs   []string `json:"cids"`
			}
			pageBytes, decodeErr := decodeStrictBoundedCount(response.Body, maxJSONResponse, &output)
			_ = response.Body.Close()
			if decodeErr != nil {
				return decodeErr
			}
			inventoryBytes += pageBytes
			if inventoryBytes > maxInventoryBytes {
				return fmt.Errorf("%w: blob inventory exceeds byte bound", mailbox.ErrInvalidRecord)
			}
			if output.CIDs == nil {
				return fmt.Errorf("%w: blob inventory is missing", mailbox.ErrIntegrity)
			}
			for _, cid := range output.CIDs {
				if !validRawCID(cid) {
					return fmt.Errorf("%w: blob inventory CID is invalid", mailbox.ErrIntegrity)
				}
				if _, duplicate := seenCIDs[cid]; duplicate {
					return fmt.Errorf("%w: duplicate blob inventory item", mailbox.ErrIntegrity)
				}
				seenCIDs[cid] = struct{}{}
				cids = append(cids, cid)
				if len(cids) > maxInventoryItems {
					return fmt.Errorf("%w: blob inventory exceeds safety bound", mailbox.ErrInvalidRecord)
				}
			}
			if output.Cursor == "" {
				return nil
			}
			if len(output.Cursor) > maxCursorBytes || strings.ContainsAny(output.Cursor, "\r\n") || len(output.CIDs) == 0 || output.Cursor != output.CIDs[len(output.CIDs)-1] {
				return fmt.Errorf("%w: malformed blob cursor", mailbox.ErrIntegrity)
			}
			if _, repeated := seenCursors[output.Cursor]; repeated {
				return fmt.Errorf("%w: repeated blob cursor", mailbox.ErrIntegrity)
			}
			seenCursors[output.Cursor] = struct{}{}
			query.Set("cursor", output.Cursor)
		}
	})
	return cids, err
}

func (c *Client) GetBlob(ctx context.Context, cid string) ([]byte, error) {
	if !validRawCID(cid) {
		return nil, mailbox.ErrInvalidRecord
	}
	var blob []byte
	err := c.withReader(ctx, func(credential ScopedDoer) error {
		data, err := c.readMessageBlob(ctx, credential, cid)
		if err != nil {
			return err
		}
		blob = data
		return nil
	})
	return blob, err
}

// GetLatestCommit returns the bounded signed-commit object without claiming it
// is verified. The alpha signature does not sign the repo hash; only the live
// stable-read method may create a source-authenticated snapshot capability.
func (c *Client) GetLatestCommit(ctx context.Context) (json.RawMessage, error) {
	var commit json.RawMessage
	err := c.withReader(ctx, func(credential ScopedDoer) error {
		response, err := c.request(ctx, credential, http.MethodGet, getLatestCommitEndpoint, targetQuery(c.target), nil, "", "application/json")
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return decodeProviderError(response)
		}
		var output struct {
			Commit json.RawMessage `json:"commit"`
		}
		if err := decodeStrictBounded(response.Body, maxCommitBytes, &output); err != nil {
			return err
		}
		if len(output.Commit) == 0 || string(output.Commit) == "null" || output.Commit[0] != '{' {
			return fmt.Errorf("%w: signed commit is missing", mailbox.ErrIntegrity)
		}
		commit = append(json.RawMessage(nil), output.Commit...)
		return nil
	})
	return commit, err
}

// StreamRepo scopes one fresh read credential to a CAR consumer. This raw
// escape hatch does not validate the CAR and deliberately returns no verified
// or source-authenticated capability.
func (c *Client) StreamRepo(ctx context.Context, excludeValues bool, consume func(io.Reader) error) error {
	if consume == nil {
		return mailbox.ErrInvalidRecord
	}
	return c.withReader(ctx, func(credential ScopedDoer) error {
		query := targetQuery(c.target)
		query.Set("excludeValues", fmt.Sprint(excludeValues))
		response, err := c.request(ctx, credential, http.MethodGet, getRepoEndpoint, query, nil, "", "application/vnd.ipld.car")
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return decodeProviderError(response)
		}
		mediaType, _, parseErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if parseErr != nil || !strings.EqualFold(mediaType, "application/vnd.ipld.car") {
			return fmt.Errorf("%w: repo export media type mismatch", mailbox.ErrIntegrity)
		}
		limited := &io.LimitedReader{R: response.Body, N: maxRepoStreamBytes + 1}
		if err := consume(limited); err != nil {
			return err
		}
		if limited.N <= 0 {
			return fmt.Errorf("%w: repo export exceeds safety bound", mailbox.ErrInvalidRecord)
		}
		var probe [1]byte
		if count, readErr := limited.Read(probe[:]); count != 0 || !errors.Is(readErr, io.EOF) {
			return fmt.Errorf("%w: repo export consumer did not exhaust the snapshot", mailbox.ErrIntegrity)
		}
		return nil
	})
}

type wireCreate struct {
	Type       string          `json:"$type"`
	Collection string          `json:"collection"`
	RKey       string          `json:"rkey"`
	Value      json.RawMessage `json:"value"`
}

type wireCreateResult struct {
	Type             string `json:"$type"`
	URI              string `json:"uri"`
	CID              string `json:"cid"`
	ValidationStatus string `json:"validationStatus"`
}

func validateCreate(create Create) error {
	if !allowedCollection(create.Collection) || !validRecordKey(create.RKey) || !recordTypeMatches(create.Value, create.Collection) {
		return mailbox.ErrInvalidRecord
	}
	return nil
}

func allowedCollection(collection string) bool {
	_, ok := allowedCollections[collection]
	return ok
}

func validRecordKey(rkey string) bool {
	key, err := syntax.ParseRecordKey(rkey)
	return err == nil && key.String() != "*"
}

func validRecordCID(raw string) bool {
	parsed, err := cidlib.Decode(raw)
	if err != nil {
		return false
	}
	prefix := parsed.Prefix()
	return prefix.Version == 1 && prefix.Codec == cidlib.DagCBOR && prefix.MhType == multihash.SHA2_256 && prefix.MhLength == sha256.Size
}

func validRawCID(raw string) bool {
	parsed, err := cidlib.Decode(raw)
	if err != nil {
		return false
	}
	prefix := parsed.Prefix()
	return parsed.String() == raw && prefix.Version == 1 && prefix.Codec == cidlib.Raw &&
		prefix.MhType == multihash.SHA2_256 && prefix.MhLength == sha256.Size
}

func validBlobCID(raw string, data []byte) bool {
	if !validRawCID(raw) {
		return false
	}
	parsed, _ := cidlib.Decode(raw)
	actual, err := parsed.Prefix().Sum(data)
	return err == nil && parsed.Equals(actual)
}

func recordTypeMatches(value json.RawMessage, collection string) bool {
	if len(value) == 0 || len(value) > maxWriteRequest {
		return false
	}
	var envelope struct {
		Type string `json:"$type"`
	}
	decoder := json.NewDecoder(bytes.NewReader(value))
	if err := decoder.Decode(&envelope); err != nil || envelope.Type != collection {
		return false
	}
	return decoder.Decode(&struct{}{}) == io.EOF
}

func (t Target) repositoryTarget() repository.Target {
	return repository.Target{ProviderOrigin: t.Origin, SpaceURI: t.SpaceURI, RepoDID: t.RepoDID, Epoch: t.Epoch}
}

func targetQuery(target Target) url.Values {
	return url.Values{"space": {target.SpaceURI}, "repo": {target.RepoDID}}
}

func (c *Client) withWriter(ctx context.Context, operation func(ScopedDoer) error) error {
	writer, err := c.writer.AcquireWriter(ctx, c.target)
	if writer != nil {
		defer writer.Close()
	}
	if err != nil || writer == nil {
		return redactAuthError("acquire member writer", err)
	}
	return operation(writer)
}

func (c *Client) withReader(ctx context.Context, operation func(ScopedDoer) error) error {
	credential, err := c.reader.AcquireReader(ctx, c.target)
	if credential != nil {
		defer credential.Close()
	}
	if err != nil || credential == nil {
		return redactAuthError("acquire read credential", err)
	}
	return operation(credential)
}

func redactAuthError(operation string, err error) error {
	for _, sentinel := range []error{
		context.Canceled, context.DeadlineExceeded, ErrReauthorizationRequired,
		repository.ErrUnauthorized, repository.ErrRevoked, repository.ErrTarget,
	} {
		if errors.Is(err, sentinel) {
			return fmt.Errorf("officialspaces: %s failed: %w", operation, sentinel)
		}
	}
	return fmt.Errorf("officialspaces: %s failed", operation)
}

func (c *Client) request(ctx context.Context, doer Doer, method, endpoint string, query url.Values, body []byte, contentType, accept string) (*http.Response, error) {
	target, err := url.Parse(c.origin + "/xrpc/" + endpoint)
	if err != nil {
		return nil, errors.New("officialspaces: construct request target")
	}
	if query != nil {
		target.RawQuery = query.Encode()
	}
	var input io.Reader
	if body != nil {
		input = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, target.String(), input)
	if err != nil {
		return nil, errors.New("officialspaces: construct request")
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	if accept != "" {
		request.Header.Set("Accept", accept)
	}
	request.Header.Set("Cache-Control", "no-store")
	response, err := doer.Do(ctx, request, endpoint)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, redactAuthError("authenticated request", err)
	}
	if response == nil || response.Body == nil || response.Request == nil || response.Request.URL == nil || response.Request.URL.String() != request.URL.String() ||
		(response.Request.Host != "" && !strings.EqualFold(response.Request.Host, response.Request.URL.Host)) {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, repository.ErrTarget
	}
	return response, nil
}

func decodeStrictBounded(reader io.Reader, limit int64, output any) error {
	_, err := decodeStrictBoundedCount(reader, limit, output)
	return err
}

func decodeStrictBoundedCount(reader io.Reader, limit int64, output any) (int, error) {
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil || int64(len(data)) > limit {
		return 0, errors.New("officialspaces: response exceeded safety bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return 0, errors.New("officialspaces: invalid JSON response")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return 0, errors.New("officialspaces: JSON response contained trailing data")
	}
	return len(data), nil
}

func decodeProviderError(response *http.Response) error {
	data, _ := io.ReadAll(io.LimitReader(response.Body, maxErrorResponse+1))
	var body struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(data, &body)
	if !safeErrorCode(body.Error) {
		body.Error = ""
	}
	providerErr := &ProviderError{Status: response.StatusCode, Code: body.Error}
	var sentinel error
	switch {
	case response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden:
		sentinel = repository.ErrUnauthorized
	case body.Error == "RecordAlreadyExists":
		sentinel = repository.ErrExists
	case body.Error == "RecordNotFound" || body.Error == "BlobNotFound" || body.Error == "SpaceNotFound" || body.Error == "RepoNotFound":
		sentinel = repository.ErrNotFound
	}
	if sentinel == nil {
		return providerErr
	}
	return fmt.Errorf("%w: %v", sentinel, providerErr)
}

func safeErrorCode(code string) bool {
	_, known := knownProviderErrorCodes[code]
	return known
}

func cleanOrigin(raw string, allowHTTP bool) (string, error) {
	origin, err := url.Parse(raw)
	if err != nil || origin.Hostname() == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || (origin.Path != "" && origin.Path != "/") {
		return "", errors.New("officialspaces: provider must be a clean origin")
	}
	if origin.Scheme != "https" {
		if !allowHTTP || origin.Scheme != "http" || !isLoopbackHost(origin.Hostname()) {
			return "", errors.New("officialspaces: provider must use HTTPS (HTTP is loopback-test-only)")
		}
	}
	hostname := strings.ToLower(origin.Hostname())
	port := origin.Port()
	if (origin.Scheme == "https" && port == "443") || (origin.Scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		origin.Host = net.JoinHostPort(hostname, port)
	} else if strings.Contains(hostname, ":") {
		origin.Host = "[" + hostname + "]"
	} else {
		origin.Host = hostname
	}
	origin.Path = ""
	origin.RawPath = ""
	return strings.TrimSuffix(origin.String(), "/"), nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
