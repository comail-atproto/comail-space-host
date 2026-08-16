package rsky

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/comail-atproto/comail-pds-lab/internal/mailbox"
	"github.com/comail-atproto/comail-pds-lab/internal/repository"
)

const (
	createSpaceNSID = "com.atproto.simplespace.createSpace"
	listSpacesNSID  = "com.atproto.space.listSpaces"
	uploadBlobNSID  = "com.atproto.repo.uploadBlob"
	applyWritesNSID = "com.atproto.space.applyWrites"
	putRecordNSID   = "com.atproto.space.putRecord"
	getRecordNSID   = "com.atproto.space.getRecord"
	listRecordsNSID = "com.atproto.space.listRecords"
	getBlobNSID     = "com.atproto.space.getBlob"

	maxJSONResponse = 2 * 1024 * 1024
	maxListRecords  = 1_000_000
)

// Doer sends one authenticated request. Implementations must bind the
// authorization proof to endpoint and must refuse redirects before forwarding
// credentials to another origin.
type Doer interface {
	Do(context.Context, *http.Request, string) (*http.Response, error)
}

type Config struct {
	Origin             string
	DID                string
	Epoch              string
	AllowHTTP          bool
	AllowWrites        bool
	CertificationProbe bool
}

type Client struct {
	origin      string
	did         string
	epoch       string
	doer        Doer
	allowWrites bool
}

type ProviderError struct {
	Status int
	Code   string
}

func (e *ProviderError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("rsky: HTTP %d", e.Status)
	}
	return fmt.Sprintf("rsky: HTTP %d (%s)", e.Status, e.Code)
}

func New(cfg Config, doer Doer) (*Client, error) {
	if doer == nil {
		return nil, errors.New("rsky: authenticated request doer is required")
	}
	origin, err := cleanOrigin(cfg.Origin, cfg.AllowHTTP)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(cfg.DID, "did:") || strings.ContainsAny(cfg.DID, "/?#") {
		return nil, errors.New("rsky: exact account DID is required")
	}
	if cfg.Epoch == "" {
		return nil, errors.New("rsky: pinned provider epoch is required")
	}
	if cfg.AllowWrites && !cfg.CertificationProbe {
		return nil, fmt.Errorf("%w: pinned rsky epoch is not certified for mailbox writes", repository.ErrUnsupported)
	}
	return &Client{origin: origin, did: cfg.DID, epoch: cfg.Epoch, doer: doer, allowWrites: cfg.AllowWrites}, nil
}

func (c *Client) ProviderID() string { return "rsky@" + c.epoch }

func (c *Client) Capabilities(context.Context) (repository.Capabilities, error) {
	return repository.Capabilities{
		// The pinned epoch commits space records before referenced-blob
		// promotion. Until that ordering is fixed and regression-tested, the
		// mailbox authority contract must treat applyWrites as non-atomic.
		AtomicApplyWrites: false,
		CompareAndSwap:    true,
		ReferencedBlobs:   true,
		RepoOplog:         true,
		CARExport:         true,
		Notifications:     true,
	}, nil
}

func (c *Client) EnsureMailbox(ctx context.Context, recipientDID, key string) (repository.Target, error) {
	if err := c.requireWrites(); err != nil {
		return repository.Target{}, err
	}
	if recipientDID != c.did || !validKey(key) {
		return repository.Target{}, repository.ErrTarget
	}
	expectedURI := fmt.Sprintf("at://%s/space/%s/%s", c.did, mailbox.MailboxSpaceType, key)
	target := repository.Target{ProviderOrigin: c.origin, SpaceURI: expectedURI, RepoDID: c.did, Epoch: c.epoch}
	spaces, err := c.listSpaces(ctx)
	if err != nil {
		return repository.Target{}, err
	}
	for _, space := range spaces {
		if space.URI == expectedURI {
			if !space.IsOwner || !space.IsMember {
				return repository.Target{}, fmt.Errorf("%w: mailbox exists without owner/member binding", repository.ErrTarget)
			}
			return target, nil
		}
	}
	var out struct {
		URI string `json:"uri"`
	}
	err = c.doJSON(ctx, http.MethodPost, createSpaceNSID, nil, map[string]any{
		"type": mailbox.MailboxSpaceType, "skey": key,
	}, &out)
	if err != nil {
		if errors.Is(err, repository.ErrExists) {
			spaces, listErr := c.listSpaces(ctx)
			if listErr != nil {
				return repository.Target{}, errors.Join(err, listErr)
			}
			for _, space := range spaces {
				if space.URI == expectedURI && space.IsOwner && space.IsMember {
					return target, nil
				}
			}
		}
		return repository.Target{}, err
	}
	if out.URI != expectedURI {
		return repository.Target{}, fmt.Errorf("%w: createSpace returned unexpected URI", repository.ErrTarget)
	}
	return target, nil
}

func (c *Client) UploadBlob(ctx context.Context, target repository.Target, data []byte, mimeType string) (mailbox.BlobRef, error) {
	if err := c.requireWrites(); err != nil {
		return mailbox.BlobRef{}, err
	}
	if err := c.validateTarget(target); err != nil {
		return mailbox.BlobRef{}, err
	}
	if len(data) == 0 || len(data) > mailbox.MaxRawMessageBytes || mimeType == "" {
		if len(data) > mailbox.MaxRawMessageBytes {
			return mailbox.BlobRef{}, mailbox.ErrMessageTooLarge
		}
		return mailbox.BlobRef{}, mailbox.ErrInvalidRecord
	}
	var out struct {
		Blob mailbox.BlobRef `json:"blob"`
	}
	if err := c.doRawJSON(ctx, http.MethodPost, uploadBlobNSID, nil, data, mimeType, &out); err != nil {
		return mailbox.BlobRef{}, err
	}
	if out.Blob.Type == "" {
		out.Blob.Type = "blob"
	}
	if out.Blob.Ref.Link == "" || out.Blob.MIMEType != mimeType || out.Blob.Size != int64(len(data)) {
		return mailbox.BlobRef{}, fmt.Errorf("%w: provider returned mismatched blob metadata", mailbox.ErrIntegrity)
	}
	return out.Blob, nil
}

func (c *Client) ApplyWrites(ctx context.Context, target repository.Target, writes []repository.Write) (repository.Commit, error) {
	if err := c.requireWrites(); err != nil {
		return repository.Commit{}, err
	}
	if err := c.validateTarget(target); err != nil {
		return repository.Commit{}, err
	}
	if len(writes) == 0 || len(writes) > 200 {
		return repository.Commit{}, mailbox.ErrInvalidRecord
	}
	wireWrites := make([]map[string]any, 0, len(writes))
	for _, write := range writes {
		if !validCollection(write.Collection) || !validKey(write.RKey) {
			return repository.Commit{}, mailbox.ErrInvalidRecord
		}
		wire := map[string]any{"action": string(write.Action), "collection": write.Collection, "rkey": write.RKey}
		switch write.Action {
		case repository.Create, repository.Update:
			if write.Value == nil {
				return repository.Commit{}, mailbox.ErrInvalidRecord
			}
			wire["value"] = write.Value
		case repository.Delete:
		default:
			return repository.Commit{}, mailbox.ErrInvalidRecord
		}
		wireWrites = append(wireWrites, wire)
	}
	var out struct {
		Commit *struct {
			Rev  string `json:"rev"`
			Hash string `json:"hash"`
		} `json:"commit"`
		Results []struct {
			URI string `json:"uri"`
			CID string `json:"cid"`
		} `json:"results"`
	}
	if err := c.doJSON(ctx, http.MethodPost, applyWritesNSID, nil, map[string]any{
		"space": target.SpaceURI, "repo": target.RepoDID, "validate": false, "writes": wireWrites,
	}, &out); err != nil {
		return repository.Commit{}, err
	}
	if out.Commit == nil || out.Commit.Rev == "" || out.Commit.Hash == "" || len(out.Results) != len(writes) {
		return repository.Commit{}, fmt.Errorf("%w: incomplete applyWrites receipt", mailbox.ErrIntegrity)
	}
	commit := repository.Commit{Rev: out.Commit.Rev, Hash: out.Commit.Hash, Results: make([]repository.WriteResult, len(out.Results))}
	for i, result := range out.Results {
		if writes[i].Action != repository.Delete {
			if result.URI != recordURI(target, writes[i].Collection, writes[i].RKey) || result.CID == "" {
				return repository.Commit{}, fmt.Errorf("%w: applyWrites result target mismatch", repository.ErrTarget)
			}
		}
		commit.Results[i] = repository.WriteResult{URI: result.URI, CID: result.CID}
	}
	return commit, nil
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
	if err := c.doJSON(ctx, http.MethodPost, putRecordNSID, nil, map[string]any{
		"space": target.SpaceURI, "repo": target.RepoDID, "collection": collection,
		"rkey": rkey, "record": value, "swapRecord": expectedCID, "validate": false,
	}, &out); err != nil {
		return repository.Record{}, err
	}
	if out.URI != recordURI(target, collection, rkey) || out.CID == "" {
		return repository.Record{}, fmt.Errorf("%w: putRecord result target mismatch", repository.ErrTarget)
	}
	valueJSON, err := json.Marshal(value)
	if err != nil {
		return repository.Record{}, err
	}
	return repository.Record{URI: out.URI, Collection: collection, RKey: rkey, CID: out.CID, Value: valueJSON}, nil
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
	if err := c.doJSON(ctx, http.MethodGet, getRecordNSID, url.Values{
		"space": {target.SpaceURI}, "repo": {target.RepoDID}, "collection": {collection}, "rkey": {rkey},
	}, nil, &out); err != nil {
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
	params := url.Values{"space": {target.SpaceURI}, "repo": {target.RepoDID}, "limit": {"500"}}
	if collection != "" {
		params.Set("collection", collection)
	}
	var records []repository.Record
	seenCursors := make(map[string]bool)
	for {
		var out struct {
			Cursor  string `json:"cursor"`
			Records []struct {
				Collection string          `json:"collection"`
				RKey       string          `json:"rkey"`
				CID        string          `json:"cid"`
				Value      json.RawMessage `json:"value"`
			} `json:"records"`
		}
		if err := c.doJSON(ctx, http.MethodGet, listRecordsNSID, params, nil, &out); err != nil {
			return nil, err
		}
		for _, item := range out.Records {
			if !validCollection(item.Collection) || !validKey(item.RKey) || item.CID == "" || len(item.Value) == 0 || (collection != "" && item.Collection != collection) {
				return nil, fmt.Errorf("%w: malformed listRecords item", mailbox.ErrIntegrity)
			}
			records = append(records, repository.Record{
				URI: recordURI(target, item.Collection, item.RKey), Collection: item.Collection,
				RKey: item.RKey, CID: item.CID, Value: item.Value,
			})
			if len(records) > maxListRecords {
				return nil, fmt.Errorf("%w: record inventory exceeds safety bound", mailbox.ErrInvalidRecord)
			}
		}
		if out.Cursor == "" {
			break
		}
		if seenCursors[out.Cursor] {
			return nil, fmt.Errorf("%w: provider repeated listRecords cursor", mailbox.ErrIntegrity)
		}
		seenCursors[out.Cursor] = true
		params.Set("cursor", out.Cursor)
	}
	return records, nil
}

func (c *Client) GetBlob(ctx context.Context, target repository.Target, cid string) ([]byte, error) {
	if err := c.validateTarget(target); err != nil {
		return nil, err
	}
	if cid == "" || strings.ContainsAny(cid, " /?#") {
		return nil, mailbox.ErrInvalidRecord
	}
	resp, err := c.request(ctx, http.MethodGet, getBlobNSID, url.Values{
		"space": {target.SpaceURI}, "repo": {target.RepoDID}, "cid": {cid},
	}, nil, "")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, decodeProviderError(resp)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, mailbox.MaxRawMessageBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > mailbox.MaxRawMessageBytes {
		return nil, mailbox.ErrMessageTooLarge
	}
	return data, nil
}

type spaceView struct {
	URI      string `json:"uri"`
	IsOwner  bool   `json:"isOwner"`
	IsMember bool   `json:"isMember"`
}

func (c *Client) listSpaces(ctx context.Context) ([]spaceView, error) {
	params := url.Values{"type": {mailbox.MailboxSpaceType}, "did": {c.did}, "limit": {"500"}}
	var spaces []spaceView
	seen := make(map[string]bool)
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
			return nil, fmt.Errorf("%w: provider repeated listSpaces cursor", mailbox.ErrIntegrity)
		}
		seen[out.Cursor] = true
		params.Set("cursor", out.Cursor)
	}
}

func (c *Client) doJSON(ctx context.Context, method, endpoint string, query url.Values, body any, out any) error {
	var data []byte
	var err error
	if body != nil {
		data, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	return c.doRawJSON(ctx, method, endpoint, query, data, "application/json", out)
}

func (c *Client) doRawJSON(ctx context.Context, method, endpoint string, query url.Values, data []byte, contentType string, out any) error {
	resp, err := c.request(ctx, method, endpoint, query, data, contentType)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return decodeProviderError(resp)
	}
	limited := io.LimitReader(resp.Body, maxJSONResponse+1)
	responseData, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if len(responseData) > maxJSONResponse {
		return errors.New("rsky: JSON response exceeded safety bound")
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(responseData, out); err != nil {
		return fmt.Errorf("rsky: decode %s response: %w", endpoint, err)
	}
	return nil
}

func (c *Client) request(ctx context.Context, method, endpoint string, query url.Values, data []byte, contentType string) (*http.Response, error) {
	u, err := url.Parse(c.origin + "/xrpc/" + endpoint)
	if err != nil {
		return nil, err
	}
	if query != nil {
		u.RawQuery = query.Encode()
	}
	var body io.Reader
	if data != nil {
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cache-Control", "no-store")
	resp, err := c.doer.Do(ctx, req, endpoint)
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Body == nil || resp.Request == nil || !sameOrigin(resp.Request.URL, c.origin) {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		return nil, fmt.Errorf("%w: authenticated response escaped pinned origin", repository.ErrTarget)
	}
	return resp, nil
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
	case body.Error == "RecordNotFound" || body.Error == "BlobNotFound" || body.Error == "SpaceNotFound" || body.Error == "SpaceDeleted" || body.Error == "RepoNotFound":
		sentinel = repository.ErrNotFound
	case body.Error == "RecordExists" || body.Error == "SpaceExists":
		sentinel = repository.ErrExists
	case body.Error == "InvalidSwap":
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
		return fmt.Errorf("%w: rsky client is read-only until an explicit certified write mode is selected", repository.ErrUnsupported)
	}
	return nil
}

func recordURI(target repository.Target, collection, rkey string) string {
	return target.SpaceURI + "/" + target.RepoDID + "/" + collection + "/" + rkey
}

func parseSpaceURI(raw string) (authority, spaceType, key string, ok bool) {
	if !strings.HasPrefix(raw, "at://") {
		return "", "", "", false
	}
	parts := strings.Split(strings.TrimPrefix(raw, "at://"), "/")
	if len(parts) != 4 || parts[1] != "space" || !strings.HasPrefix(parts[0], "did:") {
		return "", "", "", false
	}
	return parts[0], parts[2], parts[3], true
}

func cleanOrigin(raw string, allowHTTP bool) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("rsky: provider origin must be a clean origin")
	}
	if u.Scheme != "https" {
		if !allowHTTP || u.Scheme != "http" || !isLoopbackHost(u.Hostname()) {
			return "", errors.New("rsky: provider origin must use HTTPS (HTTP is loopback-test-only)")
		}
	}
	u.Path = ""
	return strings.TrimSuffix(u.String(), "/"), nil
}

func sameOrigin(u *url.URL, rawOrigin string) bool {
	origin, err := url.Parse(rawOrigin)
	if err != nil || u == nil {
		return false
	}
	return strings.EqualFold(u.Scheme, origin.Scheme) && strings.EqualFold(u.Hostname(), origin.Hostname()) && effectivePort(u) == effectivePort(origin)
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

var _ repository.Repository = (*Client)(nil)
