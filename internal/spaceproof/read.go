// Package spaceproof performs redacted, metadata-only official Spaces checks.
package spaceproof

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

	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/comail-atproto/comail-space-host/internal/mailbox"
	"github.com/comail-atproto/comail-space-host/internal/repository"
)

const (
	listRecordsEndpoint = "com.atproto.space.listRecords"
	maxResponseBytes    = 64 * 1024
	maxCursorBytes      = 2048
	proofEpoch          = "atproto-89deb9faca20e56fa2a262fe9746ed52bc1095ba"

	RepoReady = "ready"
)

type Doer interface {
	Do(context.Context, *http.Request, string) (*http.Response, error)
}

type Config struct {
	Origin   string
	DID      string
	SpaceKey string
}

type Result struct {
	RepoState             string `json:"repoState"`
	RecordMetadataPresent bool   `json:"recordMetadataPresent"`
}

type Client struct {
	origin string
	target repository.Target
	doer   Doer
}

func New(config Config, doer Doer) (*Client, error) {
	if doer == nil {
		return nil, errors.New("spaceproof: authenticated credential doer is required")
	}
	did, err := syntax.ParseDID(config.DID)
	if err != nil {
		return nil, errors.New("spaceproof: exact repo DID is required")
	}
	key, err := syntax.ParseRecordKey(config.SpaceKey)
	if err != nil || key.String() == "*" {
		return nil, errors.New("spaceproof: exact mailbox space key is required")
	}
	origin, err := cleanHTTPSOrigin(config.Origin)
	if err != nil {
		return nil, err
	}
	target := repository.Target{
		ProviderOrigin: origin,
		SpaceURI:       "at://" + did.String() + "/space/" + mailbox.MailboxSpaceType + "/" + key.String(),
		RepoDID:        did.String(),
		Epoch:          proofEpoch,
	}
	if err := target.ValidateFor(did.String()); err != nil {
		return nil, repository.ErrTarget
	}
	return &Client{origin: origin, target: target, doer: doer}, nil
}

// ProveRead exercises one fresh space credential without returning record
// identifiers or values. A 200 metadata-only listing proves DPoP credential
// use; RepoNotFound is target drift for this sole-host personal-mailbox profile.
func (c *Client) ProveRead(ctx context.Context) (Result, error) {
	target, err := url.Parse(c.origin + "/xrpc/" + listRecordsEndpoint)
	if err != nil {
		return Result{}, errors.New("spaceproof: construct list target")
	}
	target.RawQuery = url.Values{
		"space":         {c.target.SpaceURI},
		"repo":          {c.target.RepoDID},
		"collection":    {mailbox.MessageCollection},
		"limit":         {"1"},
		"excludeValues": {"true"},
	}.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return Result{}, errors.New("spaceproof: construct list request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	response, err := c.doer.Do(ctx, request, listRecordsEndpoint)
	if err != nil {
		return Result{}, err
	}
	if response == nil || response.Body == nil || response.Request == nil || response.Request.URL == nil ||
		response.Request.URL.String() != request.URL.String() ||
		(response.Request.Host != "" && !strings.EqualFold(response.Request.Host, response.Request.URL.Host)) {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return Result{}, repository.ErrTarget
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes+1))
		return Result{}, fmt.Errorf("spaceproof: credential read failed with HTTP %d", response.StatusCode)
	}
	var output struct {
		Cursor  string `json:"cursor,omitempty"`
		Records []struct {
			Collection string `json:"collection"`
			RKey       string `json:"rkey"`
			CID        string `json:"cid"`
		} `json:"records"`
	}
	if err := decodeStrictBounded(response.Body, &output); err != nil {
		return Result{}, err
	}
	if output.Records == nil || len(output.Records) > 1 || len(output.Cursor) > maxCursorBytes || strings.ContainsAny(output.Cursor, "\r\n") {
		return Result{}, errors.New("spaceproof: invalid metadata-only listing")
	}
	if len(output.Records) == 0 {
		if output.Cursor != "" {
			return Result{}, errors.New("spaceproof: empty listing carried a cursor")
		}
		return Result{RepoState: RepoReady}, nil
	}
	record := output.Records[0]
	if record.Collection != mailbox.MessageCollection {
		return Result{}, repository.ErrTarget
	}
	if _, err := syntax.ParseNSID(record.Collection); err != nil {
		return Result{}, errors.New("spaceproof: invalid record collection")
	}
	if _, err := syntax.ParseRecordKey(record.RKey); err != nil {
		return Result{}, errors.New("spaceproof: invalid record key")
	}
	if _, err := syntax.ParseCID(record.CID); err != nil {
		return Result{}, errors.New("spaceproof: invalid record CID")
	}
	expectedCursor, err := repository.RecordURI(c.target, record.Collection, record.RKey)
	if err != nil || output.Cursor != expectedCursor {
		return Result{}, repository.ErrTarget
	}
	return Result{RepoState: RepoReady, RecordMetadataPresent: true}, nil
}

func decodeStrictBounded(reader io.Reader, output any) error {
	data, err := io.ReadAll(io.LimitReader(reader, maxResponseBytes+1))
	if err != nil || len(data) > maxResponseBytes {
		return errors.New("spaceproof: response exceeded limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return errors.New("spaceproof: invalid JSON response")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("spaceproof: JSON response contained trailing data")
	}
	return nil
}

func cleanHTTPSOrigin(raw string) (string, error) {
	origin, err := url.Parse(raw)
	if err != nil || origin.Scheme != "https" || origin.Hostname() == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || (origin.Path != "" && origin.Path != "/") {
		return "", errors.New("spaceproof: provider must be a clean HTTPS origin")
	}
	origin.Scheme = "https"
	hostname := strings.ToLower(origin.Hostname())
	port := origin.Port()
	if port == "443" {
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
