package spaceprovision

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
	createSpaceEndpoint  = "com.atproto.simplespace.createSpace"
	getSpaceEndpoint     = "com.atproto.simplespace.getSpace"
	listMembersEndpoint  = "com.atproto.simplespace.listMembers"
	memberListPolicyType = "com.atproto.simplespace.defs#memberListPolicy"
	openAppAccessType    = "com.atproto.simplespace.defs#open"
	maxJSONResponseBytes = 64 * 1024
)

type Doer interface {
	Do(context.Context, *http.Request, string) (*http.Response, error)
}

type Config struct {
	Origin    string
	DID       string
	SpaceKey  string
	AllowHTTP bool
}

type Result struct {
	SpaceURI string `json:"spaceUri"`
	Created  bool   `json:"created"`
}

type Client struct {
	origin   string
	did      string
	spaceKey string
	spaceURI string
	doer     Doer
}

func New(config Config, doer Doer) (*Client, error) {
	if doer == nil {
		return nil, errors.New("spaceprovision: authenticated doer is required")
	}
	did, err := syntax.ParseDID(config.DID)
	if err != nil {
		return nil, errors.New("spaceprovision: exact authority DID is required")
	}
	key, err := syntax.ParseRecordKey(config.SpaceKey)
	if err != nil || key.String() == "*" {
		return nil, errors.New("spaceprovision: exact mailbox space key is required")
	}
	origin, err := cleanOrigin(config.Origin, config.AllowHTTP)
	if err != nil {
		return nil, err
	}
	spaceURI := "at://" + did.String() + "/space/" + mailbox.MailboxSpaceType + "/" + key.String()
	return &Client{origin: origin, did: did.String(), spaceKey: key.String(), spaceURI: spaceURI, doer: doer}, nil
}

// Ensure creates the one predetermined personal mailbox space or verifies an
// idempotent retry. It accepts only member-list user access, open app access,
// and an empty member list (the authority owner is admitted implicitly).
func (c *Client) Ensure(ctx context.Context) (Result, error) {
	created, err := c.create(ctx)
	if err != nil {
		return Result{}, err
	}
	if err := c.verifyConfig(ctx); err != nil {
		return Result{}, err
	}
	if err := c.verifyMembers(ctx); err != nil {
		return Result{}, err
	}
	return Result{SpaceURI: c.spaceURI, Created: created}, nil
}

func (c *Client) create(ctx context.Context) (bool, error) {
	input := struct {
		Type      string    `json:"type"`
		SpaceKey  string    `json:"skey"`
		Policy    unionType `json:"policy"`
		AppAccess unionType `json:"appAccess"`
	}{
		Type: mailbox.MailboxSpaceType, SpaceKey: c.spaceKey,
		Policy: unionType{Type: memberListPolicyType}, AppAccess: unionType{Type: openAppAccessType},
	}
	response, err := c.request(ctx, http.MethodPost, createSpaceEndpoint, nil, input)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		code := decodeErrorCode(response.Body)
		if response.StatusCode == http.StatusBadRequest && code == "SpaceAlreadyExists" {
			return false, nil
		}
		return false, fmt.Errorf("spaceprovision: create mailbox failed with HTTP %d", response.StatusCode)
	}
	var output struct {
		URI string `json:"uri"`
	}
	if err := decodeStrictBounded(response.Body, &output); err != nil || output.URI != c.spaceURI {
		return false, fmt.Errorf("%w: create response target mismatch", repository.ErrTarget)
	}
	return true, nil
}

func (c *Client) verifyConfig(ctx context.Context) error {
	query := url.Values{"space": {c.spaceURI}}
	response, err := c.request(ctx, http.MethodGet, getSpaceEndpoint, query, nil)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("spaceprovision: get mailbox failed with HTTP %d", response.StatusCode)
	}
	var output struct {
		URI       string    `json:"uri"`
		Policy    unionType `json:"policy"`
		AppAccess unionType `json:"appAccess"`
	}
	if err := decodeStrictBounded(response.Body, &output); err != nil {
		return err
	}
	if output.URI != c.spaceURI || output.Policy.Type != memberListPolicyType || output.AppAccess.Type != openAppAccessType {
		return fmt.Errorf("%w: mailbox declaration drift", repository.ErrTarget)
	}
	return nil
}

func (c *Client) verifyMembers(ctx context.Context) error {
	query := url.Values{"space": {c.spaceURI}, "limit": {"1000"}}
	response, err := c.request(ctx, http.MethodGet, listMembersEndpoint, query, nil)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		return fmt.Errorf("spaceprovision: list members failed with HTTP %d", response.StatusCode)
	}
	var output struct {
		Cursor  string `json:"cursor,omitempty"`
		Members []struct {
			DID string `json:"did"`
		} `json:"members"`
	}
	decodeErr := decodeStrictBounded(response.Body, &output)
	_ = response.Body.Close()
	if decodeErr != nil {
		return decodeErr
	}
	if output.Members == nil || len(output.Members) != 0 || output.Cursor != "" {
		return fmt.Errorf("%w: mailbox member-list drift", repository.ErrTarget)
	}
	return nil
}

type unionType struct {
	Type string `json:"$type"`
}

func (c *Client) request(ctx context.Context, method, endpoint string, query url.Values, body any) (*http.Response, error) {
	target, err := url.Parse(c.origin + "/xrpc/" + endpoint)
	if err != nil {
		return nil, errors.New("spaceprovision: construct request target")
	}
	if query != nil {
		target.RawQuery = query.Encode()
	}
	var encoded []byte
	if body != nil {
		encoded, err = json.Marshal(body)
		if err != nil {
			return nil, errors.New("spaceprovision: encode request")
		}
	}
	request, err := http.NewRequestWithContext(ctx, method, target.String(), bytes.NewReader(encoded))
	if err != nil {
		return nil, errors.New("spaceprovision: construct request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.doer.Do(ctx, request, endpoint)
	if err != nil {
		return nil, err
	}
	if response == nil || response.Body == nil || response.Request == nil || !sameOrigin(response.Request.URL, c.origin) ||
		(response.Request.Host != "" && !strings.EqualFold(response.Request.Host, response.Request.URL.Host)) {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, repository.ErrTarget
	}
	return response, nil
}

func decodeStrictBounded(reader io.Reader, output any) error {
	data, err := io.ReadAll(io.LimitReader(reader, maxJSONResponseBytes+1))
	if err != nil || len(data) > maxJSONResponseBytes {
		return errors.New("spaceprovision: JSON response exceeded limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return errors.New("spaceprovision: invalid JSON response")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("spaceprovision: JSON response contained trailing data")
	}
	return nil
}

func decodeErrorCode(reader io.Reader) string {
	data, err := io.ReadAll(io.LimitReader(reader, maxJSONResponseBytes+1))
	if err != nil || len(data) > maxJSONResponseBytes {
		return ""
	}
	var output struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(data, &output) != nil || len(output.Error) > 128 || strings.ContainsAny(output.Error, " \t\r\n") {
		return ""
	}
	return output.Error
}

func cleanOrigin(raw string, allowHTTP bool) (string, error) {
	origin, err := url.Parse(raw)
	if err != nil || origin.Hostname() == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || (origin.Path != "" && origin.Path != "/") {
		return "", errors.New("spaceprovision: provider must be a clean origin")
	}
	if origin.Scheme == "http" {
		ip := net.ParseIP(origin.Hostname())
		if !allowHTTP || origin.Port() == "" || ip == nil || !ip.IsLoopback() {
			return "", errors.New("spaceprovision: HTTP is allowed only for an explicit loopback test origin")
		}
	} else if origin.Scheme != "https" {
		return "", errors.New("spaceprovision: provider must use HTTPS")
	}
	origin.Scheme = strings.ToLower(origin.Scheme)
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

func sameOrigin(target *url.URL, expected string) bool {
	want, err := url.Parse(expected)
	if err != nil || target == nil || target.User != nil || target.Opaque != "" || target.Host == "" || target.Fragment != "" {
		return false
	}
	return strings.EqualFold(target.Scheme, want.Scheme) && strings.EqualFold(target.Hostname(), want.Hostname()) && effectivePort(target) == effectivePort(want)
}

func effectivePort(target *url.URL) string {
	if target.Port() != "" {
		return target.Port()
	}
	if target.Scheme == "https" {
		return "443"
	}
	return ""
}
