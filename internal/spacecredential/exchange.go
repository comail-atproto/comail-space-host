package spacecredential

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/comail-atproto/comail-space-host/internal/mailbox"
	"github.com/comail-atproto/comail-space-host/internal/oauthclient"
)

const (
	credentialEndpoint         = "com.atproto.space.getSpaceCredential"
	maxCredentialResponseBytes = 20 * 1024
)

type DelegationSource interface {
	WithDelegation(ctx context.Context, exchange func(token string) error) error
}

type AppAccessProfile string

const AppAccessOpen AppAccessProfile = "open"

type Config struct {
	SpaceURI        string
	SpaceHostOrigin string
	SigningKeys     SigningKeyResolver
	AllowHTTP       bool
	Now             func() time.Time
	RenewalWindow   time.Duration
	AppAccess       AppAccessProfile
}

type Exchanger struct {
	spaceURI      string
	issuerDID     string
	origin        string
	signingKeys   SigningKeyResolver
	client        *http.Client
	now           func() time.Time
	renewalWindow time.Duration
}

func New(config Config) (*Exchanger, error) {
	issuerDID, err := validateSpaceURI(config.SpaceURI)
	if err != nil {
		return nil, err
	}
	if config.SigningKeys == nil {
		return nil, errors.New("spacecredential: signing-key resolver is required")
	}
	if config.AppAccess != AppAccessOpen {
		return nil, errors.New("spacecredential: only the explicit open app-access profile is supported")
	}
	client, origin, err := oauthclient.NewPinnedHTTPClient(config.SpaceHostOrigin, config.AllowHTTP)
	if err != nil {
		return nil, err
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	renewalWindow := config.RenewalWindow
	if renewalWindow == 0 {
		renewalWindow = defaultCredentialRenewal
	}
	if renewalWindow < 0 || renewalWindow >= maxCredentialLifetime {
		return nil, errors.New("spacecredential: invalid credential renewal window")
	}
	return &Exchanger{
		spaceURI: config.SpaceURI, issuerDID: issuerDID, origin: origin,
		signingKeys: config.SigningKeys, client: client, now: now, renewalWindow: renewalWindow,
	}, nil
}

func (x *Exchanger) Acquire(ctx context.Context, source DelegationSource) (*Credential, error) {
	if x == nil || source == nil {
		return nil, errors.New("spacecredential: delegation source is required")
	}
	issuer, err := syntax.ParseDID(x.issuerDID)
	if err != nil {
		return nil, errors.New("spacecredential: invalid pinned authority DID")
	}
	if err := x.verifySpaceHost(ctx, issuer); err != nil {
		return nil, err
	}
	key, err := atcrypto.GeneratePrivateKeyP256()
	if err != nil {
		return nil, errors.New("spacecredential: generate fresh credential DPoP key")
	}
	public, err := key.PublicKey()
	if err != nil {
		return nil, errors.New("spacecredential: derive credential DPoP key")
	}
	jwk, err := p256PublicJWK(public)
	if err != nil {
		return nil, err
	}
	jkt, err := jwkThumbprint(jwk)
	if err != nil {
		return nil, err
	}
	endpoint := x.origin + "/xrpc/" + credentialEndpoint
	body, err := json.Marshal(struct {
		Space string `json:"space"`
	}{Space: x.spaceURI})
	if err != nil {
		return nil, errors.New("spacecredential: encode credential request")
	}
	var token string
	var usedDelegation atomic.Bool
	err = source.WithDelegation(ctx, func(delegation string) error {
		if !usedDelegation.CompareAndSwap(false, true) {
			return errors.New("spacecredential: delegation source attempted token reuse")
		}
		proof, err := newDPoPProof(key, http.MethodPost, endpoint, nil, x.now())
		if err != nil {
			return err
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return errors.New("spacecredential: construct credential request")
		}
		request.Header.Set("Accept", "application/json")
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer "+delegation)
		request.Header.Set("DPoP", proof)
		response, err := x.client.Do(request)
		if err != nil {
			return err
		}
		if response == nil || response.Body == nil {
			return errors.New("spacecredential: credential exchange returned no response")
		}
		defer response.Body.Close()
		if response.Request == nil || !sameOrigin(response.Request.URL, x.origin) {
			return errors.New("spacecredential: credential response target mismatch")
		}
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("spacecredential: credential exchange failed with HTTP %d", response.StatusCode)
		}
		var output struct {
			Credential string `json:"credential"`
		}
		if err := decodeBoundedJSON(response.Body, maxCredentialResponseBytes, &output); err != nil {
			return err
		}
		token = output.Credential
		return nil
	})
	if err != nil {
		return nil, err
	}
	claims, err := validateCredential(ctx, token, x.issuerDID, x.spaceURI, jkt, x.signingKeys, x.now())
	if err != nil {
		return nil, err
	}
	return &Credential{
		token: token, key: key, spaceURI: x.spaceURI, origin: x.origin, client: x.client,
		now: x.now, expiresAt: time.Unix(claims.ExpiresAt, 0).UTC(), renewalWindow: x.renewalWindow,
	}, nil
}

func (x *Exchanger) verifySpaceHost(ctx context.Context, did syntax.DID) error {
	// Re-resolve for every short-lived credential acquisition. A cached DID
	// document could otherwise keep an old host authoritative indefinitely.
	resolved, err := x.signingKeys.ResolveSpaceHost(ctx, did, true)
	if err != nil || !exactResolvedOrigin(resolved, x.origin) {
		return errors.New("spacecredential: resolved space host does not match pinned origin")
	}
	return nil
}

func exactResolvedOrigin(resolved, expected string) bool {
	target, err := url.Parse(resolved)
	if err != nil || target.User != nil || target.Opaque != "" || target.RawQuery != "" || target.Fragment != "" || (target.Path != "" && target.Path != "/") {
		return false
	}
	return sameOrigin(target, expected)
}

func validateSpaceURI(raw string) (string, error) {
	if !strings.HasPrefix(raw, "at://") || strings.ContainsAny(raw, "?# \t\r\n") {
		return "", errors.New("spacecredential: exact mailbox space URI is required")
	}
	parts := strings.Split(strings.TrimPrefix(raw, "at://"), "/")
	if len(parts) != 4 || parts[1] != "space" || parts[2] != mailbox.MailboxSpaceType {
		return "", errors.New("spacecredential: exact mailbox space URI is required")
	}
	did, err := syntax.ParseDID(parts[0])
	if err != nil {
		return "", errors.New("spacecredential: invalid space authority DID")
	}
	if _, err := syntax.ParseRecordKey(parts[3]); err != nil || parts[3] == "*" {
		return "", errors.New("spacecredential: invalid exact mailbox space key")
	}
	return did.String(), nil
}

func decodeBoundedJSON(reader io.Reader, maximum int64, output any) error {
	data, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil || int64(len(data)) > maximum {
		return errors.New("spacecredential: credential response exceeded limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return errors.New("spacecredential: invalid credential response")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("spacecredential: credential response contained trailing data")
	}
	return nil
}
