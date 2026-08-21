package spacecredential

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/identity"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/comail-atproto/comail-space-host/internal/oauthclient"
)

const maxDIDDocumentBytes = 128 * 1024

// PLCSigningKeyResolver resolves only did:plc authorities through one pinned,
// bounded PLC directory. It never uses environment proxies, redirects, handle
// resolution, or request-selectable origins.
type PLCSigningKeyResolver struct {
	client *http.Client
	origin string
	mu     sync.Mutex
	cache  map[syntax.DID]identity.Identity
}

func NewPLCSigningKeyResolver(plcOrigin string, allowHTTP bool) (*PLCSigningKeyResolver, error) {
	client, origin, err := oauthclient.NewPinnedHTTPClient(plcOrigin, allowHTTP)
	if err != nil {
		return nil, err
	}
	return &PLCSigningKeyResolver{client: client, origin: origin, cache: make(map[syntax.DID]identity.Identity)}, nil
}

func (r *PLCSigningKeyResolver) ResolveCredentialKey(ctx context.Context, did syntax.DID, kid string, forceRefresh bool) (atcrypto.PublicKey, error) {
	if kid != "#atproto" && kid != "#atproto_space" {
		return nil, errors.New("spacecredential: unsupported credential signing key ID")
	}
	ident, err := r.resolveIdentity(ctx, did, forceRefresh)
	if err != nil {
		return nil, err
	}
	keyID := strings.TrimPrefix(kid, "#")
	if keyID == "atproto" {
		if _, dedicated := ident.Keys["atproto_space"]; dedicated {
			return nil, errors.New("spacecredential: refused credential signing-key downgrade")
		}
	}
	key, err := ident.GetPublicKey(keyID)
	if err != nil {
		return nil, errors.New("spacecredential: credential signing key is not declared")
	}
	return key, nil
}

func (r *PLCSigningKeyResolver) ResolveSpaceHost(ctx context.Context, did syntax.DID, forceRefresh bool) (string, error) {
	ident, err := r.resolveIdentity(ctx, did, forceRefresh)
	if err != nil {
		return "", err
	}
	endpoint := ident.GetServiceEndpoint("atproto_space_host")
	if endpoint == "" {
		endpoint = ident.PDSEndpoint()
	}
	if endpoint == "" {
		return "", errors.New("spacecredential: space authority declares no host endpoint")
	}
	return endpoint, nil
}

func (r *PLCSigningKeyResolver) resolveIdentity(ctx context.Context, did syntax.DID, forceRefresh bool) (identity.Identity, error) {
	if did.Method() != "plc" {
		return identity.Identity{}, errors.New("spacecredential: pinned PLC resolver accepts only did:plc")
	}
	if !forceRefresh {
		r.mu.Lock()
		cached, ok := r.cache[did]
		r.mu.Unlock()
		if ok {
			return cached, nil
		}
	}
	target, err := url.Parse(r.origin)
	if err != nil {
		return identity.Identity{}, errors.New("spacecredential: invalid pinned PLC origin")
	}
	target.Path = "/" + did.String()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return identity.Identity{}, errors.New("spacecredential: construct PLC request")
	}
	request.Header.Set("Accept", "application/did+ld+json, application/json")
	response, err := r.client.Do(request)
	if err != nil {
		return identity.Identity{}, errors.New("spacecredential: resolve authority DID")
	}
	if response == nil || response.Body == nil {
		return identity.Identity{}, errors.New("spacecredential: PLC returned no response")
	}
	defer response.Body.Close()
	if response.Request == nil || !sameOrigin(response.Request.URL, r.origin) || response.StatusCode != http.StatusOK {
		return identity.Identity{}, errors.New("spacecredential: PLC DID resolution failed")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxDIDDocumentBytes+1))
	if err != nil || len(data) > maxDIDDocumentBytes {
		return identity.Identity{}, errors.New("spacecredential: PLC DID document exceeded limit")
	}
	var document identity.DIDDocument
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&document); err != nil {
		return identity.Identity{}, errors.New("spacecredential: invalid PLC DID document")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) || document.DID != did {
		return identity.Identity{}, errors.New("spacecredential: PLC DID document identity mismatch")
	}
	ident := identity.ParseIdentity(&document)
	if ident.DID != did {
		return identity.Identity{}, errors.New("spacecredential: parsed PLC identity mismatch")
	}
	r.mu.Lock()
	r.cache[did] = ident
	r.mu.Unlock()
	return ident, nil
}

var _ SigningKeyResolver = (*PLCSigningKeyResolver)(nil)
