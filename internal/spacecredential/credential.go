package spacecredential

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/comail-atproto/comail-space-host/internal/repository"
)

const (
	credentialTokenType      = "atproto-space-credential+jwt"
	maxCredentialBytes       = 16 * 1024
	maxCredentialLifetime    = 2 * time.Hour
	credentialClockSkew      = 5 * time.Second
	defaultCredentialRenewal = 10 * time.Minute
)

var (
	ErrCredentialClosed  = errors.New("spacecredential: credential is closed")
	ErrCredentialExpired = errors.New("spacecredential: credential is expired")
	credentialJWTID      = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

type SigningKeyResolver interface {
	ResolveCredentialKey(ctx context.Context, did syntax.DID, kid string, forceRefresh bool) (atcrypto.PublicKey, error)
	ResolveSpaceHost(ctx context.Context, did syntax.DID, forceRefresh bool) (string, error)
}

type credentialHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid"`
}

type confirmationClaim struct {
	JKT string `json:"jkt"`
}

type credentialClaims struct {
	Issuer       string            `json:"iss"`
	Subject      string            `json:"sub"`
	Audience     json.RawMessage   `json:"aud,omitempty"`
	IssuedAt     int64             `json:"iat"`
	ExpiresAt    int64             `json:"exp"`
	JWTID        string            `json:"jti"`
	Confirmation confirmationClaim `json:"cnf"`
}

type Credential struct {
	mu            sync.Mutex
	token         string
	key           atcrypto.PrivateKey
	spaceURI      string
	origin        string
	client        *http.Client
	now           func() time.Time
	expiresAt     time.Time
	renewalWindow time.Duration
	closed        bool
}

func (c *Credential) String() string   { return "spacecredential.Credential(redacted)" }
func (c *Credential) GoString() string { return "spacecredential.Credential{redacted}" }

func (c *Credential) ExpiresAt() time.Time {
	if c == nil {
		return time.Time{}
	}
	return c.expiresAt
}

func (c *Credential) NeedsRenewal(now time.Time) bool {
	if c == nil || c.expiresAt.IsZero() {
		return true
	}
	return !now.UTC().Add(c.renewalWindow).Before(c.expiresAt)
}

func (c *Credential) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = ""
	c.key = nil
	c.closed = true
}

func (c *Credential) Do(ctx context.Context, request *http.Request, endpoint string) (*http.Response, error) {
	if c == nil || request == nil || request.URL == nil || !sameOrigin(request.URL, c.origin) {
		return nil, repository.ErrTarget
	}
	if request.Host != "" && !strings.EqualFold(request.Host, request.URL.Host) {
		return nil, repository.ErrTarget
	}
	if _, err := syntax.ParseNSID(endpoint); err != nil || request.URL.EscapedPath() != "/xrpc/"+endpoint {
		return nil, repository.ErrTarget
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.token == "" || c.key == nil {
		return nil, ErrCredentialClosed
	}
	if !c.now().UTC().Add(-credentialClockSkew).Before(c.expiresAt) {
		return nil, ErrCredentialExpired
	}
	proof, err := newDPoPProof(c.key, request.Method, request.URL.String(), &c.token, c.now())
	if err != nil {
		return nil, err
	}
	attempt := request.Clone(ctx)
	attempt.Header = request.Header.Clone()
	attempt.Header.Set("Authorization", "DPoP "+c.token)
	attempt.Header.Set("DPoP", proof)
	response, err := c.client.Do(attempt)
	if err != nil {
		return nil, err
	}
	if response == nil || response.Request == nil || !sameOrigin(response.Request.URL, c.origin) ||
		(response.Request.Host != "" && !strings.EqualFold(response.Request.Host, response.Request.URL.Host)) {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, repository.ErrTarget
	}
	return response, nil
}

func validateCredential(ctx context.Context, token, issuerDID, spaceURI, dpopJKT string, resolver SigningKeyResolver, now time.Time) (credentialClaims, error) {
	if token == "" || len(token) > maxCredentialBytes || strings.ContainsAny(token, " \t\r\n") {
		return credentialClaims{}, errors.New("spacecredential: malformed credential")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return credentialClaims{}, errors.New("spacecredential: malformed credential")
	}
	var header credentialHeader
	var claims credentialClaims
	if err := decodeJWTPart(parts[0], &header); err != nil {
		return credentialClaims{}, errors.New("spacecredential: malformed credential header")
	}
	if err := decodeJWTPart(parts[1], &claims); err != nil {
		return credentialClaims{}, errors.New("spacecredential: malformed credential claims")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != 64 {
		return credentialClaims{}, errors.New("spacecredential: malformed credential signature")
	}
	if header.Type != credentialTokenType || (header.KeyID != "#atproto" && header.KeyID != "#atproto_space") {
		return credentialClaims{}, errors.New("spacecredential: credential header mismatch")
	}
	did, err := syntax.ParseDID(issuerDID)
	if err != nil || claims.Issuer != did.String() || claims.Subject != spaceURI || len(claims.Audience) != 0 || claims.Confirmation.JKT != dpopJKT {
		return credentialClaims{}, errors.New("spacecredential: credential target or binding mismatch")
	}
	if !credentialJWTID.MatchString(claims.JWTID) || claims.IssuedAt < 0 || claims.ExpiresAt <= claims.IssuedAt || claims.ExpiresAt-claims.IssuedAt > int64(maxCredentialLifetime/time.Second) {
		return credentialClaims{}, errors.New("spacecredential: credential lifetime claims are invalid")
	}
	nowSeconds := now.UTC().Unix()
	if claims.IssuedAt > nowSeconds+int64(credentialClockSkew/time.Second) || nowSeconds-int64(credentialClockSkew/time.Second) >= claims.ExpiresAt {
		return credentialClaims{}, ErrCredentialExpired
	}
	publicKey, err := resolver.ResolveCredentialKey(ctx, did, header.KeyID, false)
	if err != nil || publicKey == nil {
		return credentialClaims{}, errors.New("spacecredential: resolve credential signing key")
	}
	signingInput := []byte(parts[0] + "." + parts[1])
	if err := verifyCredentialSignature(publicKey, header.Algorithm, signingInput, signature); err != nil {
		freshKey, refreshErr := resolver.ResolveCredentialKey(ctx, did, header.KeyID, true)
		if refreshErr != nil || freshKey == nil || freshKey.Equal(publicKey) || verifyCredentialSignature(freshKey, header.Algorithm, signingInput, signature) != nil {
			return credentialClaims{}, errors.New("spacecredential: invalid credential signature")
		}
	}
	return claims, nil
}

func verifyCredentialSignature(key atcrypto.PublicKey, algorithm string, signingInput, signature []byte) error {
	switch key.(type) {
	case *atcrypto.PublicKeyP256:
		if algorithm != "ES256" {
			return errors.New("algorithm mismatch")
		}
	case *atcrypto.PublicKeyK256:
		if algorithm != "ES256K" {
			return errors.New("algorithm mismatch")
		}
	default:
		return errors.New("unsupported key")
	}
	return key.HashAndVerify(signingInput, signature)
}

func decodeJWTPart(encoded string, output any) error {
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(data) == 0 || len(data) > maxCredentialBytes {
		return errors.New("invalid JWT encoding")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing JWT JSON")
	}
	return nil
}

func sameOrigin(target *url.URL, origin string) bool {
	want, err := url.Parse(origin)
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
	if target.Scheme == "http" {
		return "80"
	}
	return ""
}
