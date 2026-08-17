package serviceauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mr-tron/base58"
)

const tokenLifetime = 60 * time.Second

type Config struct {
	IssuerDID         string
	Audience          string
	Key               *ecdsa.PrivateKey
	HTTPClient        *http.Client
	AllowLoopbackHTTP bool
	Now               func() time.Time
}

type Signer struct {
	issuerDID         string
	audience          string
	key               *ecdsa.PrivateKey
	http              *http.Client
	allowLoopbackHTTP bool
	now               func() time.Time
}

type VerificationMethod struct {
	ID                 string `json:"id"`
	Type               string `json:"type"`
	Controller         string `json:"controller"`
	PublicKeyMultibase string `json:"publicKeyMultibase"`
}

type Document struct {
	Context            []string             `json:"@context"`
	ID                 string               `json:"id"`
	VerificationMethod []VerificationMethod `json:"verificationMethod"`
	Service            []any                `json:"service"`
}

func New(config Config) (*Signer, error) {
	if !validDIDWeb(config.IssuerDID) || !validAudience(config.Audience) || config.Key == nil || config.Key.Curve != elliptic.P256() || config.Key.D == nil {
		return nil, errors.New("serviceauth: exact did:web issuer, audience fragment, and P-256 key are required")
	}
	hc := config.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 45 * time.Second}
	}
	copyClient := *hc
	if copyClient.Timeout == 0 {
		copyClient.Timeout = 45 * time.Second
	}
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("serviceauth: authenticated redirects are disabled")
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	return &Signer{
		issuerDID: config.IssuerDID, audience: config.Audience, key: config.Key,
		http: &copyClient, allowLoopbackHTTP: config.AllowLoopbackHTTP, now: now,
	}, nil
}

func validDIDWeb(value string) bool {
	return strings.HasPrefix(value, "did:web:") && len(value) > len("did:web:") && !strings.ContainsAny(value, "/?#@ \t\r\n\x00")
}

func validAudience(value string) bool {
	parts := strings.Split(value, "#")
	return len(parts) == 2 && validDIDWeb(parts[0]) && parts[1] != "" && !strings.ContainsAny(parts[1], "/?#@ \t\r\n\x00")
}

func (s *Signer) Do(ctx context.Context, request *http.Request, endpoint string) (*http.Response, error) {
	if request == nil || request.URL == nil || endpoint == "" || request.URL.Path != "/xrpc/"+endpoint {
		return nil, errors.New("serviceauth: exact XRPC request and method are required")
	}
	if request.URL.Scheme != "https" {
		if !(s.allowLoopbackHTTP && request.URL.Scheme == "http" && isLoopback(request.URL.Hostname())) {
			return nil, errors.New("serviceauth: authenticated XRPC requires HTTPS")
		}
	}
	now := s.now().UTC()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": s.issuerDID,
		"aud": s.audience,
		"lxm": endpoint,
		"exp": now.Add(tokenLifetime).Unix(),
	})
	delete(token.Header, "typ")
	signed, err := token.SignedString(s.key)
	if err != nil {
		return nil, fmt.Errorf("serviceauth: sign request: %w", err)
	}
	clone := request.Clone(ctx)
	clone.Header = request.Header.Clone()
	clone.Header.Set("Authorization", "Bearer "+signed)
	return s.http.Do(clone)
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *Signer) DIDDocument() Document {
	compressed := elliptic.MarshalCompressed(elliptic.P256(), s.key.PublicKey.X, s.key.PublicKey.Y)
	multicodec := append([]byte{0x80, 0x24}, compressed...)
	return Document{
		Context: []string{"https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"},
		ID:      s.issuerDID,
		VerificationMethod: []VerificationMethod{{
			ID: s.issuerDID + "#atproto", Type: "Multikey", Controller: s.issuerDID,
			PublicKeyMultibase: "z" + base58.Encode(multicodec),
		}},
		Service: []any{},
	}
}

func LoadPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	if !filepath.IsAbs(path) || path == string(filepath.Separator) {
		return nil, errors.New("serviceauth: signing key path must be absolute")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o177 != 0 {
		return nil, errors.New("serviceauth: signing key must be an owner-only regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	opened, statErr := file.Stat()
	if statErr != nil || !opened.Mode().IsRegular() || opened.Mode().Perm()&0o177 != 0 || !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, errors.New("serviceauth: signing key changed or became unsafe while opening")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, 16*1024+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(data) > 16*1024 {
		return nil, errors.New("serviceauth: signing key exceeds safety bound")
	}
	block, rest := pem.Decode(data)
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("serviceauth: signing key PEM is malformed")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("serviceauth: signing key must be PKCS#8")
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("serviceauth: signing key must be P-256")
	}
	return key, nil
}
