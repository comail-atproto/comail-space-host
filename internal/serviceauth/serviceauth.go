package serviceauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
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
	Origin            string
	Key               *ecdsa.PrivateKey
	HTTPClient        *http.Client
	AllowLoopbackHTTP bool
	Now               func() time.Time
}

type Signer struct {
	issuerDID         string
	audience          string
	origin            *url.URL
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
	origin, err := cleanOrigin(config.Origin, config.AllowLoopbackHTTP)
	if !validDIDWeb(config.IssuerDID) || !validAudience(config.Audience) || err != nil || config.Key == nil || config.Key.Curve != elliptic.P256() || config.Key.D == nil {
		return nil, errors.New("serviceauth: exact did:web issuer, audience fragment, and P-256 key are required")
	}
	hc := config.HTTPClient
	if hc == nil {
		hc = &http.Client{
			Transport: &http.Transport{
				Proxy: nil,
				DialContext: (&net.Dialer{
					Timeout: 10 * time.Second, KeepAlive: 30 * time.Second,
				}).DialContext,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          10,
				IdleConnTimeout:       30 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 30 * time.Second,
				TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
			},
			Timeout: 45 * time.Second,
		}
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
		issuerDID: config.IssuerDID, audience: config.Audience, origin: origin, key: config.Key,
		http: &copyClient, allowLoopbackHTTP: config.AllowLoopbackHTTP, now: now,
	}, nil
}

func cleanOrigin(value string, allowLoopbackHTTP bool) (*url.URL, error) {
	if value == "" {
		return nil, nil
	}
	origin, err := url.Parse(value)
	if err != nil || origin.Hostname() == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || origin.RawPath != "" ||
		(origin.Path != "" && (origin.Path == "/" || path.Clean(origin.Path) != origin.Path || strings.HasSuffix(origin.Path, "/"))) {
		return nil, errors.New("serviceauth: provider origin must be exact")
	}
	if origin.Scheme != "https" && !(allowLoopbackHTTP && origin.Scheme == "http" && isLoopback(origin.Hostname())) {
		return nil, errors.New("serviceauth: provider origin must use HTTPS")
	}
	return origin, nil
}

func validDIDWeb(value string) bool {
	return strings.HasPrefix(value, "did:web:") && len(value) > len("did:web:") && !strings.ContainsAny(value, "/?#@ \t\r\n\x00")
}

func validAudience(value string) bool {
	parts := strings.Split(value, "#")
	return len(parts) == 2 && validDIDWeb(parts[0]) && parts[1] != "" && !strings.ContainsAny(parts[1], "/?#@ \t\r\n\x00")
}

func (s *Signer) Do(ctx context.Context, request *http.Request, endpoint string) (*http.Response, error) {
	if request == nil || request.URL == nil || s.origin == nil || endpoint == "" || !sameOrigin(request.URL, s.origin) ||
		request.URL.Path != s.origin.Path+"/xrpc/"+endpoint {
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

func sameOrigin(actual, expected *url.URL) bool {
	return actual != nil && expected != nil && actual.User == nil &&
		strings.EqualFold(actual.Scheme, expected.Scheme) && strings.EqualFold(actual.Hostname(), expected.Hostname()) &&
		effectivePort(actual) == effectivePort(expected)
}

func effectivePort(value *url.URL) string {
	if value.Port() != "" {
		return value.Port()
	}
	if value.Scheme == "https" {
		return "443"
	}
	if value.Scheme == "http" {
		return "80"
	}
	return ""
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
	if !privateKeyFileSafe(path, info) {
		return nil, errors.New("serviceauth: signing key must be an owner-only regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	opened, statErr := file.Stat()
	if statErr != nil || !privateKeyFileSafe(path, opened) || !os.SameFile(info, opened) {
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

func privateKeyFileSafe(path string, info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() {
		return false
	}
	permissions := info.Mode().Perm()
	if permissions&0o177 == 0 {
		return true
	}
	// Current systemd exposes LoadCredential files as 0440 root:root plus an
	// ACL granting only the service user access. Accept that one documented
	// credential shape only for a direct child of the manager-provided private
	// credential directory; ordinary group-readable key files remain rejected.
	credentialDirectory := strings.TrimSpace(os.Getenv("CREDENTIALS_DIRECTORY"))
	if permissions != 0o440 || credentialDirectory == "" || !filepath.IsAbs(credentialDirectory) {
		return false
	}
	cleanDirectory := filepath.Clean(credentialDirectory)
	directoryInfo, err := os.Lstat(cleanDirectory)
	if err != nil || !directoryInfo.IsDir() {
		return false
	}
	cleanPath := filepath.Clean(path)
	return cleanPath != cleanDirectory && filepath.Dir(cleanPath) == cleanDirectory
}
