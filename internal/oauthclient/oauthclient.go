package oauthclient

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bluesky-social/indigo/atproto/auth/oauth"
	"github.com/bluesky-social/indigo/atproto/identity"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/comail-atproto/comail-space-host/internal/repository"
)

var ErrReauthorizationRequired = errors.New("oauthclient: interactive reauthorization required")

const maxDPoPNonceBytes = 1024

type Config struct {
	DID         string
	Handle      string
	Origin      string
	CallbackURL string
	SpaceKey    string
	AllowHTTP   bool
}

type Manager struct {
	app      *oauth.ClientApp
	did      syntax.DID
	handle   syntax.Handle
	origin   string
	spaceKey string
	client   *http.Client
}

func New(cfg Config, store oauth.ClientAuthStore) (*Manager, error) {
	if store == nil {
		return nil, errors.New("oauthclient: encrypted auth store is required")
	}
	did, err := syntax.ParseDID(cfg.DID)
	if err != nil {
		return nil, fmt.Errorf("oauthclient: parse exact DID: %w", err)
	}
	handle, err := syntax.ParseHandle(cfg.Handle)
	if err != nil {
		return nil, fmt.Errorf("oauthclient: parse exact handle: %w", err)
	}
	callback, err := url.Parse(cfg.CallbackURL)
	if err != nil || callback.Scheme != "http" || callback.Hostname() != "127.0.0.1" || callback.Port() == "" || callback.Path != "/oauth/callback" || callback.User != nil || callback.RawQuery != "" || callback.Fragment != "" {
		return nil, errors.New("oauthclient: callback must be exact http://127.0.0.1:PORT/oauth/callback")
	}
	client, origin, err := NewPinnedHTTPClient(cfg.Origin, cfg.AllowHTTP)
	if err != nil {
		return nil, err
	}
	scopes, err := MailboxScopes(did.String(), cfg.SpaceKey)
	if err != nil {
		return nil, err
	}
	oauthConfig := oauth.NewLocalhostConfig(cfg.CallbackURL, scopes)
	app := oauth.NewClientApp(&oauthConfig, store)
	app.Client = client
	app.Resolver.Client = client
	directory := identity.NewMockDirectory()
	directory.Insert(identity.Identity{
		DID: did, Handle: handle, AlsoKnownAs: []string{"at://" + handle.String()},
		Services: map[string]identity.ServiceEndpoint{
			"atproto_pds": {Type: "AtprotoPersonalDataServer", URL: origin},
		},
	})
	app.Dir = directory
	return &Manager{app: app, did: did, handle: handle, origin: origin, spaceKey: cfg.SpaceKey, client: client}, nil
}

func (m *Manager) Start(ctx context.Context) (string, error) {
	authorizeURL, err := m.app.StartAuthFlow(ctx, m.handle.String())
	if err != nil {
		return "", fmt.Errorf("oauthclient: start flow: %w", err)
	}
	u, err := url.Parse(authorizeURL)
	if err != nil || !sameOrigin(u, m.origin) || u.User != nil || u.Fragment != "" {
		return "", fmt.Errorf("%w: authorization URL escaped pinned provider", repository.ErrTarget)
	}
	return authorizeURL, nil
}

func (m *Manager) Finish(ctx context.Context, values url.Values) (*oauth.ClientSession, error) {
	data, err := m.app.ProcessCallback(ctx, values)
	if err != nil {
		return nil, fmt.Errorf("oauthclient: process callback: %w", err)
	}
	if data.AccountDID != m.did || !sameOriginString(data.HostURL, m.origin) {
		rejection := fmt.Errorf("%w: OAuth subject or resource server mismatch", repository.ErrTarget)
		return nil, m.rejectSession(ctx, data.AccountDID, data.SessionID, nil, rejection)
	}
	if err := ValidateSteadyGrant(data.Scopes, m.did.String(), m.spaceKey); err != nil {
		rejection := fmt.Errorf("%w: %v", repository.ErrUnauthorized, err)
		return nil, m.rejectSession(ctx, data.AccountDID, data.SessionID, nil, rejection)
	}
	return m.Resume(ctx, data.SessionID)
}

func (m *Manager) Resume(ctx context.Context, sessionID string) (*oauth.ClientSession, error) {
	if sessionID == "" {
		return nil, errors.New("oauthclient: session ID is required")
	}
	session, err := m.app.ResumeSession(ctx, m.did, sessionID)
	if err != nil {
		return nil, fmt.Errorf("oauthclient: resume session: %w", err)
	}
	if session.Data.AccountDID != m.did || !sameOriginString(session.Data.HostURL, m.origin) {
		rejection := fmt.Errorf("%w: resumed OAuth session target mismatch", repository.ErrTarget)
		return nil, m.rejectSession(ctx, m.did, sessionID, session, rejection)
	}
	if err := ValidateSteadyGrant(session.Data.Scopes, m.did.String(), m.spaceKey); err != nil {
		rejection := fmt.Errorf("%w: %v", repository.ErrUnauthorized, err)
		return nil, m.rejectSession(ctx, m.did, sessionID, session, rejection)
	}
	return session, nil
}

func (m *Manager) rejectSession(ctx context.Context, storageDID syntax.DID, sessionID string, session *oauth.ClientSession, rejection error) error {
	var resumeErr error
	if session == nil {
		session, resumeErr = m.app.ResumeSession(ctx, storageDID, sessionID)
	}
	var revokeErr error
	if session == nil {
		revokeErr = errors.New("oauthclient: could not load rejected session for remote revocation")
	} else if session.Data.AuthServerRevocationEndpoint == "" {
		revokeErr = errors.New("oauthclient: OAuth server supplied no revocation endpoint for rejected session")
	} else if err := session.RevokeSession(ctx); err != nil {
		revokeErr = fmt.Errorf("oauthclient: revoke rejected OAuth session: %w", err)
	}
	deleteErr := m.app.Store.DeleteSession(ctx, storageDID, sessionID)
	if deleteErr != nil {
		deleteErr = fmt.Errorf("oauthclient: delete rejected OAuth session: %w", deleteErr)
	}
	if resumeErr != nil {
		resumeErr = fmt.Errorf("oauthclient: resume rejected OAuth session for cleanup: %w", resumeErr)
	}
	return errors.Join(rejection, resumeErr, revokeErr, deleteErr)
}

func (m *Manager) Doer(session *oauth.ClientSession) (*SessionDoer, error) {
	if session == nil || session.Data == nil || session.Data.AccountDID != m.did || !sameOriginString(session.Data.HostURL, m.origin) {
		return nil, repository.ErrTarget
	}
	if err := ValidateSteadyGrant(session.Data.Scopes, m.did.String(), m.spaceKey); err != nil {
		return nil, fmt.Errorf("%w: %v", repository.ErrUnauthorized, err)
	}
	return &SessionDoer{session: session, client: m.client, origin: m.origin, did: m.did.String(), spaceKey: m.spaceKey}, nil
}

type SessionDoer struct {
	mu       sync.Mutex
	session  *oauth.ClientSession
	client   *http.Client
	origin   string
	did      string
	spaceKey string
}

func (d *SessionDoer) Do(ctx context.Context, req *http.Request, endpoint string) (*http.Response, error) {
	if req == nil || req.URL == nil || !sameOrigin(req.URL, d.origin) {
		return nil, repository.ErrTarget
	}
	if req.Host != "" && !strings.EqualFold(req.Host, req.URL.Host) {
		return nil, repository.ErrTarget
	}
	if _, err := syntax.ParseNSID(endpoint); err != nil {
		return nil, fmt.Errorf("oauthclient: parse endpoint: %w", err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.session == nil || d.session.Data == nil {
		return nil, repository.ErrTarget
	}
	if err := ValidateSteadyGrant(d.session.Data.Scopes, d.did, d.spaceKey); err != nil {
		return nil, fmt.Errorf("%w: %v", repository.ErrUnauthorized, err)
	}
	accessToken, originalNonce := d.session.GetHostAccessData()
	if accessToken == "" {
		return nil, ErrReauthorizationRequired
	}
	dpopURL := *req.URL
	dpopURL.RawQuery = ""
	dpopURL.ForceQuery = false
	dpopURL.Fragment = ""
	dpopURL.RawFragment = ""

	for attempt := range 2 {
		currentToken, currentNonce := d.session.GetHostAccessData()
		if currentToken != accessToken {
			return nil, ErrReauthorizationRequired
		}
		proof, err := d.session.NewHostDPoP(req.Method, dpopURL.String())
		if err != nil {
			return nil, fmt.Errorf("oauthclient: create host DPoP proof: %w", err)
		}
		if currentToken, _ = d.session.GetHostAccessData(); currentToken != accessToken {
			return nil, ErrReauthorizationRequired
		}
		attemptRequest := req.Clone(ctx)
		attemptRequest.Header = req.Header.Clone()
		if attempt > 0 && req.Body != nil {
			if req.GetBody == nil {
				return nil, errors.New("oauthclient: request body cannot be replayed for a DPoP nonce")
			}
			attemptRequest.Body, err = req.GetBody()
			if err != nil {
				return nil, fmt.Errorf("oauthclient: replay request body: %w", err)
			}
		}
		attemptRequest.Header.Set("Authorization", "DPoP "+accessToken)
		attemptRequest.Header.Set("DPoP", proof)
		resp, err := d.client.Do(attemptRequest)
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Request == nil || !sameOrigin(resp.Request.URL, d.origin) ||
			(resp.Request.Host != "" && !strings.EqualFold(resp.Request.Host, resp.Request.URL.Host)) {
			if resp != nil && resp.Body != nil {
				_ = resp.Body.Close()
			}
			return nil, repository.ErrTarget
		}
		if err := ValidateSteadyGrant(d.session.Data.Scopes, d.did, d.spaceKey); err != nil {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("%w: %v", repository.ErrUnauthorized, err)
		}
		if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("WWW-Authenticate") == "" {
			return resp, nil
		}
		authHeader := resp.Header.Get("WWW-Authenticate")
		if strings.Contains(authHeader, `error="invalid_token"`) {
			_ = resp.Body.Close()
			return nil, ErrReauthorizationRequired
		}
		newNonce := resp.Header.Get("DPoP-Nonce")
		if !strings.Contains(authHeader, `error="use_dpop_nonce"`) || newNonce == "" {
			return resp, nil
		}
		_ = resp.Body.Close()
		if attempt > 0 || newNonce == currentNonce || newNonce == originalNonce || len(newNonce) > maxDPoPNonceBytes {
			return nil, errors.New("oauthclient: invalid or repeated PDS DPoP nonce")
		}
		d.session.UpdateHostDPoPNonce(ctx, newNonce)
	}
	return nil, errors.New("oauthclient: exhausted PDS DPoP nonce retry")
}

// NewPinnedHTTPClient returns a no-proxy, no-redirect client bound to the
// exact resolved addresses and TLS hostname of one clean origin.
func NewPinnedHTTPClient(rawOrigin string, allowHTTP bool) (*http.Client, string, error) {
	origin, err := url.Parse(rawOrigin)
	if err != nil || origin.Hostname() == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || (origin.Path != "" && origin.Path != "/") {
		return nil, "", errors.New("oauthclient: provider must be a clean origin")
	}
	hadExplicitPort := origin.Port() != ""
	canonicalizeOrigin(origin)
	if origin.Scheme == "http" {
		if !allowHTTP || !hadExplicitPort || net.ParseIP(origin.Hostname()) == nil || !net.ParseIP(origin.Hostname()).IsLoopback() {
			return nil, "", errors.New("oauthclient: HTTP is allowed only for an explicit loopback test origin")
		}
	} else if origin.Scheme != "https" {
		return nil, "", errors.New("oauthclient: provider must use HTTPS")
	}
	origin.Path = ""
	origin.RawPath = ""
	cleanOrigin := strings.TrimSuffix(origin.String(), "/")
	port := originDialPort(origin)
	expectedAddress := net.JoinHostPort(origin.Hostname(), port)
	dialTargets := []string{expectedAddress}
	if origin.Scheme == "https" {
		resolveCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		addresses, err := net.DefaultResolver.LookupIPAddr(resolveCtx, origin.Hostname())
		if err != nil {
			return nil, "", fmt.Errorf("oauthclient: resolve pinned provider: %w", err)
		}
		if len(addresses) == 0 {
			return nil, "", errors.New("oauthclient: pinned provider resolved to no addresses")
		}
		dialTargets = dialTargets[:0]
		for _, address := range addresses {
			ip := address.IP
			if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
				return nil, "", errors.New("oauthclient: HTTPS provider resolved to a non-public address")
			}
			dialTargets = append(dialTargets, net.JoinHostPort(ip.String(), port))
		}
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	var nextTarget atomic.Uint64
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if !strings.EqualFold(address, expectedAddress) {
				return nil, fmt.Errorf("oauthclient: refused outbound address %q", address)
			}
			start := int(nextTarget.Add(1)-1) % len(dialTargets)
			var lastErr error
			for i := range dialTargets {
				target := dialTargets[(start+i)%len(dialTargets)]
				connection, err := dialer.DialContext(ctx, network, target)
				if err == nil {
					return connection, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12, ServerName: origin.Hostname()},
		ForceAttemptHTTP2: true,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   20 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("oauthclient: refused authenticated HTTP redirect")
		},
	}
	return client, cleanOrigin, nil
}

func canonicalizeOrigin(origin *url.URL) {
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
}

func originDialPort(origin *url.URL) string {
	if port := origin.Port(); port != "" {
		return port
	}
	if origin.Scheme == "http" {
		return "80"
	}
	return "443"
}

func newPinnedHTTPClient(rawOrigin string, allowHTTP bool) (*http.Client, string, error) {
	return NewPinnedHTTPClient(rawOrigin, allowHTTP)
}

func sameOriginString(raw, expected string) bool {
	u, err := url.Parse(raw)
	return err == nil && sameOrigin(u, expected)
}

func sameOrigin(u *url.URL, expected string) bool {
	want, err := url.Parse(expected)
	if err != nil || u == nil || u.User != nil || u.Opaque != "" || u.Host == "" || u.Fragment != "" {
		return false
	}
	return strings.EqualFold(u.Scheme, want.Scheme) && strings.EqualFold(u.Hostname(), want.Hostname()) && effectivePort(u) == effectivePort(want)
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
