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
	"github.com/comail-atproto/comail-pds-lab/internal/mailbox"
	"github.com/comail-atproto/comail-pds-lab/internal/repository"
)

type Config struct {
	DID         string
	Handle      string
	Origin      string
	CallbackURL string
	SpaceKey    string
	AllowHTTP   bool
}

type Manager struct {
	app    *oauth.ClientApp
	did    syntax.DID
	handle syntax.Handle
	origin string
	scopes []string
	client *http.Client
}

func MailboxScopes(spaceKey string) ([]string, error) {
	if spaceKey == "" || strings.ContainsAny(spaceKey, "&=?# /+") {
		return nil, errors.New("oauthclient: safe exact space key is required")
	}
	spaceScope := "space:" + mailbox.MailboxSpaceType + "?authority=self&skey=" + url.QueryEscape(spaceKey) +
		"&collection=" + mailbox.MessageCollection +
		"&collection=" + mailbox.MessageStateCollection +
		"&collection=" + mailbox.FolderCollection +
		"&action=read&action=create&action=update&action=delete&manage=create&manage=update&manage=delete"
	return []string{"atproto", "blob:" + mailbox.MessageMIMEType, spaceScope}, nil
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
	client, origin, err := newPinnedHTTPClient(cfg.Origin, cfg.AllowHTTP)
	if err != nil {
		return nil, err
	}
	scopes, err := MailboxScopes(cfg.SpaceKey)
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
	return &Manager{app: app, did: did, handle: handle, origin: origin, scopes: scopes, client: client}, nil
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
		return nil, fmt.Errorf("%w: OAuth subject or resource server mismatch", repository.ErrTarget)
	}
	for _, required := range m.scopes {
		if !contains(data.Scopes, required) {
			_ = m.app.Store.DeleteSession(ctx, data.AccountDID, data.SessionID)
			return nil, fmt.Errorf("%w: OAuth grant omitted a required scope", repository.ErrUnauthorized)
		}
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
		return nil, fmt.Errorf("%w: resumed OAuth session target mismatch", repository.ErrTarget)
	}
	return session, nil
}

func (m *Manager) Doer(session *oauth.ClientSession) (*SessionDoer, error) {
	if session == nil || session.Data == nil || session.Data.AccountDID != m.did || !sameOriginString(session.Data.HostURL, m.origin) {
		return nil, repository.ErrTarget
	}
	return &SessionDoer{session: session, client: m.client, origin: m.origin}, nil
}

type SessionDoer struct {
	mu      sync.Mutex
	session *oauth.ClientSession
	client  *http.Client
	origin  string
}

func (d *SessionDoer) Do(ctx context.Context, req *http.Request, endpoint string) (*http.Response, error) {
	if req == nil || req.URL == nil || !sameOrigin(req.URL, d.origin) {
		return nil, repository.ErrTarget
	}
	nsid, err := syntax.ParseNSID(endpoint)
	if err != nil {
		return nil, fmt.Errorf("oauthclient: parse endpoint: %w", err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	resp, err := d.session.DoWithAuth(d.client, req.WithContext(ctx), nsid)
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Request == nil || !sameOrigin(resp.Request.URL, d.origin) {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		return nil, repository.ErrTarget
	}
	return resp, nil
}

func newPinnedHTTPClient(rawOrigin string, allowHTTP bool) (*http.Client, string, error) {
	origin, err := url.Parse(rawOrigin)
	if err != nil || origin.Hostname() == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || (origin.Path != "" && origin.Path != "/") {
		return nil, "", errors.New("oauthclient: provider must be a clean origin")
	}
	if origin.Scheme == "http" {
		if !allowHTTP || origin.Port() == "" || net.ParseIP(origin.Hostname()) == nil || !net.ParseIP(origin.Hostname()).IsLoopback() {
			return nil, "", errors.New("oauthclient: HTTP is allowed only for an explicit loopback test origin")
		}
	} else if origin.Scheme != "https" {
		return nil, "", errors.New("oauthclient: provider must use HTTPS")
	}
	origin.Path = ""
	origin.RawPath = ""
	cleanOrigin := strings.TrimSuffix(origin.String(), "/")
	port := origin.Port()
	if port == "" {
		port = "443"
	}
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

func sameOriginString(raw, expected string) bool {
	u, err := url.Parse(raw)
	return err == nil && sameOrigin(u, expected)
}

func sameOrigin(u *url.URL, expected string) bool {
	want, err := url.Parse(expected)
	if err != nil || u == nil {
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

func contains(values []string, required string) bool {
	for _, value := range values {
		if value == required {
			return true
		}
	}
	return false
}
