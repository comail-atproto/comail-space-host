package happyview

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const sessionCookiePrefix = "happyview_session="

// SessionDoer authenticates only to a loopback HappyView instance with a
// browser-created signed session cookie. It deliberately refuses redirects,
// proxies, inherited auth headers, symlinked files, and broadly readable
// secret files.
type SessionDoer struct {
	cookie string
	client *http.Client
}

func NewSessionDoer(cookiePath string) (*SessionDoer, error) {
	if !filepath.IsAbs(cookiePath) {
		return nil, errors.New("happyview: session cookie path must be absolute")
	}
	info, err := os.Lstat(cookiePath)
	if err != nil {
		return nil, fmt.Errorf("happyview: inspect session cookie file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o177 != 0 {
		return nil, errors.New("happyview: session cookie must be a regular owner-only file")
	}
	file, err := os.Open(cookiePath)
	if err != nil {
		return nil, fmt.Errorf("happyview: open session cookie file: %w", err)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, 16*1024+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, fmt.Errorf("happyview: read session cookie file: %w", readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("happyview: close session cookie file: %w", closeErr)
	}
	if len(data) > 16*1024 {
		return nil, errors.New("happyview: session cookie exceeds safety bound")
	}
	cookie := strings.TrimSpace(string(data))
	value := strings.TrimPrefix(cookie, sessionCookiePrefix)
	if value == cookie || value == "" || strings.ContainsAny(value, ";\r\n\x00") {
		return nil, errors.New("happyview: expected one happyview_session cookie")
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	return &SessionDoer{
		cookie: cookie,
		client: &http.Client{
			Transport: transport,
			Timeout:   60 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (d *SessionDoer) Do(ctx context.Context, request *http.Request, _ string) (*http.Response, error) {
	if d == nil || d.client == nil || d.cookie == "" || request == nil || request.URL == nil {
		return nil, errors.New("happyview: invalid session request")
	}
	if !isLoopbackHost(request.URL.Hostname()) {
		return nil, errors.New("happyview: browser session cookies are loopback-only")
	}
	if request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" {
		return nil, errors.New("happyview: refused inherited authentication header")
	}
	clone := request.Clone(ctx)
	clone.Header = request.Header.Clone()
	clone.Header.Set("Cookie", d.cookie)
	return d.client.Do(clone)
}

var _ Doer = (*SessionDoer)(nil)
