package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/comail-atproto/comail-pds-lab/internal/authoritycert"
	"github.com/comail-atproto/comail-pds-lab/internal/providers/happyview"
	"github.com/comail-atproto/comail-pds-lab/internal/shadowagent"
)

type options struct {
	Listen                          string
	Provider                        string
	Origin                          string
	BasePath                        string
	PublicHost                      string
	DID                             string
	SpaceKey                        string
	CookieFile                      string
	TokenFile                       string
	Commit                          bool
	AuthorityCertificateSHA256      string
	SourceVersioningCertificateFile string
}

type virtualHostDoer struct {
	inner      happyview.Doer
	basePath   string
	publicHost string
}

func (d *virtualHostDoer) Do(ctx context.Context, request *http.Request, endpoint string) (*http.Response, error) {
	clone := request.Clone(ctx)
	clone.URL.Path = d.basePath + request.URL.Path
	clone.Host = d.publicHost
	clone.Header = request.Header.Clone()
	return d.inner.Do(ctx, clone, endpoint)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "comail-pds-agent:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("comail-pds-agent", flag.ContinueOnError)
	opts := options{}
	flags.StringVar(&opts.Listen, "listen", "127.0.0.1:39094", "exact IPv4 loopback listener")
	flags.StringVar(&opts.Provider, "provider", "", "explicit isolated provider adapter")
	flags.StringVar(&opts.Origin, "origin", "http://127.0.0.1:39090", "provider loopback origin")
	flags.StringVar(&opts.BasePath, "base-path", "/comail-pds-lab", "provider path prefix")
	flags.StringVar(&opts.PublicHost, "public-host", "little-mac.lobster-hake.ts.net", "provider virtual host")
	flags.StringVar(&opts.DID, "did", "", "exact mailbox recipient DID")
	flags.StringVar(&opts.SpaceKey, "space-key", "default", "exact mailbox space key")
	flags.StringVar(&opts.CookieFile, "cookie-file", "", "absolute owner-only HappyView session file")
	flags.StringVar(&opts.TokenFile, "token-file", "", "absolute owner-only agent bearer token file")
	flags.BoolVar(&opts.Commit, "commit", false, "allow writes to the exact private target")
	flags.StringVar(&opts.AuthorityCertificateSHA256, "authority-certificate-sha256", "", "pinned authority certification evidence digest (enables v2 inventory/CAS)")
	flags.StringVar(&opts.SourceVersioningCertificateFile, "source-versioning-certificate-file", "", "owner-only v2 authority evidence bound to this exact provider epoch")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := validateOptions(opts); err != nil {
		return err
	}
	token, err := readOwnerSecret(opts.TokenFile)
	if err != nil {
		return fmt.Errorf("read agent token: %w", err)
	}
	session, err := happyview.NewSessionDoer(opts.CookieFile)
	if err != nil {
		return err
	}
	doer := &virtualHostDoer{inner: session, basePath: opts.BasePath, publicHost: opts.PublicHost}
	repo, err := happyview.New(happyview.Config{
		Origin: opts.Origin, DID: opts.DID, Epoch: happyview.CertifiedEpoch,
		AllowHTTP: true, AllowWrites: true,
	}, doer)
	if err != nil {
		return err
	}
	// Exact, idempotent provisioning also re-verifies the existing HappyView
	// space's private policy and collection allowlist before the agent serves.
	target, err := repo.EnsureMailbox(ctx, opts.DID, opts.SpaceKey)
	if err != nil {
		return fmt.Errorf("verify exact HappyView mailbox: %w", err)
	}
	authorityCertificateSHA256 := opts.AuthorityCertificateSHA256
	sourceVersioningCertified := false
	if opts.SourceVersioningCertificateFile != "" {
		digest, err := authoritycert.LoadEvidence(opts.SourceVersioningCertificateFile, repo.ProviderID(), target)
		if err != nil {
			return fmt.Errorf("verify source-versioning certificate: %w", err)
		}
		if authorityCertificateSHA256 != "" && authorityCertificateSHA256 != digest {
			return errors.New("source-versioning evidence digest does not match the pinned authority certificate")
		}
		authorityCertificateSHA256 = digest
		sourceVersioningCertified = true
	}
	handler, err := shadowagent.NewHandler(shadowagent.Config{
		Token: token, DID: opts.DID, Target: target, Repository: repo,
		AuthorityCertificateSHA256: authorityCertificateSHA256,
		SourceVersioningCertified:  sourceVersioningCertified,
	})
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp4", opts.Listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer listener.Close()
	server := &http.Server{
		Handler: handler, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 45 * time.Second, WriteTimeout: 45 * time.Second,
		IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 * 1024,
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(listener) }()
	fmt.Printf("Private mailbox shadow agent listening on http://%s (%s)\n", opts.Listen, repo.ProviderID())
	select {
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	}
}

func validateOptions(opts options) error {
	host, port, err := net.SplitHostPort(opts.Listen)
	if err != nil || host != "127.0.0.1" || port == "" {
		return errors.New("listener must use exact IPv4 loopback")
	}
	if opts.Provider != "happyview" {
		return errors.New("explicit --provider happyview is required by this lab command")
	}
	if !opts.Commit {
		return errors.New("live shadow agent requires explicit --commit")
	}
	if _, err := syntax.ParseDID(opts.DID); err != nil {
		return errors.New("exact mailbox DID is required")
	}
	if _, err := syntax.ParseRecordKey(opts.SpaceKey); err != nil {
		return errors.New("exact mailbox space key is required")
	}
	if opts.BasePath == "/" || (opts.BasePath != "" && (!strings.HasPrefix(opts.BasePath, "/") || strings.HasSuffix(opts.BasePath, "/") || strings.Contains(opts.BasePath, ".."))) {
		return errors.New("invalid provider base path")
	}
	if opts.PublicHost == "" || strings.ContainsAny(opts.PublicHost, "/ :?#@") {
		return errors.New("exact provider public host is required")
	}
	if !filepath.IsAbs(opts.CookieFile) || !filepath.IsAbs(opts.TokenFile) {
		return errors.New("cookie and token files must be absolute")
	}
	if opts.AuthorityCertificateSHA256 != "" {
		decoded, err := hex.DecodeString(opts.AuthorityCertificateSHA256)
		if err != nil || len(decoded) != sha256.Size || opts.AuthorityCertificateSHA256 != strings.ToLower(opts.AuthorityCertificateSHA256) {
			return errors.New("authority certificate SHA-256 must be 64 lowercase hexadecimal characters")
		}
	}
	if opts.SourceVersioningCertificateFile != "" && (!filepath.IsAbs(opts.SourceVersioningCertificateFile) || opts.SourceVersioningCertificateFile == string(filepath.Separator)) {
		return errors.New("source-versioning certificate file must be an absolute file path")
	}
	return nil
}

func readOwnerSecret(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("secret path must be absolute")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o177 != 0 {
		return "", errors.New("secret must be a regular owner-only file")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	openedInfo, statErr := file.Stat()
	if statErr != nil || !openedInfo.Mode().IsRegular() || openedInfo.Mode().Perm()&0o177 != 0 || !os.SameFile(info, openedInfo) {
		_ = file.Close()
		return "", errors.New("secret changed or became unsafe while opening")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, 16*1024+1))
	closeErr := file.Close()
	if readErr != nil {
		return "", readErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if len(data) > 16*1024 {
		return "", errors.New("secret exceeds safety bound")
	}
	value := strings.TrimSpace(string(data))
	if value == "" || strings.ContainsAny(value, "\r\n\x00") {
		return "", errors.New("secret is empty or malformed")
	}
	return value, nil
}
