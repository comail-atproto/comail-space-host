package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/comail-atproto/comail-space-host/internal/authoritycert"
	"github.com/comail-atproto/comail-space-host/internal/authvault"
	"github.com/comail-atproto/comail-space-host/internal/memory"
	"github.com/comail-atproto/comail-space-host/internal/migrate"
	"github.com/comail-atproto/comail-space-host/internal/oauthclient"
	"github.com/comail-atproto/comail-space-host/internal/projection"
	"github.com/comail-atproto/comail-space-host/internal/providers/happyview"
	"github.com/comail-atproto/comail-space-host/internal/spacecredential"
	"github.com/comail-atproto/comail-space-host/internal/spaceproof"
	"github.com/comail-atproto/comail-space-host/internal/sqliteimport"
	"github.com/comail-atproto/comail-space-host/internal/synthetic"
	"github.com/comail-atproto/comail-space-host/internal/vandelayimport"
)

const syntheticDID = "did:plc:comailpdslabsynthetic"
const officialPLCOrigin = "https://plc.directory"

const happyViewCertifiedEpoch = happyview.CertifiedEpoch

var errHappyViewWriteConfirmation = errors.New("prove-happyview requires both --provider happyview and --commit")

type proofEvidence struct {
	Version    int               `json:"version"`
	Synthetic  bool              `json:"synthetic"`
	Generated  string            `json:"generatedAt"`
	Migration  migrate.Report    `json:"migration"`
	Projection projection.Report `json:"projection"`
	Passed     bool              `json:"passed"`
}

type oauthCallbackGate struct {
	state atomic.Uint32
}

func (g *oauthCallbackGate) begin() bool {
	return g.state.CompareAndSwap(0, 1)
}

func (g *oauthCallbackGate) finish(err error) {
	if errors.Is(err, oauthclient.ErrInvalidCallback) {
		g.state.CompareAndSwap(1, 0)
		return
	}
	g.state.Store(2)
}

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "comail-pds-lab:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usageError()
	}
	switch args[0] {
	case "inspect":
		return runInspect(ctx, args[1:])
	case "dry-run":
		return runDryRun(ctx, args[1:])
	case "inspect-vandelay":
		return runInspectVandelay(ctx, args[1:])
	case "dry-run-vandelay":
		return runDryRunVandelay(ctx, args[1:])
	case "prove-vandelay":
		return runProveVandelay(ctx, args[1:])
	case "prove-happyview":
		return runProveHappyView(ctx, args[1:])
	case "certify-happyview-authority":
		return runCertifyHappyViewAuthority(ctx, args[1:])
	case "capture-happyview-session":
		return runCaptureHappyViewSession(ctx, args[1:])
	case "synthetic-proof":
		return runSyntheticProof(ctx, args[1:])
	case "vault-init":
		return runVaultInit(args[1:])
	case "oauth-login":
		return runOAuthLogin(ctx, args[1:])
	case "oauth-provision":
		return runOAuthProvision(ctx, args[1:])
	case "oauth-credential-proof":
		return runOAuthCredentialProof(ctx, args[1:])
	case "oauth-revoke":
		return runOAuthRevoke(ctx, args[1:])
	case "help", "-h", "--help":
		fmt.Print(usage())
		return nil
	default:
		return usageError()
	}
}

type happyViewAuthorityOptions struct {
	Provider   string
	Commit     bool
	Origin     string
	BasePath   string
	PublicHost string
	DID        string
	SpaceKey   string
	Epoch      string
	CookieFile string
	WorkDir    string
	RunID      string
}

func validateHappyViewAuthorityOptions(opts happyViewAuthorityOptions) error {
	if opts.Provider != "happyview" || !opts.Commit {
		return errors.New("certify-happyview-authority requires both --provider happyview and --commit")
	}
	if opts.Epoch != happyViewCertifiedEpoch {
		return errors.New("certify-happyview-authority requires the certified HappyView epoch")
	}
	if !strings.HasPrefix(opts.DID, "did:") || strings.ContainsAny(opts.DID, "/?# \t\r\n") {
		return errors.New("certify-happyview-authority requires an exact DID")
	}
	if !strings.HasPrefix(opts.SpaceKey, "comail-cert-") || len(opts.SpaceKey) > 128 || strings.ContainsAny(opts.SpaceKey, "/?# \t\r\n") {
		return errors.New("certify-happyview-authority requires a dedicated comail-cert-* space key")
	}
	origin, err := url.Parse(opts.Origin)
	if err != nil || origin.Scheme != "http" || origin.Hostname() == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || (origin.Path != "" && origin.Path != "/") {
		return errors.New("certify-happyview-authority origin must be a clean loopback HTTP origin")
	}
	if host := origin.Hostname(); !strings.EqualFold(host, "localhost") {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return errors.New("certify-happyview-authority origin must be loopback-only")
		}
	}
	if opts.BasePath == "/" || (opts.BasePath != "" && (!strings.HasPrefix(opts.BasePath, "/") || strings.HasSuffix(opts.BasePath, "/") || strings.Contains(opts.BasePath, ".."))) {
		return errors.New("certify-happyview-authority received an invalid provider base path")
	}
	if opts.BasePath != "" && (opts.PublicHost == "" || strings.ContainsAny(opts.PublicHost, "/ :?#@")) {
		return errors.New("certify-happyview-authority requires an exact provider virtual host")
	}
	for name, path := range map[string]string{"cookie-file": opts.CookieFile, "work-dir": opts.WorkDir} {
		if !filepath.IsAbs(path) || path == string(filepath.Separator) {
			return fmt.Errorf("certify-happyview-authority requires an absolute --%s", name)
		}
	}
	if opts.RunID != "" && (len(opts.RunID) > 96 || strings.ContainsAny(opts.RunID, " \t\r\n\x00")) {
		return errors.New("certify-happyview-authority received an invalid run ID")
	}
	return nil
}

func runCertifyHappyViewAuthority(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("certify-happyview-authority", flag.ContinueOnError)
	opts := happyViewAuthorityOptions{}
	flags.StringVar(&opts.Provider, "provider", "", "must be the literal happyview to confirm the destination")
	flags.BoolVar(&opts.Commit, "commit", false, "write one synthetic message to a dedicated certification space")
	flags.StringVar(&opts.Origin, "origin", "http://127.0.0.1:39090", "exact loopback HappyView origin")
	flags.StringVar(&opts.BasePath, "base-path", "/comail-pds-lab", "provider path prefix")
	flags.StringVar(&opts.PublicHost, "public-host", "little-mac.lobster-hake.ts.net", "provider virtual host")
	flags.StringVar(&opts.DID, "did", "", "exact account DID authenticated in HappyView")
	flags.StringVar(&opts.SpaceKey, "space-key", "", "new dedicated comail-cert-* space key")
	flags.StringVar(&opts.Epoch, "epoch", happyViewCertifiedEpoch, "certified HappyView source commit")
	flags.StringVar(&opts.CookieFile, "cookie-file", "", "absolute owner-only HappyView session cookie file")
	flags.StringVar(&opts.WorkDir, "work-dir", "", "new absolute directory for redacted evidence and disposable projections")
	flags.StringVar(&opts.RunID, "run-id", "", "optional opaque idempotency run ID")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := validateHappyViewAuthorityOptions(opts); err != nil {
		return err
	}
	if opts.RunID == "" {
		random := make([]byte, 18)
		if _, err := rand.Read(random); err != nil {
			return err
		}
		opts.RunID = base64.RawURLEncoding.EncodeToString(random)
	}
	doer, err := happyview.NewSessionDoer(opts.CookieFile)
	if err != nil {
		return err
	}
	var providerDoer happyview.Doer = doer
	if opts.BasePath != "" {
		providerDoer = &happyViewVirtualHostDoer{inner: doer, basePath: opts.BasePath, publicHost: opts.PublicHost}
	}
	repo, err := happyview.New(happyview.Config{
		Origin: opts.Origin, DID: opts.DID, Epoch: opts.Epoch, AllowHTTP: true, AllowWrites: true,
	}, providerDoer)
	if err != nil {
		return err
	}
	report, err := authoritycert.Run(ctx, repo, authoritycert.Options{
		RecipientDID: opts.DID, SpaceKey: opts.SpaceKey, RunID: opts.RunID, WorkDir: opts.WorkDir, Now: time.Now().UTC(),
	})
	if err != nil {
		return err
	}
	if err := writeExclusiveJSON(filepath.Join(opts.WorkDir, "evidence.json"), report); err != nil {
		return err
	}
	if !report.Passed {
		return errors.New("HappyView authority certification did not pass")
	}
	return printJSON(report)
}

type happyViewVirtualHostDoer struct {
	inner      happyview.Doer
	basePath   string
	publicHost string
}

func (d *happyViewVirtualHostDoer) Do(ctx context.Context, request *http.Request, endpoint string) (*http.Response, error) {
	clone := request.Clone(ctx)
	clone.URL.Path = d.basePath + request.URL.Path
	clone.Host = d.publicHost
	clone.Header = request.Header.Clone()
	return d.inner.Do(ctx, clone, endpoint)
}

func happyViewCaptureHandler(nonce, output string, result chan<- error) http.Handler {
	var completed atomic.Bool
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if request.Method != http.MethodGet || request.URL.Path != "/capture/"+nonce {
			http.NotFound(response, request)
			return
		}
		if !completed.CompareAndSwap(false, true) {
			http.Error(response, "Session capture already completed.", http.StatusConflict)
			return
		}
		cookie, err := request.Cookie("happyview_session")
		if err != nil || cookie.Value == "" || len(cookie.Value) > 16*1024 || strings.ContainsAny(cookie.Value, ";\r\n\x00") {
			http.Error(response, "No valid local HappyView session was present. Log in first, then retry the capture command.", http.StatusUnauthorized)
			result <- errors.New("capture-happyview-session did not receive a valid HappyView cookie")
			return
		}
		err = writeExclusiveSecret(output, []byte("happyview_session="+cookie.Value+"\n"))
		if err != nil {
			http.Error(response, "The session could not be stored.", http.StatusInternalServerError)
			result <- err
			return
		}
		_, _ = response.Write([]byte("Comail PDS lab captured the local HappyView session. You may close this tab.\n"))
		result <- nil
	})
}

func runCaptureHappyViewSession(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("capture-happyview-session", flag.ContinueOnError)
	output := flags.String("out", "", "new absolute owner-only session file")
	listen := flags.String("listen", "127.0.0.1:39091", "exact IPv4 loopback listener")
	timeout := flags.Duration("timeout", 5*time.Minute, "maximum time to wait for the browser")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if !filepath.IsAbs(*output) || *output == string(filepath.Separator) {
		return errors.New("capture-happyview-session requires an absolute --out")
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil || host != "127.0.0.1" {
		return errors.New("capture-happyview-session listener must use exact IPv4 loopback")
	}
	parent := filepath.Dir(*output)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("capture-happyview-session output directory must be owner-only")
	}
	if _, err := os.Lstat(*output); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errors.New("capture-happyview-session refuses to overwrite its output")
	}
	nonceBytes := make([]byte, 24)
	if _, err := rand.Read(nonceBytes); err != nil {
		return err
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return fmt.Errorf("listen for HappyView session capture: %w", err)
	}
	defer listener.Close()
	result := make(chan error, 1)
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: happyViewCaptureHandler(nonce, *output, result)}
	serveErr := make(chan error, 1)
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
	}()
	if err := printJSON(map[string]any{
		"version":    1,
		"captureUrl": "http://" + *listen + "/capture/" + nonce,
		"next":       "While logged into HappyView on 127.0.0.1, open this one-use URL in the same browser.",
	}); err != nil {
		_ = server.Close()
		return err
	}
	waitCtx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	select {
	case err := <-result:
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer shutdownCancel()
		_ = server.Shutdown(shutdownCtx)
		if err != nil {
			return err
		}
		return printJSON(map[string]any{"version": 1, "captured": true, "path": *output})
	case err := <-serveErr:
		return err
	case <-waitCtx.Done():
		_ = server.Close()
		return fmt.Errorf("HappyView session capture wait ended: %w", waitCtx.Err())
	}
}

func writeExclusiveSecret(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

type happyViewProofOptions struct {
	Provider   string
	Commit     bool
	Archive    string
	Snapshot   string
	Origin     string
	DID        string
	SpaceKey   string
	Epoch      string
	CookieFile string
	WorkDir    string
}

func validateHappyViewProofOptions(opts happyViewProofOptions) error {
	if opts.Provider != "happyview" || !opts.Commit {
		return errHappyViewWriteConfirmation
	}
	if opts.Epoch != happyViewCertifiedEpoch {
		return errors.New("prove-happyview requires the certified HappyView epoch")
	}
	if (opts.Archive == "") == (opts.Snapshot == "") {
		return errors.New("prove-happyview requires exactly one closed --archive or --snapshot")
	}
	if !strings.HasPrefix(opts.DID, "did:") || strings.ContainsAny(opts.DID, "/?#") || opts.SpaceKey == "" {
		return errors.New("prove-happyview requires an exact DID and space key")
	}
	origin, err := url.Parse(opts.Origin)
	if err != nil || origin.Scheme != "http" || origin.Hostname() == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || (origin.Path != "" && origin.Path != "/") {
		return errors.New("prove-happyview origin must be a clean loopback HTTP origin")
	}
	host := origin.Hostname()
	if !strings.EqualFold(host, "localhost") {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return errors.New("prove-happyview origin must be loopback-only")
		}
	}
	sourceName, sourcePath := "archive", opts.Archive
	if opts.Snapshot != "" {
		sourceName, sourcePath = "snapshot", opts.Snapshot
	}
	for name, path := range map[string]string{sourceName: sourcePath, "cookie-file": opts.CookieFile, "work-dir": opts.WorkDir} {
		if !filepath.IsAbs(path) || path == string(filepath.Separator) {
			return fmt.Errorf("prove-happyview requires an absolute --%s", name)
		}
	}
	return nil
}

func runProveHappyView(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("prove-happyview", flag.ContinueOnError)
	opts := happyViewProofOptions{}
	flags.StringVar(&opts.Provider, "provider", "", "must be the literal happyview to confirm the destination")
	flags.BoolVar(&opts.Commit, "commit", false, "perform provider writes after all target checks")
	flags.StringVar(&opts.Archive, "archive", "", "absolute path to a closed Vandelay archive")
	flags.StringVar(&opts.Snapshot, "snapshot", "", "absolute path to a closed legacy inboxd SQLite snapshot")
	flags.StringVar(&opts.Origin, "origin", "http://127.0.0.1:39090", "exact loopback HappyView origin")
	flags.StringVar(&opts.DID, "did", "", "exact mailbox DID authenticated in HappyView")
	flags.StringVar(&opts.SpaceKey, "space-key", "primary", "exact mailbox space key")
	flags.StringVar(&opts.Epoch, "epoch", happyViewCertifiedEpoch, "certified HappyView source commit")
	flags.StringVar(&opts.CookieFile, "cookie-file", "", "absolute owner-only HappyView session cookie file")
	flags.StringVar(&opts.WorkDir, "work-dir", "", "new absolute directory for proof artifacts")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := validateHappyViewProofOptions(opts); err != nil {
		return err
	}
	doer, err := happyview.NewSessionDoer(opts.CookieFile)
	if err != nil {
		return err
	}
	repo, err := happyview.New(happyview.Config{
		Origin: opts.Origin, DID: opts.DID, Epoch: opts.Epoch,
		AllowHTTP: true, AllowWrites: true,
	}, doer)
	if err != nil {
		return err
	}
	if err := os.Mkdir(opts.WorkDir, 0o700); err != nil {
		return fmt.Errorf("create proof directory: %w", err)
	}
	var snapshot migrate.SourceSnapshot
	var closeSnapshot func() error
	if opts.Snapshot != "" {
		legacySnapshot, openErr := sqliteimport.Open(opts.Snapshot)
		if openErr != nil {
			return openErr
		}
		snapshot = legacySnapshot
		closeSnapshot = legacySnapshot.Close
	} else {
		archiveSnapshot, openErr := vandelayimport.Open(opts.Archive)
		if openErr != nil {
			return openErr
		}
		snapshot = archiveSnapshot
		closeSnapshot = archiveSnapshot.Close
	}
	defer closeSnapshot()
	migration, err := migrate.Run(ctx, snapshot, repo, migrate.Options{RecipientDID: opts.DID, SpaceKey: opts.SpaceKey, Commit: true})
	if err != nil {
		return err
	}
	projectionReport, err := projection.Rebuild(ctx, repo, migration.Target, filepath.Join(opts.WorkDir, "rebuilt-projection.sqlite"))
	if err != nil {
		return err
	}
	evidence := proofEvidence{
		Version: 1, Synthetic: false, Generated: time.Now().UTC().Format(time.RFC3339),
		Migration: migration, Projection: projectionReport,
		Passed: migration.Verification.Passed() && projectionReport.Passed(),
	}
	if err := writeExclusiveJSON(filepath.Join(opts.WorkDir, "evidence.json"), evidence); err != nil {
		return err
	}
	if !evidence.Passed {
		return errors.New("HappyView authority proof did not pass")
	}
	return printJSON(evidence)
}

func runProveVandelay(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("prove-vandelay", flag.ContinueOnError)
	archivePath := flags.String("archive", "", "absolute path to a closed Vandelay archive")
	did := flags.String("did", "", "exact mailbox DID")
	spaceKey := flags.String("space-key", "primary", "exact mailbox space key")
	workDir := flags.String("work-dir", "", "new absolute directory for proof artifacts")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if !filepath.IsAbs(*workDir) || *workDir == string(filepath.Separator) {
		return errors.New("prove-vandelay requires a new absolute --work-dir")
	}
	if err := os.Mkdir(*workDir, 0o700); err != nil {
		return fmt.Errorf("create proof directory: %w", err)
	}
	snapshot, err := vandelayimport.Open(*archivePath)
	if err != nil {
		return err
	}
	defer snapshot.Close()
	repo := memory.NewBackend().OwnerSession(*did)
	migration, err := migrate.Run(ctx, snapshot, repo, migrate.Options{RecipientDID: *did, SpaceKey: *spaceKey, Commit: true})
	if err != nil {
		return err
	}
	projectionReport, err := projection.Rebuild(ctx, repo, migration.Target, filepath.Join(*workDir, "rebuilt-projection.sqlite"))
	if err != nil {
		return err
	}
	evidence := proofEvidence{Version: 1, Synthetic: false, Generated: time.Now().UTC().Format(time.RFC3339), Migration: migration, Projection: projectionReport, Passed: migration.Verification.Passed() && projectionReport.Passed()}
	if err := writeExclusiveJSON(filepath.Join(*workDir, "evidence.json"), evidence); err != nil {
		return err
	}
	if !evidence.Passed {
		return errors.New("Vandelay proof did not pass")
	}
	return printJSON(evidence)
}

func runInspectVandelay(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("inspect-vandelay", flag.ContinueOnError)
	archivePath := flags.String("archive", "", "absolute path to a closed Vandelay archive")
	did := flags.String("did", "", "exact mailbox DID")
	spaceKey := flags.String("space-key", "primary", "exact mailbox space key")
	if err := flags.Parse(args); err != nil {
		return err
	}
	snapshot, err := vandelayimport.Open(*archivePath)
	if err != nil {
		return err
	}
	defer snapshot.Close()
	inventory, err := snapshot.Inspect(ctx, *did, *spaceKey)
	if err != nil {
		return err
	}
	return printJSON(inventory)
}

func runDryRunVandelay(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("dry-run-vandelay", flag.ContinueOnError)
	archivePath := flags.String("archive", "", "absolute path to a closed Vandelay archive")
	did := flags.String("did", "", "exact mailbox DID")
	spaceKey := flags.String("space-key", "primary", "exact mailbox space key")
	evidence := flags.String("evidence", "", "create-only path for redacted JSON evidence")
	if err := flags.Parse(args); err != nil {
		return err
	}
	snapshot, err := vandelayimport.Open(*archivePath)
	if err != nil {
		return err
	}
	defer snapshot.Close()
	repo := memory.NewBackend().OwnerSession(*did)
	report, err := migrate.Run(ctx, snapshot, repo, migrate.Options{RecipientDID: *did, SpaceKey: *spaceKey})
	if err != nil {
		return err
	}
	if *evidence != "" {
		if err := migrate.WriteReport(*evidence, report); err != nil {
			return err
		}
	}
	return printJSON(report)
}

func runInspect(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("inspect", flag.ContinueOnError)
	snapshotPath := flags.String("snapshot", "", "absolute path to a consistent SQLite snapshot")
	did := flags.String("did", "", "exact mailbox DID")
	spaceKey := flags.String("space-key", "primary", "exact mailbox space key")
	if err := flags.Parse(args); err != nil {
		return err
	}
	snapshot, err := sqliteimport.Open(*snapshotPath)
	if err != nil {
		return err
	}
	defer snapshot.Close()
	inventory, err := snapshot.Inspect(ctx, *did, *spaceKey)
	if err != nil {
		return err
	}
	return printJSON(inventory)
}

func runDryRun(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("dry-run", flag.ContinueOnError)
	snapshotPath := flags.String("snapshot", "", "absolute path to a consistent SQLite snapshot")
	did := flags.String("did", "", "exact mailbox DID")
	spaceKey := flags.String("space-key", "primary", "exact mailbox space key")
	evidence := flags.String("evidence", "", "create-only path for redacted JSON evidence")
	if err := flags.Parse(args); err != nil {
		return err
	}
	snapshot, err := sqliteimport.Open(*snapshotPath)
	if err != nil {
		return err
	}
	defer snapshot.Close()
	repo := memory.NewBackend().OwnerSession(*did)
	report, err := migrate.Run(ctx, snapshot, repo, migrate.Options{RecipientDID: *did, SpaceKey: *spaceKey})
	if err != nil {
		return err
	}
	if *evidence != "" {
		if err := migrate.WriteReport(*evidence, report); err != nil {
			return err
		}
	}
	return printJSON(report)
}

func runSyntheticProof(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("synthetic-proof", flag.ContinueOnError)
	workDir := flags.String("work-dir", "", "new absolute directory for disposable proof artifacts")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if !filepath.IsAbs(*workDir) || *workDir == string(filepath.Separator) {
		return errors.New("synthetic-proof requires a new absolute --work-dir")
	}
	if err := os.Mkdir(*workDir, 0o700); err != nil {
		return fmt.Errorf("create proof directory: %w", err)
	}
	snapshotPath := filepath.Join(*workDir, "synthetic-source.sqlite")
	if err := synthetic.CreateSnapshot(snapshotPath, syntheticDID, "primary"); err != nil {
		return err
	}
	snapshot, err := sqliteimport.Open(snapshotPath)
	if err != nil {
		return err
	}
	defer snapshot.Close()
	repo := memory.NewBackend().OwnerSession(syntheticDID)
	migration, err := migrate.Run(ctx, snapshot, repo, migrate.Options{RecipientDID: syntheticDID, SpaceKey: "primary", Commit: true})
	if err != nil {
		return err
	}
	projectionReport, err := projection.Rebuild(ctx, repo, migration.Target, filepath.Join(*workDir, "rebuilt-projection.sqlite"))
	if err != nil {
		return err
	}
	evidence := proofEvidence{
		Version: 1, Synthetic: true, Generated: time.Now().UTC().Format(time.RFC3339),
		Migration: migration, Projection: projectionReport,
		Passed: migration.Verification.Passed() && projectionReport.Passed(),
	}
	if err := writeExclusiveJSON(filepath.Join(*workDir, "evidence.json"), evidence); err != nil {
		return err
	}
	if !evidence.Passed {
		return errors.New("synthetic proof did not pass")
	}
	return printJSON(evidence)
}

func runVaultInit(args []string) error {
	flags := flag.NewFlagSet("vault-init", flag.ContinueOnError)
	vaultPath := flags.String("vault", "", "absolute encrypted vault path")
	keyPath := flags.String("key", "", "absolute vault key path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	_, err := authvault.Create(*vaultPath, *keyPath)
	if err != nil {
		return err
	}
	return printJSON(map[string]any{"version": 1, "initialized": true})
}

func runOAuthLogin(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("oauth-login", flag.ContinueOnError)
	vaultPath := flags.String("vault", "", "absolute encrypted vault path")
	keyPath := flags.String("key", "", "absolute vault key path")
	did := flags.String("did", "", "exact account DID")
	handle := flags.String("handle", "", "exact account handle")
	origin := flags.String("origin", "", "exact rsky PDS HTTPS origin")
	spaceKey := flags.String("space-key", "primary", "exact mailbox space key")
	callbackURL := flags.String("callback-url", "http://127.0.0.1:49153/oauth/callback", "exact loopback OAuth callback")
	timeout := flags.Duration("timeout", 5*time.Minute, "maximum time to wait for browser callback")
	if err := flags.Parse(args); err != nil {
		return err
	}
	vault, err := authvault.Open(*vaultPath, *keyPath)
	if err != nil {
		return err
	}
	manager, err := oauthclient.New(oauthclient.Config{
		DID: *did, Handle: *handle, Origin: *origin, CallbackURL: *callbackURL, SpaceKey: *spaceKey,
	}, vault)
	if err != nil {
		return err
	}
	callback, err := url.Parse(*callbackURL)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", callback.Host)
	if err != nil {
		return fmt.Errorf("listen for OAuth callback: %w", err)
	}
	defer listener.Close()
	type loginResult struct {
		sessionID string
		err       error
	}
	result := make(chan loginResult, 1)
	var callbackGate oauthCallbackGate
	server := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			if request.Method != http.MethodGet || request.URL.Path != callback.Path {
				http.NotFound(w, request)
				return
			}
			if !callbackGate.begin() {
				http.Error(w, "OAuth callback already completed", http.StatusConflict)
				return
			}
			session, finishErr := manager.Finish(request.Context(), request.URL.Query())
			callbackGate.finish(finishErr)
			if finishErr != nil {
				w.WriteHeader(http.StatusBadRequest)
				if errors.Is(finishErr, oauthclient.ErrInvalidCallback) {
					_, _ = w.Write([]byte("Comail PDS lab rejected an invalid OAuth callback. The listener is still waiting.\n"))
					return
				}
				_, _ = w.Write([]byte("Comail PDS lab rejected this OAuth session. You may close this tab.\n"))
				result <- loginResult{err: finishErr}
				return
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte("Comail PDS lab OAuth complete. You may close this tab.\n"))
			result <- loginResult{sessionID: session.Data.SessionID}
		}),
	}
	serveErr := make(chan error, 1)
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
	}()
	authorizeURL, err := manager.Start(ctx)
	if err != nil {
		_ = server.Close()
		return err
	}
	if err := printJSON(map[string]any{
		"version": 1, "authorizationUrl": authorizeURL,
		"next": "Open this URL in a browser and approve the exact mailbox-space grant.",
	}); err != nil {
		_ = server.Close()
		return err
	}
	waitCtx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	select {
	case got := <-result:
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer shutdownCancel()
		_ = server.Shutdown(shutdownCtx)
		if got.err != nil {
			return got.err
		}
		return printJSON(map[string]any{"version": 1, "authenticated": true, "did": *did, "sessionId": got.sessionID})
	case err := <-serveErr:
		return err
	case <-waitCtx.Done():
		_ = server.Close()
		return fmt.Errorf("OAuth callback wait ended: %w", waitCtx.Err())
	}
}

func runOAuthProvision(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("oauth-provision", flag.ContinueOnError)
	vaultPath := flags.String("vault", "", "absolute encrypted vault path")
	keyPath := flags.String("key", "", "absolute vault key path")
	did := flags.String("did", "", "exact account DID")
	handle := flags.String("handle", "", "exact account handle")
	origin := flags.String("origin", "", "exact Spaces PDS HTTPS origin")
	spaceKey := flags.String("space-key", "primary", "exact mailbox space key")
	callbackURL := flags.String("callback-url", "http://127.0.0.1:49153/oauth/callback", "exact loopback OAuth callback")
	timeout := flags.Duration("timeout", 5*time.Minute, "maximum time to wait for browser callback")
	if err := flags.Parse(args); err != nil {
		return err
	}
	vault, err := authvault.Open(*vaultPath, *keyPath)
	if err != nil {
		return err
	}
	provisioner, err := oauthclient.NewProvisioner(oauthclient.Config{
		DID: *did, Handle: *handle, Origin: *origin, CallbackURL: *callbackURL, SpaceKey: *spaceKey,
	}, vault)
	if err != nil {
		return err
	}
	callback, err := url.Parse(*callbackURL)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", callback.Host)
	if err != nil {
		return fmt.Errorf("listen for OAuth callback: %w", err)
	}
	defer listener.Close()
	type provisionResult struct {
		spaceURI string
		created  bool
		err      error
	}
	result := make(chan provisionResult, 1)
	var callbackGate oauthCallbackGate
	server := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			if request.Method != http.MethodGet || request.URL.Path != callback.Path {
				http.NotFound(w, request)
				return
			}
			if !callbackGate.begin() {
				http.Error(w, "OAuth callback already completed", http.StatusConflict)
				return
			}
			provisioned, finishErr := provisioner.Finish(request.Context(), request.URL.Query())
			callbackGate.finish(finishErr)
			if finishErr != nil {
				w.WriteHeader(http.StatusBadRequest)
				if errors.Is(finishErr, oauthclient.ErrInvalidCallback) {
					_, _ = w.Write([]byte("Comail rejected an invalid OAuth callback. The listener is still waiting.\n"))
					return
				}
				_, _ = w.Write([]byte("Comail rejected provisioning and attempted one-time OAuth cleanup. You may close this tab.\n"))
				result <- provisionResult{err: finishErr}
				return
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte("Comail mailbox space provisioned and one-time OAuth cleaned up. You may close this tab.\n"))
			result <- provisionResult{spaceURI: provisioned.SpaceURI, created: provisioned.Created}
		}),
	}
	serveErr := make(chan error, 1)
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
	}()
	authorizeURL, err := provisioner.Start(ctx)
	if err != nil {
		_ = server.Close()
		return err
	}
	if err := printJSON(map[string]any{
		"version": 1, "authorizationUrl": authorizeURL,
		"next": "Open this URL in a browser and approve the exact one-time mailbox-space creation grant.",
	}); err != nil {
		_ = server.Close()
		return err
	}
	waitCtx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	select {
	case got := <-result:
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer shutdownCancel()
		_ = server.Shutdown(shutdownCtx)
		if got.err != nil {
			return got.err
		}
		return printJSON(map[string]any{
			"version": 1, "provisioned": true, "did": *did, "spaceUri": got.spaceURI,
			"created": got.created, "oneTimeSessionRevokedAndDeleted": true,
		})
	case err := <-serveErr:
		return err
	case <-waitCtx.Done():
		_ = server.Close()
		return fmt.Errorf("OAuth callback wait ended: %w", waitCtx.Err())
	}
}

func runOAuthCredentialProof(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("oauth-credential-proof", flag.ContinueOnError)
	vaultPath := flags.String("vault", "", "absolute encrypted vault path")
	keyPath := flags.String("key", "", "absolute vault key path")
	did := flags.String("did", "", "exact account DID")
	handle := flags.String("handle", "", "exact account handle")
	origin := flags.String("origin", "", "exact Spaces PDS HTTPS origin")
	spaceKey := flags.String("space-key", "primary", "exact mailbox space key")
	sessionID := flags.String("session-id", "", "encrypted steady OAuth session ID")
	callbackURL := flags.String("callback-url", "http://127.0.0.1:49153/oauth/callback", "exact loopback OAuth callback used for the session")
	timeout := flags.Duration("timeout", time.Minute, "maximum credential proof duration")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := validateCredentialProofInputs(*sessionID, *timeout); err != nil {
		return err
	}
	vault, err := authvault.Open(*vaultPath, *keyPath)
	if err != nil {
		return err
	}
	manager, err := oauthclient.New(oauthclient.Config{
		DID: *did, Handle: *handle, Origin: *origin, CallbackURL: *callbackURL, SpaceKey: *spaceKey,
	}, vault)
	if err != nil {
		return err
	}
	proofCtx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	session, err := manager.Resume(proofCtx, *sessionID)
	if err != nil {
		return err
	}
	delegations, err := manager.Doer(session)
	if err != nil {
		return err
	}
	resolver, err := spacecredential.NewPLCSigningKeyResolver(officialPLCOrigin, false)
	if err != nil {
		return err
	}
	spaceURI := "at://" + *did + "/space/email.atmos.mailbox/" + *spaceKey
	exchanger, err := spacecredential.New(spacecredential.Config{
		SpaceURI: spaceURI, SpaceHostOrigin: *origin, SigningKeys: resolver,
		AppAccess: spacecredential.AppAccessOpen,
	})
	if err != nil {
		return err
	}
	credential, err := exchanger.Acquire(proofCtx, delegations)
	if err != nil {
		return err
	}
	defer credential.Close()
	reader, err := spaceproof.New(spaceproof.Config{Origin: *origin, DID: *did, SpaceKey: *spaceKey}, credential)
	if err != nil {
		return err
	}
	readProof, err := reader.ProveRead(proofCtx)
	if err != nil {
		return err
	}
	return printJSON(map[string]any{
		"version": 1, "profile": "official-alpha-sole-host-open-app", "readOnly": true,
		"activationAttempted": false, "did": *did, "origin": *origin, "spaceUri": spaceURI,
		"steadyGrantValidated": true, "delegationExchanged": true,
		"credentialSignatureAndBindingVerified": true, "dpopReadVerified": true,
		"repoState": readProof.RepoState, "recordMetadataPresent": readProof.RecordMetadataPresent,
		"expiresAt":    credential.ExpiresAt().Format(time.RFC3339),
		"needsRenewal": credential.NeedsRenewal(time.Now()),
	})
}

func validateCredentialProofInputs(sessionID string, timeout time.Duration) error {
	if sessionID == "" || len(sessionID) > 1024 || strings.ContainsAny(sessionID, " \t\r\n\x00") {
		return errors.New("oauth-credential-proof requires one bounded opaque session ID")
	}
	if timeout <= 0 || timeout > 5*time.Minute {
		return errors.New("oauth-credential-proof timeout must be positive and no more than five minutes")
	}
	return nil
}

func runOAuthRevoke(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("oauth-revoke", flag.ContinueOnError)
	vaultPath := flags.String("vault", "", "absolute encrypted vault path")
	keyPath := flags.String("key", "", "absolute vault key path")
	did := flags.String("did", "", "exact account DID")
	handle := flags.String("handle", "", "exact account handle")
	origin := flags.String("origin", "", "exact Spaces PDS HTTPS origin")
	spaceKey := flags.String("space-key", "primary", "exact mailbox space key")
	sessionID := flags.String("session-id", "", "encrypted steady OAuth session ID")
	callbackURL := flags.String("callback-url", "http://127.0.0.1:49153/oauth/callback", "exact loopback OAuth callback used for the session")
	timeout := flags.Duration("timeout", time.Minute, "maximum revocation duration")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := validateOAuthRevokeInputs(*sessionID, *timeout); err != nil {
		return err
	}
	vault, err := authvault.Open(*vaultPath, *keyPath)
	if err != nil {
		return err
	}
	manager, err := oauthclient.New(oauthclient.Config{
		DID: *did, Handle: *handle, Origin: *origin, CallbackURL: *callbackURL, SpaceKey: *spaceKey,
	}, vault)
	if err != nil {
		return err
	}
	revokeCtx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	if err := manager.RevokeAndDelete(revokeCtx, *sessionID); err != nil {
		return err
	}
	return printJSON(map[string]any{
		"version": 1, "remoteTokensRevoked": true, "encryptedLocalSessionDeleted": true,
		"activationAttempted": false,
	})
}

func validateOAuthRevokeInputs(sessionID string, timeout time.Duration) error {
	if sessionID == "" || len(sessionID) > 1024 || strings.ContainsAny(sessionID, " \t\r\n\x00") {
		return errors.New("oauth-revoke requires one bounded opaque session ID")
	}
	if timeout <= 0 || timeout > 5*time.Minute {
		return errors.New("oauth-revoke timeout must be positive and no more than five minutes")
	}
	return nil
}

func writeExclusiveJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func printJSON(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func usageError() error {
	return errors.New("expected one of: inspect, dry-run, inspect-vandelay, dry-run-vandelay, prove-vandelay, prove-happyview, certify-happyview-authority, capture-happyview-session, synthetic-proof, vault-init, oauth-login, oauth-provision, oauth-credential-proof, oauth-revoke, help")
}

func usage() string {
	return `Comail permissioned-PDS mailbox lab

Commands:
  inspect          Inventory one exact mailbox in a read-only SQLite snapshot
  dry-run          Produce hashes/counts without any destination writes
  inspect-vandelay Inventory one closed Stalwart/Vandelay account archive
  dry-run-vandelay Validate and hash a Vandelay archive without provider writes
  prove-vandelay   Migrate an archive into memory and rebuild a fresh projection
  prove-happyview  Write a Vandelay archive to a pinned local HappyView space
  certify-happyview-authority
                    Prove state CAS, rebuild, and deletion in a fresh lab space
  capture-happyview-session
                    Store the local browser's signed session in an owner-only file
  synthetic-proof  Migrate synthetic mail and rebuild a fresh SQLite projection
  vault-init       Create an encrypted OAuth session vault and key
  oauth-login      Obtain and encrypt an exact mailbox-space OAuth grant
  oauth-provision  Create/verify one exact space with a one-time OAuth grant
  oauth-credential-proof
                    Verify delegation and a fresh DPoP-bound space credential
  oauth-revoke     Confirm remote steady-token revocation, then delete local state

All source SQLite inputs must be explicit, closed, consistent snapshots. The
rsky certificate applies only to the isolated pinned build plus lab patch.
`
}
