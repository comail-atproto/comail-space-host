package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/comail-atproto/comail-pds-lab/internal/authvault"
	"github.com/comail-atproto/comail-pds-lab/internal/memory"
	"github.com/comail-atproto/comail-pds-lab/internal/migrate"
	"github.com/comail-atproto/comail-pds-lab/internal/oauthclient"
	"github.com/comail-atproto/comail-pds-lab/internal/projection"
	"github.com/comail-atproto/comail-pds-lab/internal/sqliteimport"
	"github.com/comail-atproto/comail-pds-lab/internal/synthetic"
	"github.com/comail-atproto/comail-pds-lab/internal/vandelayimport"
)

const syntheticDID = "did:plc:comailpdslabsynthetic"

type proofEvidence struct {
	Version    int               `json:"version"`
	Synthetic  bool              `json:"synthetic"`
	Generated  string            `json:"generatedAt"`
	Migration  migrate.Report    `json:"migration"`
	Projection projection.Report `json:"projection"`
	Passed     bool              `json:"passed"`
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
	case "synthetic-proof":
		return runSyntheticProof(ctx, args[1:])
	case "vault-init":
		return runVaultInit(args[1:])
	case "oauth-login":
		return runOAuthLogin(ctx, args[1:])
	case "help", "-h", "--help":
		fmt.Print(usage())
		return nil
	default:
		return usageError()
	}
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
	var completed atomic.Bool
	server := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			if request.Method != http.MethodGet || request.URL.Path != callback.Path {
				http.NotFound(w, request)
				return
			}
			if completed.Load() {
				http.Error(w, "OAuth callback already completed", http.StatusConflict)
				return
			}
			session, finishErr := manager.Finish(request.Context(), request.URL.Query())
			if finishErr != nil {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte("Comail PDS lab rejected this OAuth callback. The listener is still waiting.\n"))
				return
			}
			if !completed.CompareAndSwap(false, true) {
				http.Error(w, "OAuth callback already completed", http.StatusConflict)
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
	return errors.New("expected one of: inspect, dry-run, inspect-vandelay, dry-run-vandelay, prove-vandelay, synthetic-proof, vault-init, oauth-login, help")
}

func usage() string {
	return `Comail permissioned-PDS mailbox lab

Commands:
  inspect          Inventory one exact mailbox in a read-only SQLite snapshot
  dry-run          Produce hashes/counts without any destination writes
  inspect-vandelay Inventory one closed Stalwart/Vandelay account archive
  dry-run-vandelay Validate and hash a Vandelay archive without provider writes
  prove-vandelay   Migrate an archive into memory and rebuild a fresh projection
  synthetic-proof  Migrate synthetic mail and rebuild a fresh SQLite projection
  vault-init       Create an encrypted OAuth session vault and key
  oauth-login      Obtain and encrypt an exact mailbox-space OAuth grant

All source SQLite inputs must be explicit, closed, consistent snapshots. The
rsky certificate applies only to the isolated pinned build plus lab patch.
`
}
