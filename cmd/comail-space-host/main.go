package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/comail-atproto/comail-space-host/internal/authoritycert"
	"github.com/comail-atproto/comail-space-host/internal/providers/happyview"
	"github.com/comail-atproto/comail-space-host/internal/serviceauth"
	"github.com/comail-atproto/comail-space-host/internal/shadowagent"
)

type mailboxConfig struct {
	DID                        string `json:"did"`
	SpaceKey                   string `json:"spaceKey"`
	AuthorityCertificateSHA256 string `json:"authorityCertificateSha256"`
	EvidenceFile               string `json:"evidenceFile"`
}

type config struct {
	Listen           string          `json:"listen"`
	ProviderOrigin   string          `json:"providerOrigin"`
	ServiceIssuerDID string          `json:"serviceIssuerDid"`
	ServiceAudience  string          `json:"serviceAudience"`
	ServiceKeyFile   string          `json:"serviceKeyFile"`
	RelayTokenFile   string          `json:"relayTokenFile"`
	Mailboxes        []mailboxConfig `json:"mailboxes"`
	ShutdownSeconds  int             `json:"shutdownSeconds,omitempty"`
}

func main() {
	configPath := flag.String("config", "", "absolute path to the production space-host config")
	identityOnly := flag.Bool("identity-only", false, "write only the public did:web document to stdout")
	identityIssuer := flag.String("identity-issuer", "", "exact did:web issuer for identity-only mode")
	identityKey := flag.String("identity-key", "", "absolute P-256 PKCS#8 key path for identity-only mode")
	flag.Parse()
	if *identityOnly {
		if err := writeIdentityDocument(os.Stdout, *identityIssuer, *identityKey); err != nil {
			fmt.Fprintln(os.Stderr, "comail-space-host:", err)
			os.Exit(1)
		}
		return
	}
	if !filepath.IsAbs(*configPath) {
		fmt.Fprintln(os.Stderr, "comail-space-host: --config must be absolute")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, *configPath); err != nil {
		fmt.Fprintln(os.Stderr, "comail-space-host:", err)
		os.Exit(1)
	}
}

func writeIdentityDocument(output io.Writer, issuerDID, keyPath string) error {
	if output == nil || !strings.HasPrefix(issuerDID, "did:web:") || !safeAbsoluteFile(keyPath) {
		return errors.New("identity-only mode requires an exact did:web issuer and absolute key path")
	}
	key, err := serviceauth.LoadPrivateKey(keyPath)
	if err != nil {
		return fmt.Errorf("load identity signing key: %w", err)
	}
	signer, err := serviceauth.New(serviceauth.Config{IssuerDID: issuerDID, Audience: issuerDID + "#self", Key: key})
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(signer.DIDDocument())
}

func run(ctx context.Context, path string) error {
	configured, err := loadConfig(path)
	if err != nil {
		return err
	}
	key, err := serviceauth.LoadPrivateKey(configured.ServiceKeyFile)
	if err != nil {
		return fmt.Errorf("load service signing key: %w", err)
	}
	signer, err := serviceauth.New(serviceauth.Config{
		IssuerDID: configured.ServiceIssuerDID, Audience: configured.ServiceAudience, Key: key,
	})
	if err != nil {
		return err
	}
	relayToken, err := readOwnerSecret(configured.RelayTokenFile)
	if err != nil {
		return fmt.Errorf("load relay token: %w", err)
	}

	handlers := make([]*shadowagent.Handler, 0, len(configured.Mailboxes))
	for _, mailboxConfig := range configured.Mailboxes {
		repo, err := happyview.New(happyview.Config{
			Origin: configured.ProviderOrigin, DID: mailboxConfig.DID, Epoch: happyview.CertifiedEpoch, AllowWrites: true,
		}, signer)
		if err != nil {
			return fmt.Errorf("construct mailbox provider: %w", err)
		}
		target, err := repo.OpenMailbox(ctx, mailboxConfig.DID, mailboxConfig.SpaceKey)
		if err != nil {
			return fmt.Errorf("verify configured private mailbox: %w", err)
		}
		digest, err := authoritycert.LoadEvidence(mailboxConfig.EvidenceFile, repo.ProviderID(), target)
		if err != nil || digest != mailboxConfig.AuthorityCertificateSHA256 {
			return fmt.Errorf("verify mailbox authority certificate: %w", errors.Join(err, errors.New("configured digest mismatch")))
		}
		handler, err := shadowagent.NewHandler(shadowagent.Config{
			Token: relayToken, DID: mailboxConfig.DID, Target: target, Repository: repo,
			AuthorityCertificateSHA256: digest, SourceVersioningCertified: true,
		})
		if err != nil {
			return err
		}
		handlers = append(handlers, handler)
	}
	mux, err := shadowagent.NewMultiplexer(handlers...)
	if err != nil {
		return err
	}
	root := http.NewServeMux()
	root.HandleFunc("GET /.well-known/did.json", func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Cache-Control", "public, max-age=300")
		response.Header().Set("Content-Type", "application/did+json")
		response.Header().Set("X-Content-Type-Options", "nosniff")
		_ = json.NewEncoder(response).Encode(signer.DIDDocument())
	})
	root.HandleFunc("GET /healthz", func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(response, `{"ok":true}`)
	})
	root.Handle("/", mux)
	listener, err := net.Listen("tcp4", configured.Listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer listener.Close()
	server := &http.Server{
		Handler: root, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 45 * time.Second,
		WriteTimeout: 45 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 * 1024,
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(listener) }()
	fmt.Printf("Comail space host ready: mailboxes=%d provider=%s\n", len(configured.Mailboxes), happyview.CertifiedEpoch)
	select {
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), time.Duration(configured.ShutdownSeconds)*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	}
}

func loadConfig(path string) (config, error) {
	if !filepath.IsAbs(path) || path == string(filepath.Separator) {
		return config{}, errors.New("config path must be absolute")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return config{}, err
	}
	if len(data) == 0 || len(data) > 64*1024 {
		return config{}, errors.New("config size is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var configured config
	if err := decoder.Decode(&configured); err != nil {
		return config{}, errors.New("config JSON is invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return config{}, errors.New("config contains trailing data")
	}
	if configured.ShutdownSeconds == 0 {
		configured.ShutdownSeconds = 10
	}
	if err := validateConfig(configured); err != nil {
		return config{}, err
	}
	return configured, nil
}

func validateConfig(configured config) error {
	host, port, err := net.SplitHostPort(configured.Listen)
	if err != nil || host != "127.0.0.1" || port == "" {
		return errors.New("listener must use exact IPv4 loopback")
	}
	origin, err := url.Parse(configured.ProviderOrigin)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.RawPath != "" ||
		origin.RawQuery != "" || origin.Fragment != "" || origin.Path == "/" ||
		(origin.Path != "" && (path.Clean(origin.Path) != origin.Path || strings.HasSuffix(origin.Path, "/"))) {
		return errors.New("provider origin must be an exact HTTPS base URL")
	}
	if !strings.HasPrefix(configured.ServiceIssuerDID, "did:web:") || !strings.HasPrefix(configured.ServiceAudience, "did:web:") || !strings.Contains(configured.ServiceAudience, "#") {
		return errors.New("service issuer and audience must be exact did:web identifiers")
	}
	if !safeAbsoluteFile(configured.ServiceKeyFile) || !safeAbsoluteFile(configured.RelayTokenFile) || configured.ServiceKeyFile == configured.RelayTokenFile {
		return errors.New("separate absolute service key and relay token files are required")
	}
	if len(configured.Mailboxes) == 0 || len(configured.Mailboxes) > 100 || configured.ShutdownSeconds < 1 || configured.ShutdownSeconds > 60 {
		return errors.New("mailbox count or shutdown timeout is outside its safety bound")
	}
	seenDID := make(map[string]struct{}, len(configured.Mailboxes))
	seenSpace := make(map[string]struct{}, len(configured.Mailboxes))
	for _, mailbox := range configured.Mailboxes {
		if _, err := syntax.ParseDID(mailbox.DID); err != nil {
			return errors.New("mailbox requires an exact DID")
		}
		if _, err := syntax.ParseRecordKey(mailbox.SpaceKey); err != nil {
			return errors.New("mailbox requires an exact space key")
		}
		decoded, err := hex.DecodeString(mailbox.AuthorityCertificateSHA256)
		if err != nil || len(decoded) != sha256.Size || mailbox.AuthorityCertificateSHA256 != strings.ToLower(mailbox.AuthorityCertificateSHA256) || !safeAbsoluteFile(mailbox.EvidenceFile) {
			return errors.New("mailbox requires a pinned certificate and absolute evidence path")
		}
		space := mailbox.DID + "\x00" + mailbox.SpaceKey
		if _, duplicate := seenDID[mailbox.DID]; duplicate {
			return errors.New("duplicate mailbox DID")
		}
		if _, duplicate := seenSpace[space]; duplicate {
			return errors.New("duplicate mailbox space")
		}
		seenDID[mailbox.DID] = struct{}{}
		seenSpace[space] = struct{}{}
	}
	return nil
}

func safeAbsoluteFile(path string) bool {
	return filepath.IsAbs(path) && path != string(filepath.Separator)
}

func readOwnerSecret(path string) (string, error) {
	if !safeAbsoluteFile(path) {
		return "", errors.New("secret path must be absolute")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o177 != 0 {
		return "", errors.New("secret must be an owner-only regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	opened, statErr := file.Stat()
	if statErr != nil || !opened.Mode().IsRegular() || opened.Mode().Perm()&0o177 != 0 || !os.SameFile(info, opened) {
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
	value := strings.TrimSpace(string(data))
	if len(data) > 16*1024 || value == "" || strings.ContainsAny(value, "\r\n\x00") {
		return "", errors.New("secret is empty, too large, or malformed")
	}
	return value, nil
}
