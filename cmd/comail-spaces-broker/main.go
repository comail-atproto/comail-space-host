package main

import (
	"bytes"
	"context"
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
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/bluesky-social/indigo/atproto/auth/oauth"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/comail-atproto/comail-space-host/internal/authvault"
	"github.com/comail-atproto/comail-space-host/internal/oauthclient"
	"github.com/comail-atproto/comail-space-host/internal/onboardingbroker"
	"github.com/comail-atproto/comail-space-host/internal/securefile"
	"github.com/comail-atproto/comail-space-host/internal/spacecredential"
	"github.com/comail-atproto/comail-space-host/internal/spaceproof"
)

const (
	maxConfigBytes = 128 * 1024
)

type config struct {
	Enabled             bool            `json:"enabled"`
	Listen              string          `json:"listen"`
	BrokerOrigin        string          `json:"brokerOrigin"`
	ReturnURL           string          `json:"returnUrl"`
	RelayTokenFile      string          `json:"relayTokenFile"`
	VaultFile           string          `json:"vaultFile"`
	VaultKeyFile        string          `json:"vaultKeyFile"`
	PLCOrigin           string          `json:"plcOrigin"`
	ProofTimeoutSeconds int             `json:"proofTimeoutSeconds"`
	ShutdownSeconds     int             `json:"shutdownSeconds"`
	Accounts            []accountConfig `json:"accounts"`
}

type accountConfig struct {
	DID                      string `json:"did"`
	Handle                   string `json:"handle"`
	PDSOrigin                string `json:"pdsOrigin"`
	SpaceHostOrigin          string `json:"spaceHostOrigin"`
	SpaceKey                 string `json:"spaceKey"`
	ProvisioningMetadataPath string `json:"provisioningMetadataPath"`
	SteadyMetadataPath       string `json:"steadyMetadataPath"`
}

func main() {
	configPath := flag.String("config", "", "absolute path to the production Spaces onboarding broker config")
	flag.Parse()
	if !safeAbsolutePath(*configPath) {
		fmt.Fprintln(os.Stderr, "comail-spaces-broker: --config must be an absolute file path")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, *configPath); err != nil {
		fmt.Fprintln(os.Stderr, "comail-spaces-broker:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, configPath string) error {
	configured, err := loadConfig(configPath)
	if err != nil {
		return err
	}
	relayToken, err := readOwnerSecret(configured.RelayTokenFile)
	if err != nil {
		return fmt.Errorf("read relay bearer: %w", err)
	}
	vault, err := openOrCreateVault(configured.VaultFile, configured.VaultKeyFile)
	if err != nil {
		return fmt.Errorf("open encrypted OAuth vault: %w", err)
	}
	resolver, err := spacecredential.NewPLCSigningKeyResolver(configured.PLCOrigin, false)
	if err != nil {
		return fmt.Errorf("configure PLC resolver: %w", err)
	}

	accounts := make([]onboardingbroker.Account, 0, len(configured.Accounts))
	runtimes := make([]onboardingbroker.OAuthRuntime, 0, len(configured.Accounts))
	proofTimeout := time.Duration(configured.ProofTimeoutSeconds) * time.Second
	for _, item := range configured.Accounts {
		account := onboardingbroker.Account{
			DID: item.DID, Handle: item.Handle, PDSOrigin: item.PDSOrigin, SpaceKey: item.SpaceKey,
		}
		provisioning, err := oauthclient.NewProvisioner(oauthclient.Config{
			DID: account.DID, Handle: account.Handle, Origin: account.PDSOrigin,
			CallbackURL: configured.BrokerOrigin + "/oauth/provision/callback",
			ClientID:    configured.BrokerOrigin + item.ProvisioningMetadataPath,
			SpaceKey:    account.SpaceKey,
		}, vault)
		if err != nil {
			return fmt.Errorf("configure provisioning OAuth runtime: %w", err)
		}
		steady, err := oauthclient.New(oauthclient.Config{
			DID: account.DID, Handle: account.Handle, Origin: account.PDSOrigin,
			CallbackURL: configured.BrokerOrigin + "/oauth/steady/callback",
			ClientID:    configured.BrokerOrigin + item.SteadyMetadataPath,
			SpaceKey:    account.SpaceKey,
		}, vault)
		if err != nil {
			return fmt.Errorf("configure steady OAuth runtime: %w", err)
		}
		spaceURI := "at://" + account.DID + "/space/email.atmos.mailbox/" + account.SpaceKey
		exchanger, err := spacecredential.New(spacecredential.Config{
			SpaceURI: spaceURI, SpaceHostOrigin: item.SpaceHostOrigin, SigningKeys: resolver,
			AppAccess: spacecredential.AppAccessOpen,
		})
		if err != nil {
			return fmt.Errorf("configure steady credential exchange: %w", err)
		}
		proofAccount := account
		proofOrigin := item.SpaceHostOrigin
		proofManager := steady
		proofExchanger := exchanger
		proveSteady := func(parent context.Context, session *oauth.ClientSession) error {
			proofCtx, cancel := context.WithTimeout(parent, proofTimeout)
			defer cancel()
			delegations, err := proofManager.Doer(session)
			if err != nil {
				return err
			}
			credential, err := proofExchanger.Acquire(proofCtx, delegations)
			if err != nil {
				return err
			}
			defer credential.Close()
			reader, err := spaceproof.New(spaceproof.Config{
				Origin: proofOrigin, DID: proofAccount.DID, SpaceKey: proofAccount.SpaceKey,
			}, credential)
			if err != nil {
				return err
			}
			result, err := reader.ProveRead(proofCtx)
			if err != nil {
				return err
			}
			if result.RepoState != spaceproof.RepoReady {
				return errors.New("steady proof returned an unready repository")
			}
			return nil
		}
		accounts = append(accounts, account)
		runtimes = append(runtimes, onboardingbroker.OAuthRuntime{
			Account: account, ProvisioningMetadataPath: item.ProvisioningMetadataPath,
			SteadyMetadataPath: item.SteadyMetadataPath, Provisioning: provisioning,
			Steady: steady, ProveSteady: proveSteady,
		})
	}
	driver, err := onboardingbroker.NewExactOAuthDriver(configured.BrokerOrigin, runtimes)
	if err != nil {
		return err
	}
	broker, err := onboardingbroker.New(onboardingbroker.Config{
		BrokerOrigin: configured.BrokerOrigin, RelayToken: relayToken,
		ReturnURL: configured.ReturnURL, Accounts: accounts,
	}, vault, driver)
	if err != nil {
		return err
	}

	listener, err := net.Listen("tcp4", configured.Listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer listener.Close()
	writeTimeout := 45 * time.Second
	if proofTimeout+15*time.Second > writeTimeout {
		writeTimeout = proofTimeout + 15*time.Second
	}
	server := &http.Server{
		Handler: newRootHandler(broker), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 45 * time.Second, WriteTimeout: writeTimeout,
		IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 * 1024,
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(listener) }()
	fmt.Printf("Comail Spaces onboarding broker ready: enabled_accounts=%d authority_activation=false\n", len(accounts))
	select {
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Duration(configured.ShutdownSeconds)*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	}
}

func openOrCreateVault(vaultPath, keyPath string) (*authvault.Store, error) {
	_, vaultErr := os.Lstat(vaultPath)
	_, keyErr := os.Lstat(keyPath)
	vaultMissing := errors.Is(vaultErr, os.ErrNotExist)
	keyMissing := errors.Is(keyErr, os.ErrNotExist)
	switch {
	case vaultMissing && keyMissing:
		return authvault.Create(vaultPath, keyPath)
	case vaultErr == nil && keyErr == nil:
		return authvault.Open(vaultPath, keyPath)
	case vaultErr != nil && !vaultMissing:
		return nil, fmt.Errorf("inspect OAuth vault: %w", vaultErr)
	case keyErr != nil && !keyMissing:
		return nil, fmt.Errorf("inspect OAuth vault key: %w", keyErr)
	default:
		return nil, errors.New("OAuth vault and key must either both exist or both be absent")
	}
}

func loadConfig(path string) (config, error) {
	if !safeAbsolutePath(path) {
		return config{}, errors.New("config path must be an absolute file path")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return config{}, err
	}
	if len(data) == 0 || len(data) > maxConfigBytes {
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
	if err := validateConfig(configured); err != nil {
		return config{}, err
	}
	return configured, nil
}

func validateConfig(configured config) error {
	if !configured.Enabled {
		return errors.New("broker is default-off; set enabled=true explicitly")
	}
	host, port, err := net.SplitHostPort(configured.Listen)
	if err != nil || host != "127.0.0.1" || port == "" {
		return errors.New("listener must use exact IPv4 loopback")
	}
	if !cleanPublicHTTPSOrigin(configured.BrokerOrigin) || configured.ReturnURL != "https://comail.at/webmail/login" || !cleanPublicHTTPSOrigin(configured.PLCOrigin) {
		return errors.New("broker, return, and PLC URLs are not exact HTTPS targets")
	}
	if !safeAbsolutePath(configured.RelayTokenFile) || !safeAbsolutePath(configured.VaultFile) || !safeAbsolutePath(configured.VaultKeyFile) ||
		configured.RelayTokenFile == configured.VaultFile || configured.RelayTokenFile == configured.VaultKeyFile || configured.VaultFile == configured.VaultKeyFile {
		return errors.New("separate absolute relay, vault, and vault-key paths are required")
	}
	if configured.ProofTimeoutSeconds < 1 || configured.ProofTimeoutSeconds > 60 || configured.ShutdownSeconds < 1 || configured.ShutdownSeconds > 60 {
		return errors.New("proof and shutdown timeouts must be between 1 and 60 seconds")
	}
	if len(configured.Accounts) == 0 || len(configured.Accounts) > 128 {
		return errors.New("one to 128 explicit accounts are required")
	}
	seenDIDs := make(map[string]struct{}, len(configured.Accounts))
	seenPaths := make(map[string]struct{}, len(configured.Accounts)*2)
	for _, account := range configured.Accounts {
		did, didErr := syntax.ParseDID(account.DID)
		handle, handleErr := syntax.ParseHandle(account.Handle)
		key, keyErr := syntax.ParseRecordKey(account.SpaceKey)
		if didErr != nil || did.String() != account.DID || handleErr != nil || handle.String() != account.Handle || keyErr != nil || key.String() == "*" {
			return errors.New("account contains an invalid exact DID, handle, or space key")
		}
		if !cleanPublicHTTPSOrigin(account.PDSOrigin) || account.SpaceHostOrigin != account.PDSOrigin {
			return errors.New("account PDS and space-host must be the same exact public HTTPS origin")
		}
		if _, duplicate := seenDIDs[account.DID]; duplicate {
			return errors.New("duplicate account DID")
		}
		seenDIDs[account.DID] = struct{}{}
		paths := []struct {
			path, suffix string
		}{{account.ProvisioningMetadataPath, "/provision.json"}, {account.SteadyMetadataPath, "/steady.json"}}
		for _, candidate := range paths {
			if !validOpaqueMetadataPath(candidate.path, candidate.suffix) || strings.Contains(candidate.path, account.DID) || strings.Contains(candidate.path, account.Handle) {
				return errors.New("account OAuth metadata path is not an opaque fixed profile path")
			}
			if _, duplicate := seenPaths[candidate.path]; duplicate {
				return errors.New("duplicate OAuth metadata path")
			}
			seenPaths[candidate.path] = struct{}{}
		}
	}
	return nil
}

func newRootHandler(broker http.Handler) http.Handler {
	root := http.NewServeMux()
	root.HandleFunc("GET /healthz", func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = io.WriteString(response, `{"ok":true}`)
	})
	root.Handle("/", broker)
	return root
}

func readOwnerSecret(path string) (string, error) {
	data, err := securefile.Read(path, 4096)
	if err != nil {
		return "", err
	}
	value := strings.TrimSuffix(string(data), "\n")
	if len(value) < 24 || len(value) > 1024 || strings.TrimSpace(value) != value || strings.ContainsAny(value, " \t\r\n\x00") {
		return "", errors.New("secret must be one bounded non-whitespace value")
	}
	return value, nil
}

func safeAbsolutePath(path string) bool {
	return filepath.IsAbs(path) && path != string(filepath.Separator) && filepath.Clean(path) == path
}

func cleanPublicHTTPSOrigin(raw string) bool {
	target, err := url.Parse(raw)
	if err != nil || target.Scheme != "https" || target.Hostname() == "" || target.User != nil || target.Port() != "" || target.Path != "" || target.RawPath != "" || target.RawQuery != "" || target.Fragment != "" {
		return false
	}
	hostname := target.Hostname()
	return net.ParseIP(hostname) == nil && strings.Contains(hostname, ".") && !strings.HasSuffix(hostname, ".") &&
		hostname != "localhost" && !strings.HasSuffix(hostname, ".localhost") && strings.ToLower(hostname) == hostname
}

func validOpaqueMetadataPath(path, suffix string) bool {
	const prefix = "/oauth/client/"
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		return false
	}
	slug := strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix)
	if len(slug) < 6 || len(slug) > 64 || strings.Contains(slug, "/") {
		return false
	}
	for _, character := range slug {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '-' && character != '_' {
			return false
		}
	}
	return true
}
