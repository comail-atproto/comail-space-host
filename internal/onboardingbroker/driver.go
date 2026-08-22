package onboardingbroker

import (
	"context"
	"errors"
	"net/url"
	"strings"

	"github.com/bluesky-social/indigo/atproto/auth/oauth"
	"github.com/comail-atproto/comail-space-host/internal/authvault"
	"github.com/comail-atproto/comail-space-host/internal/oauthclient"
	"github.com/comail-atproto/comail-space-host/internal/repository"
)

type ProvisioningOAuth interface {
	StartDetailed(context.Context) (oauthclient.StartResult, error)
	FinishDetailed(context.Context, url.Values) (oauthclient.ProvisioningOutcome, error)
	RetryCleanup(context.Context, string) error
	ClientMetadata() oauth.ClientMetadata
}

type SteadyOAuth interface {
	StartDetailed(context.Context) (oauthclient.StartResult, error)
	Finish(context.Context, url.Values) (*oauth.ClientSession, error)
	Resume(context.Context, string) (*oauth.ClientSession, error)
	RevokeAndDelete(context.Context, string) error
	ClientMetadata() oauth.ClientMetadata
}

type OAuthRuntime struct {
	Account                  Account
	ProvisioningMetadataPath string
	SteadyMetadataPath       string
	Provisioning             ProvisioningOAuth
	Steady                   SteadyOAuth
	// ProveSteady performs a bounded authenticated operation against the exact
	// configured PDS/space using the resumed session. Resume alone proves only
	// that encrypted local state can be decoded, not that the grant is live.
	ProveSteady func(context.Context, *oauth.ClientSession) error
}

// ExactOAuthDriver binds every allowlisted account to isolated provisioning
// and steady managers. Its metadata paths are opaque configured values rather
// than account-derived identifiers.
type ExactOAuthDriver struct {
	runtimes map[string]OAuthRuntime
	metadata map[string]oauth.ClientMetadata
}

func NewExactOAuthDriver(brokerOrigin string, runtimes []OAuthRuntime) (*ExactOAuthDriver, error) {
	if len(runtimes) == 0 {
		return nil, errors.New("onboardingbroker: OAuth runtimes are required")
	}
	driver := &ExactOAuthDriver{runtimes: make(map[string]OAuthRuntime, len(runtimes)), metadata: make(map[string]oauth.ClientMetadata, len(runtimes)*2)}
	for _, runtime := range runtimes {
		if validateAccount(runtime.Account) != nil || runtime.Provisioning == nil || runtime.Steady == nil || runtime.ProveSteady == nil {
			return nil, errors.New("onboardingbroker: invalid exact OAuth runtime")
		}
		key := runtimeKey(runtime.Account)
		if _, duplicate := driver.runtimes[key]; duplicate {
			return nil, errors.New("onboardingbroker: duplicate exact OAuth runtime")
		}
		profiles := []struct {
			path     string
			callback string
			metadata oauth.ClientMetadata
		}{
			{runtime.ProvisioningMetadataPath, "/oauth/provision/callback", runtime.Provisioning.ClientMetadata()},
			{runtime.SteadyMetadataPath, "/oauth/steady/callback", runtime.Steady.ClientMetadata()},
		}
		for _, profile := range profiles {
			if !validMetadataPath(profile.path) || strings.Contains(profile.path, runtime.Account.DID) || strings.Contains(profile.path, runtime.Account.Handle) ||
				profile.metadata.ClientID != brokerOrigin+profile.path || len(profile.metadata.RedirectURIs) != 1 || profile.metadata.RedirectURIs[0] != brokerOrigin+profile.callback {
				return nil, errors.New("onboardingbroker: OAuth metadata is not exactly broker-bound")
			}
			if _, duplicate := driver.metadata[profile.path]; duplicate {
				return nil, errors.New("onboardingbroker: duplicate OAuth metadata path")
			}
			driver.metadata[profile.path] = profile.metadata
		}
		driver.runtimes[key] = runtime
	}
	return driver, nil
}

func (d *ExactOAuthDriver) StartProvisioning(ctx context.Context, account Account) (oauthclient.StartResult, error) {
	runtime, err := d.runtime(account)
	if err != nil {
		return oauthclient.StartResult{}, err
	}
	return runtime.Provisioning.StartDetailed(ctx)
}

func (d *ExactOAuthDriver) FinishProvisioning(ctx context.Context, account Account, values url.Values) (string, error) {
	runtime, err := d.runtime(account)
	if err != nil {
		return "", err
	}
	outcome, err := runtime.Provisioning.FinishDetailed(ctx, values)
	if err != nil {
		return outcome.RetainedSessionID, err
	}
	want := "at://" + account.DID + "/space/email.atmos.mailbox/" + account.SpaceKey
	if outcome.Result.SpaceURI != want {
		return "", errors.New("onboardingbroker: provisioned space target mismatch")
	}
	return "", nil
}

func (d *ExactOAuthDriver) RetireProvisioning(ctx context.Context, account Account, sessionID string) error {
	runtime, err := d.runtime(account)
	if err != nil {
		return err
	}
	err = runtime.Provisioning.RetryCleanup(ctx, sessionID)
	if errors.Is(err, authvault.ErrNotFound) {
		return nil
	}
	return err
}

func (d *ExactOAuthDriver) StartSteady(ctx context.Context, account Account) (oauthclient.StartResult, error) {
	runtime, err := d.runtime(account)
	if err != nil {
		return oauthclient.StartResult{}, err
	}
	return runtime.Steady.StartDetailed(ctx)
}

func (d *ExactOAuthDriver) FinishSteady(ctx context.Context, account Account, values url.Values) (string, error) {
	runtime, err := d.runtime(account)
	if err != nil {
		return "", err
	}
	session, err := runtime.Steady.Finish(ctx, values)
	if err != nil {
		return "", err
	}
	if session == nil || session.Data == nil || session.Data.SessionID == "" {
		return "", errors.New("onboardingbroker: steady OAuth returned no session")
	}
	sessionID := session.Data.SessionID
	if err := classifySteadyProofError(runtime.ProveSteady(ctx, session)); err != nil {
		// Return the opaque session ID with the rejection. The handler owns the
		// durable cleanup queue, so a failed remote revocation can never orphan
		// the only handle for a newly persisted OAuth session.
		return sessionID, err
	}
	return sessionID, nil
}

func (d *ExactOAuthDriver) CheckSteady(ctx context.Context, account Account, sessionID string) error {
	runtime, err := d.runtime(account)
	if err != nil {
		return err
	}
	session, err := runtime.Steady.Resume(ctx, sessionID)
	if err != nil {
		return classifySteadyProofError(err)
	}
	return classifySteadyProofError(runtime.ProveSteady(ctx, session))
}

func (d *ExactOAuthDriver) RetireSteady(ctx context.Context, account Account, sessionID string) error {
	runtime, err := d.runtime(account)
	if err != nil {
		return err
	}
	err = runtime.Steady.RevokeAndDelete(ctx, sessionID)
	if errors.Is(err, authvault.ErrNotFound) {
		// A prior cleanup may have deleted the local handle before a concurrent
		// CAS removed it from the encrypted retry queue. Absence is idempotent
		// success: there is no remaining local token material to revoke.
		return nil
	}
	return err
}

func (d *ExactOAuthDriver) ClientMetadata(path string) (oauth.ClientMetadata, bool) {
	metadata, ok := d.metadata[path]
	return metadata, ok
}

func (d *ExactOAuthDriver) runtime(account Account) (OAuthRuntime, error) {
	if d == nil {
		return OAuthRuntime{}, errors.New("onboardingbroker: OAuth driver is required")
	}
	runtime, ok := d.runtimes[runtimeKey(account)]
	if !ok || runtime.Account != account {
		return OAuthRuntime{}, errors.New("onboardingbroker: account has no exact OAuth runtime")
	}
	return runtime, nil
}

func runtimeKey(account Account) string {
	return account.DID + "\x00" + account.Handle + "\x00" + account.PDSOrigin + "\x00" + account.SpaceKey
}

func classifySteadyProofError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, oauthclient.ErrReauthorizationRequired) || errors.Is(err, repository.ErrUnauthorized) ||
		errors.Is(err, authvault.ErrNotFound) {
		return errors.Join(ErrSteadyReauthorizationRequired, err)
	}
	return err
}

func validMetadataPath(path string) bool {
	if len(path) < len("/oauth/client/a/x.json") || len(path) > 256 || path[0] != '/' {
		return false
	}
	parsed, err := url.Parse(path)
	return err == nil && parsed.IsAbs() == false && parsed.Host == "" && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.Path == path &&
		len(parsed.Path) == len(path) && path != "/oauth/client/" && len(path) > len("/oauth/client/") && path[:len("/oauth/client/")] == "/oauth/client/"
}

var _ OAuthDriver = (*ExactOAuthDriver)(nil)
