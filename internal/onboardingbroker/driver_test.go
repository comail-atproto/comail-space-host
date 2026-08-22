package onboardingbroker

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/bluesky-social/indigo/atproto/auth/oauth"
	"github.com/comail-atproto/comail-space-host/internal/authvault"
	"github.com/comail-atproto/comail-space-host/internal/oauthclient"
	"github.com/comail-atproto/comail-space-host/internal/spaceprovision"
)

type stubProvisioningOAuth struct{ metadata oauth.ClientMetadata }

func (s *stubProvisioningOAuth) StartDetailed(context.Context) (oauthclient.StartResult, error) {
	return oauthclient.StartResult{}, nil
}

func (s *stubProvisioningOAuth) Finish(context.Context, url.Values) (spaceprovision.Result, error) {
	return spaceprovision.Result{}, nil
}

func (s *stubProvisioningOAuth) ClientMetadata() oauth.ClientMetadata { return s.metadata }

type stubSteadyOAuth struct {
	metadata  oauth.ClientMetadata
	session   *oauth.ClientSession
	revokeErr error
}

func (s *stubSteadyOAuth) StartDetailed(context.Context) (oauthclient.StartResult, error) {
	return oauthclient.StartResult{}, nil
}

func (s *stubSteadyOAuth) Finish(context.Context, url.Values) (*oauth.ClientSession, error) {
	return s.session, nil
}

func (s *stubSteadyOAuth) Resume(context.Context, string) (*oauth.ClientSession, error) {
	return s.session, nil
}

func (s *stubSteadyOAuth) RevokeAndDelete(context.Context, string) error { return s.revokeErr }
func (s *stubSteadyOAuth) ClientMetadata() oauth.ClientMetadata          { return s.metadata }

func TestExactOAuthDriverProvesNewSteadySessionBeforeReadiness(t *testing.T) {
	account := Account{DID: testDID, Handle: testHandle, PDSOrigin: "https://spaces-alpha.host.bsky.network", SpaceKey: "primary"}
	origin := "https://inbox.comail.at"
	provisionPath := "/oauth/client/h8sKQ2eMv7/provision.json"
	steadyPath := "/oauth/client/h8sKQ2eMv7/steady.json"
	proofErr := errors.New("metadata proof failed")
	proved := 0
	steady := &stubSteadyOAuth{
		metadata: oauth.ClientMetadata{ClientID: origin + steadyPath, RedirectURIs: []string{origin + "/oauth/steady/callback"}},
		session:  &oauth.ClientSession{Data: &oauth.ClientSessionData{SessionID: "new-steady-session"}},
	}
	driver, err := NewExactOAuthDriver(origin, []OAuthRuntime{{
		Account: account, ProvisioningMetadataPath: provisionPath, SteadyMetadataPath: steadyPath,
		Provisioning: &stubProvisioningOAuth{metadata: oauth.ClientMetadata{ClientID: origin + provisionPath, RedirectURIs: []string{origin + "/oauth/provision/callback"}}},
		Steady:       steady,
		ProveSteady: func(_ context.Context, got *oauth.ClientSession) error {
			proved++
			if got != steady.session {
				t.Fatal("proof received a different OAuth session")
			}
			return proofErr
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	sessionID, err := driver.FinishSteady(t.Context(), account, url.Values{"state": {"state"}})
	if !errors.Is(err, proofErr) || sessionID != "new-steady-session" || proved != 1 {
		t.Fatalf("sessionID=%q err=%v proved=%d", sessionID, err, proved)
	}
}

func TestExactOAuthDriverTreatsAlreadyDeletedRetirementAsSuccess(t *testing.T) {
	account := Account{DID: testDID, Handle: testHandle, PDSOrigin: "https://spaces-alpha.host.bsky.network", SpaceKey: "primary"}
	origin := "https://inbox.comail.at"
	provisionPath := "/oauth/client/h8sKQ2eMv7/provision.json"
	steadyPath := "/oauth/client/h8sKQ2eMv7/steady.json"
	steady := &stubSteadyOAuth{
		metadata:  oauth.ClientMetadata{ClientID: origin + steadyPath, RedirectURIs: []string{origin + "/oauth/steady/callback"}},
		revokeErr: authvault.ErrNotFound,
	}
	driver, err := NewExactOAuthDriver(origin, []OAuthRuntime{{
		Account: account, ProvisioningMetadataPath: provisionPath, SteadyMetadataPath: steadyPath,
		Provisioning: &stubProvisioningOAuth{metadata: oauth.ClientMetadata{ClientID: origin + provisionPath, RedirectURIs: []string{origin + "/oauth/provision/callback"}}},
		Steady:       steady, ProveSteady: func(context.Context, *oauth.ClientSession) error { return nil },
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := driver.RetireSteady(t.Context(), account, "already-deleted"); err != nil {
		t.Fatalf("idempotent retirement: %v", err)
	}
}
