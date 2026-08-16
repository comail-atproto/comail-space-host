package happyview_test

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/comail-atproto/comail-pds-lab/internal/mailbox"
	"github.com/comail-atproto/comail-pds-lab/internal/migrate"
	"github.com/comail-atproto/comail-pds-lab/internal/projection"
	"github.com/comail-atproto/comail-pds-lab/internal/providers/happyview"
	"github.com/comail-atproto/comail-pds-lab/internal/sqliteimport"
	"github.com/comail-atproto/comail-pds-lab/internal/synthetic"
)

const (
	liveOwnerDID    = "did:plc:comailhappyviewtest"
	liveAttackerDID = "did:plc:comailhappyviewattacker"
)

type liveCookieDoer struct {
	cookie string
	client *http.Client
}

func (d *liveCookieDoer) Do(ctx context.Context, request *http.Request, _ string) (*http.Response, error) {
	clone := request.Clone(ctx)
	clone.Header = request.Header.Clone()
	clone.Header.Set("Cookie", "happyview_session="+d.cookie)
	return d.client.Do(clone)
}

func TestLiveLoopbackSyntheticMailboxAuthority(t *testing.T) {
	origin := os.Getenv("HAPPYVIEW_LIVE_ORIGIN")
	secretPath := os.Getenv("HAPPYVIEW_LIVE_SESSION_SECRET_FILE")
	if origin == "" || secretPath == "" {
		t.Skip("set HAPPYVIEW_LIVE_ORIGIN and HAPPYVIEW_LIVE_SESSION_SECRET_FILE for the isolated runtime proof")
	}
	secretBytes, err := os.ReadFile(secretPath)
	if err != nil {
		t.Fatal(err)
	}
	secret := strings.TrimSpace(string(secretBytes))
	ownerDoer := newLiveCookieDoer(t, secret, liveOwnerDID)
	repo, err := happyview.New(happyview.Config{
		Origin: origin, DID: liveOwnerDID, Epoch: happyview.CertifiedEpoch,
		AllowHTTP: true, AllowWrites: true,
	}, ownerDoer)
	if err != nil {
		t.Fatal(err)
	}

	work := t.TempDir()
	sourcePath := filepath.Join(work, "source.sqlite")
	if err := synthetic.CreateSnapshot(sourcePath, liveOwnerDID, "primary"); err != nil {
		t.Fatal(err)
	}
	snapshot, err := sqliteimport.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	report, err := migrate.Run(context.Background(), snapshot, repo, migrate.Options{RecipientDID: liveOwnerDID, SpaceKey: "primary", Commit: true})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Verification.Passed() || len(report.Fingerprints) == 0 {
		t.Fatalf("migration verification = %#v", report.Verification)
	}
	rebuilt, err := projection.Rebuild(context.Background(), repo, report.Target, filepath.Join(work, "rebuilt.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	if !rebuilt.Passed() || rebuilt.Messages == 0 || rebuilt.TotalBytes == 0 {
		t.Fatalf("projection = %#v", rebuilt)
	}

	attackerDoer := newLiveCookieDoer(t, secret, liveAttackerDID)
	query := url.Values{
		"space":      {report.Target.SpaceURI},
		"collection": {mailbox.MessageCollection},
		"rkey":       {report.Fingerprints[0]},
	}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, origin+"/xrpc/com.atproto.space.getRecord?"+query.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := attackerDoer.Do(context.Background(), request, "com.atproto.space.getRecord")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64*1024))
	if response.StatusCode != http.StatusNotFound && response.StatusCode != http.StatusForbidden {
		t.Fatalf("non-member private read status = %d", response.StatusCode)
	}
}

func newLiveCookieDoer(t *testing.T, sessionSecret, did string) *liveCookieDoer {
	t.Helper()
	const info = "COOKIE;SIGNED:HMAC-SHA256;PRIVATE:AEAD-AES-256-GCM"
	keys, err := hkdf.Expand(sha256.New, []byte(sessionSecret), info, 64)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, keys[:32])
	_, _ = mac.Write([]byte(did))
	signed := base64.StdEncoding.EncodeToString(mac.Sum(nil)) + did
	return &liveCookieDoer{
		cookie: signed,
		client: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func TestLiveDIDsRemainSynthetic(t *testing.T) {
	for _, did := range []string{liveOwnerDID, liveAttackerDID} {
		if !strings.Contains(did, "comailhappyview") {
			t.Fatal(fmt.Errorf("live test DID is not visibly synthetic: %s", did))
		}
	}
}
