package mailboxviewer

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/comail-atproto/comail-space-host/internal/mailboxstate"
	"github.com/comail-atproto/comail-space-host/internal/repository"
)

const testDID = "did:plc:comailmailboxviewertest"

type loaderFunc func(context.Context, string) (MailboxView, error)

func (f loaderFunc) Load(ctx context.Context, cookie string) (MailboxView, error) {
	return f(ctx, cookie)
}

type mutableLoader struct {
	view      MailboxView
	mutations []mailboxstate.Mutation
}

func (l *mutableLoader) Load(context.Context, string) (MailboxView, error) { return l.view, nil }
func (l *mutableLoader) Mutate(_ context.Context, cookie string, mutation mailboxstate.Mutation) error {
	if cookie != "signed-session" {
		return repository.ErrUnauthorized
	}
	l.mutations = append(l.mutations, mutation)
	return nil
}

func TestHandlerRequiresHappyViewSession(t *testing.T) {
	handler := NewHandler(loaderFunc(func(context.Context, string) (MailboxView, error) {
		t.Fatal("loader called without a session")
		return MailboxView{}, nil
	}), "/comail-pds-lab/login/")

	request := httptest.NewRequest(http.MethodGet, "http://viewer.test/", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
	if !strings.Contains(response.Body.String(), "/comail-pds-lab/login/") {
		t.Fatal("response does not link to the isolated HappyView login")
	}
	assertSecurityHeaders(t, response.Header())
}

func TestHandlerRendersPrivateMailboxWithoutUnsafeHTML(t *testing.T) {
	handler := NewHandler(loaderFunc(func(_ context.Context, cookie string) (MailboxView, error) {
		if cookie != "signed-session" {
			t.Fatalf("cookie = %q", cookie)
		}
		return MailboxView{
			DID:      testDID,
			SpaceURI: "at://" + testDID + "/space/email.atmos.mailbox/default",
			Folders: []FolderView{
				{Name: "INBOX", Count: 1},
			},
			Messages: []MessageView{
				{Subject: `<script>alert("mail")</script>`, From: "sender@example.test", Date: "Aug 16, 2026", Folder: "INBOX", Size: "1.2 KB"},
			},
		}, nil
	}), "/comail-pds-lab/login/")

	request := httptest.NewRequest(http.MethodGet, "http://viewer.test/", nil)
	request.AddCookie(&http.Cookie{Name: "happyview_session", Value: "signed-session"})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{"1 message", "INBOX", "sender@example.test", "&lt;script&gt;alert"} {
		if !strings.Contains(body, want) {
			t.Fatalf("response is missing %q", want)
		}
	}
	if strings.Contains(body, "<script>alert") {
		t.Fatal("message subject was rendered as active HTML")
	}
	assertSecurityHeaders(t, response.Header())
}

func TestHandlerDoesNotLeakBackendErrors(t *testing.T) {
	handler := NewHandler(loaderFunc(func(context.Context, string) (MailboxView, error) {
		return MailboxView{}, errors.New("private subject or token")
	}), "/comail-pds-lab/login/")
	request := httptest.NewRequest(http.MethodGet, "http://viewer.test/", nil)
	request.AddCookie(&http.Cookie{Name: "happyview_session", Value: "signed-session"})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadGateway {
		t.Fatalf("status = %d", response.Code)
	}
	if strings.Contains(response.Body.String(), "private subject") || strings.Contains(response.Body.String(), "token") {
		t.Fatal("backend error leaked into the response")
	}
}

func TestHandlerTreatsRejectedHappyViewSessionAsUnauthorized(t *testing.T) {
	handler := NewHandler(loaderFunc(func(context.Context, string) (MailboxView, error) {
		return MailboxView{}, repository.ErrUnauthorized
	}), "/comail-pds-lab/login/")
	request := httptest.NewRequest(http.MethodGet, "http://viewer.test/", nil)
	request.AddCookie(&http.Cookie{Name: "happyview_session", Value: "expired-session"})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", response.Code)
	}
	if !strings.Contains(response.Body.String(), "/comail-pds-lab/login/") {
		t.Fatal("rejected session response does not link back to HappyView")
	}
}

func TestHandlerRejectsNonGetMethods(t *testing.T) {
	handler := NewHandler(loaderFunc(func(context.Context, string) (MailboxView, error) {
		t.Fatal("loader called for disallowed method")
		return MailboxView{}, nil
	}), "/login/")
	request := httptest.NewRequest(http.MethodPost, "http://viewer.test/", strings.NewReader("write"))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d", response.Code)
	}
}

func TestMutableHandlerRequiresSameOriginCSRFAndUsesExpectedRevision(t *testing.T) {
	loader := &mutableLoader{view: MailboxView{
		DID: testDID, SpaceURI: "at://" + testDID + "/space/email.atmos.mailbox/default",
		Folders:  []FolderView{{Name: "INBOX", Count: 1}, {Name: "Archive"}},
		Messages: []MessageView{{RKey: "sha256-message", Revision: 7, Subject: "test", Folder: "INBOX"}},
	}}
	handler := NewMutableHandler(loader, MutableConfig{
		LoginPath: "/comail-pds-lab/login/", PublicOrigin: "https://viewer.example.test", CookiePath: "/comail-pds-mailbox/",
	})
	get := httptest.NewRequest(http.MethodGet, "https://viewer.example.test/", nil)
	get.AddCookie(&http.Cookie{Name: "happyview_session", Value: "signed-session"})
	getResponse := httptest.NewRecorder()
	handler.ServeHTTP(getResponse, get)
	if getResponse.Code != http.StatusOK {
		t.Fatalf("GET status = %d", getResponse.Code)
	}
	csrfCookie := getResponse.Result().Cookies()[0]
	match := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(getResponse.Body.String())
	if len(match) != 2 || match[1] != csrfCookie.Value {
		t.Fatal("rendered CSRF token does not match the strict cookie")
	}

	values := url.Values{
		"csrf": {match[1]}, "message": {"sha256-message"}, "revision": {"7"},
		"operation": {string(mailboxstate.Move)}, "mailbox": {"Archive"},
	}
	post := httptest.NewRequest(http.MethodPost, "https://viewer.example.test/", strings.NewReader(values.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.Header.Set("Origin", "https://viewer.example.test")
	post.Header.Set("Sec-Fetch-Site", "same-origin")
	post.AddCookie(&http.Cookie{Name: "happyview_session", Value: "signed-session"})
	post.AddCookie(csrfCookie)
	postResponse := httptest.NewRecorder()
	handler.ServeHTTP(postResponse, post)
	if postResponse.Code != http.StatusSeeOther || len(loader.mutations) != 1 {
		t.Fatalf("POST status=%d mutations=%d", postResponse.Code, len(loader.mutations))
	}
	mutation := loader.mutations[0]
	if mutation.MessageRKey != "sha256-message" || mutation.ExpectedRevision != 7 || mutation.Operation != mailboxstate.Move || mutation.Mailbox != "Archive" || mutation.OperationID == "" {
		t.Fatalf("mutation = %#v", mutation)
	}

	crossSite := httptest.NewRequest(http.MethodPost, "https://viewer.example.test/", strings.NewReader(values.Encode()))
	crossSite.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	crossSite.Header.Set("Origin", "https://evil.example.test")
	crossSite.Header.Set("Sec-Fetch-Site", "cross-site")
	crossSite.AddCookie(&http.Cookie{Name: "happyview_session", Value: "signed-session"})
	crossSite.AddCookie(csrfCookie)
	crossResponse := httptest.NewRecorder()
	handler.ServeHTTP(crossResponse, crossSite)
	if crossResponse.Code != http.StatusForbidden || len(loader.mutations) != 1 {
		t.Fatal("cross-site mutation was accepted")
	}
}

func assertSecurityHeaders(t *testing.T, header http.Header) {
	t.Helper()
	for name, want := range map[string]string{
		"Cache-Control":           "no-store",
		"Content-Security-Policy": "default-src 'none'",
		"Referrer-Policy":         "no-referrer",
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
	} {
		if !strings.Contains(header.Get(name), want) {
			t.Fatalf("%s = %q, want it to contain %q", name, header.Get(name), want)
		}
	}
}
