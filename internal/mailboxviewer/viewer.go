package mailboxviewer

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/comail-atproto/comail-pds-lab/internal/mailboxstate"
	"github.com/comail-atproto/comail-pds-lab/internal/repository"
)

type FolderView struct {
	Name  string
	Count int
}

type MessageView struct {
	RKey     string
	Revision uint64
	Subject  string
	From     string
	Date     string
	Folder   string
	Size     string
	Read     bool
	Flagged  bool
	sortKey  string
}

type MailboxView struct {
	DID      string
	SpaceURI string
	Folders  []FolderView
	Messages []MessageView
}

type Loader interface {
	Load(context.Context, string) (MailboxView, error)
}

type MutableLoader interface {
	Loader
	Mutate(context.Context, string, mailboxstate.Mutation) error
}

type MutableConfig struct {
	LoginPath    string
	PublicOrigin string
	CookiePath   string
}

type Handler struct {
	loader     Loader
	loginPath  string
	template   *template.Template
	mutator    MutableLoader
	origin     string
	cookiePath string
}

func NewMutableHandler(loader MutableLoader, config MutableConfig) http.Handler {
	if loader == nil || !strings.HasPrefix(config.PublicOrigin, "https://") || strings.ContainsAny(config.PublicOrigin, "\r\n") ||
		!strings.HasPrefix(config.CookiePath, "/") || !strings.HasSuffix(config.CookiePath, "/") {
		panic("mailbox viewer: invalid mutable handler configuration")
	}
	handler := NewHandler(loader, config.LoginPath).(*Handler)
	handler.mutator = loader
	handler.origin = config.PublicOrigin
	handler.cookiePath = config.CookiePath
	return handler
}

func NewHandler(loader Loader, loginPath string) http.Handler {
	return &Handler{
		loader:    loader,
		loginPath: loginPath,
		template:  template.Must(template.New("mailbox").Funcs(template.FuncMap{"plural": plural}).Parse(pageTemplate)),
	}
}

func (h *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	setSecurityHeaders(response.Header())
	if request.Method == http.MethodPost && h.mutator != nil {
		h.mutate(response, request)
		return
	}
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		response.Header().Set("Allow", "GET, HEAD")
		http.Error(response, "Method not allowed.", http.StatusMethodNotAllowed)
		return
	}
	if request.URL.Path != "/" {
		http.NotFound(response, request)
		return
	}
	cookie, err := request.Cookie("happyview_session")
	if err != nil || !validCookieValue(cookie.Value) {
		h.renderLogin(response)
		return
	}
	view, err := h.loader.Load(request.Context(), cookie.Value)
	if err != nil {
		if errors.Is(err, repository.ErrUnauthorized) {
			h.renderLogin(response)
			return
		}
		http.Error(response, "The private mailbox could not be loaded from HappyView.", http.StatusBadGateway)
		return
	}
	if request.Method == http.MethodHead {
		return
	}
	csrf := ""
	if h.mutator != nil {
		csrf = h.csrfToken(response, request)
	}
	_ = h.template.Execute(response, map[string]any{"Mailbox": view, "LoginPath": h.loginPath, "CSRF": csrf, "Mutable": h.mutator != nil})
}

func (h *Handler) mutate(response http.ResponseWriter, request *http.Request) {
	if request.URL.Path != "/" {
		http.NotFound(response, request)
		return
	}
	if request.Header.Get("Origin") != h.origin || request.Header.Get("Sec-Fetch-Site") != "same-origin" {
		http.Error(response, "Forbidden.", http.StatusForbidden)
		return
	}
	session, err := request.Cookie("happyview_session")
	if err != nil || !validCookieValue(session.Value) {
		h.renderLogin(response)
		return
	}
	request.Body = http.MaxBytesReader(response, request.Body, 16*1024)
	if err := request.ParseForm(); err != nil {
		http.Error(response, "Invalid request.", http.StatusBadRequest)
		return
	}
	csrfCookie, err := request.Cookie("comail_viewer_csrf")
	presented := request.PostForm.Get("csrf")
	if err != nil || !validCSRF(csrfCookie.Value) || !validCSRF(presented) || subtle.ConstantTimeCompare([]byte(csrfCookie.Value), []byte(presented)) != 1 {
		http.Error(response, "Forbidden.", http.StatusForbidden)
		return
	}
	revision, err := strconv.ParseUint(request.PostForm.Get("revision"), 10, 64)
	if err != nil || revision == 0 {
		http.Error(response, "Invalid request.", http.StatusBadRequest)
		return
	}
	opID, err := randomToken()
	if err != nil {
		http.Error(response, "Mailbox state could not be updated.", http.StatusInternalServerError)
		return
	}
	operation := mailboxstate.Operation(request.PostForm.Get("operation"))
	mailboxName := ""
	if operation == mailboxstate.Move {
		mailboxName = request.PostForm.Get("mailbox")
	}
	mutation := mailboxstate.Mutation{
		MessageRKey: request.PostForm.Get("message"), ExpectedRevision: revision,
		OperationID: opID, Operation: operation,
		Mailbox: mailboxName, Now: time.Now().UTC(),
	}
	if err := h.mutator.Mutate(request.Context(), session.Value, mutation); err != nil {
		if errors.Is(err, repository.ErrUnauthorized) {
			h.renderLogin(response)
			return
		}
		if errors.Is(err, mailboxstate.ErrConflict) || errors.Is(err, mailboxstate.ErrStaleRevision) {
			http.Error(response, "Mailbox changed in another session. Reload and try again.", http.StatusConflict)
			return
		}
		http.Error(response, "Mailbox state could not be updated.", http.StatusBadGateway)
		return
	}
	response.Header().Set("Location", "./")
	response.WriteHeader(http.StatusSeeOther)
}

func (h *Handler) csrfToken(response http.ResponseWriter, request *http.Request) string {
	if cookie, err := request.Cookie("comail_viewer_csrf"); err == nil && validCSRF(cookie.Value) {
		return cookie.Value
	}
	token, err := randomToken()
	if err != nil {
		return ""
	}
	http.SetCookie(response, &http.Cookie{
		Name: "comail_viewer_csrf", Value: token, Path: h.cookiePath,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	return token
}

func randomToken() (string, error) {
	value := make([]byte, 24)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func validCSRF(value string) bool {
	return len(value) == 32 && !strings.ContainsAny(value, ";\r\n\x00")
}

func (h *Handler) renderLogin(response http.ResponseWriter) {
	response.WriteHeader(http.StatusUnauthorized)
	_ = h.template.Execute(response, map[string]any{"LoginPath": h.loginPath})
}

func validCookieValue(value string) bool {
	return value != "" && len(value) <= 16*1024 && !strings.ContainsAny(value, ";\r\n\x00")
}

func setSecurityHeaders(header http.Header) {
	header.Set("Cache-Control", "no-store")
	header.Set("Content-Type", "text/html; charset=utf-8")
	header.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
}

func plural(count int, singular, plural string) string {
	if count == 1 {
		return singular
	}
	return plural
}

const pageTemplate = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Comail PDS Lab · Mailbox</title>
  <style>
    :root { color-scheme: light dark; font-family: ui-sans-serif, system-ui, sans-serif; }
    body { margin: 0; background: Canvas; color: CanvasText; }
    main { max-width: 1100px; margin: 0 auto; padding: 2rem 1.25rem 4rem; }
    header { display: flex; justify-content: space-between; gap: 1rem; align-items: end; border-bottom: 1px solid GrayText; padding-bottom: 1rem; }
    h1 { margin: 0; font-size: 1.7rem; }
    h2 { font-size: 1rem; margin: 0 0 .75rem; }
    p { line-height: 1.5; }
    .muted { color: GrayText; font-size: .88rem; overflow-wrap: anywhere; }
    .grid { display: grid; grid-template-columns: minmax(150px, 220px) minmax(0, 1fr); gap: 1.5rem; margin-top: 1.5rem; }
    .panel { border: 1px solid GrayText; border-radius: .75rem; padding: 1rem; }
    .folders { list-style: none; margin: 0; padding: 0; }
    .folders li { display: flex; justify-content: space-between; padding: .5rem 0; border-bottom: 1px solid color-mix(in srgb, GrayText 35%, transparent); }
    table { border-collapse: collapse; width: 100%; }
    th, td { padding: .7rem .55rem; text-align: left; border-bottom: 1px solid color-mix(in srgb, GrayText 35%, transparent); vertical-align: top; }
    th { font-size: .78rem; text-transform: uppercase; letter-spacing: .04em; color: GrayText; }
    .subject { font-weight: 650; }
    .status { display: inline-block; padding: .2rem .55rem; border: 1px solid GrayText; border-radius: 999px; font-size: .78rem; }
    @media (max-width: 760px) { .grid { grid-template-columns: 1fr; } .optional { display: none; } }
  </style>
</head>
<body><main>
{{if .Mailbox}}
  <header><div><h1>Comail mailbox</h1><div class="muted">{{.Mailbox.DID}}</div></div><span class="status">HappyView private space</span></header>
  <p><strong>{{len .Mailbox.Messages}} {{plural (len .Mailbox.Messages) "message" "messages"}}</strong> across <strong>{{len .Mailbox.Folders}} {{plural (len .Mailbox.Folders) "folder" "folders"}}</strong>. {{if .Mutable}}Mailbox state is written to this private space with compare-and-swap.{{else}}This view is read-only.{{end}}</p>
  <div class="grid">
    <aside class="panel"><h2>Folders</h2><ul class="folders">{{range .Mailbox.Folders}}<li><span>{{.Name}}</span><span>{{.Count}}</span></li>{{else}}<li>No folders</li>{{end}}</ul></aside>
    <section class="panel"><h2>Messages</h2>
      <table><thead><tr><th>Subject / sender</th><th class="optional">Folder</th><th>Date</th><th class="optional">Size</th>{{if $.Mutable}}<th>Actions</th>{{end}}</tr></thead>
      <tbody>{{range .Mailbox.Messages}}<tr><td><div class="subject">{{if not .Read}}● {{end}}{{if .Flagged}}★ {{end}}{{.Subject}}</div><div class="muted">{{.From}}</div></td><td class="optional">{{.Folder}}</td><td>{{.Date}}</td><td class="optional">{{.Size}}</td>{{if $.Mutable}}<td><form method="post"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="message" value="{{.RKey}}"><input type="hidden" name="revision" value="{{.Revision}}"><button name="operation" value="{{if .Read}}markUnread{{else}}markRead{{end}}">{{if .Read}}Unread{{else}}Read{{end}}</button> <button name="operation" value="{{if .Flagged}}unflag{{else}}flag{{end}}">{{if .Flagged}}Unflag{{else}}Flag{{end}}</button> <select name="mailbox">{{range $.Mailbox.Folders}}<option value="{{.Name}}">{{.Name}}</option>{{end}}</select><button name="operation" value="move">Move</button> <button name="operation" value="tombstone">Delete</button></form></td>{{end}}</tr>{{else}}<tr><td colspan="5">No messages found in this private space.</td></tr>{{end}}</tbody></table>
    </section>
  </div>
  <p class="muted">Pinned space: {{.Mailbox.SpaceURI}}</p>
{{else}}
  <h1>Comail PDS Lab</h1>
  <p>This mailbox view requires your isolated HappyView session.</p>
  <p><a href="{{.LoginPath}}">Log in to HappyView</a>, then return to this page.</p>
{{end}}
</main></body></html>`
