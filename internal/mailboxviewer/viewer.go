package mailboxviewer

import (
	"context"
	"errors"
	"html/template"
	"net/http"
	"strings"

	"github.com/comail-atproto/comail-pds-lab/internal/repository"
)

type FolderView struct {
	Name  string
	Count int
}

type MessageView struct {
	Subject string
	From    string
	Date    string
	Folder  string
	Size    string
	sortKey string
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

type Handler struct {
	loader    Loader
	loginPath string
	template  *template.Template
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
	_ = h.template.Execute(response, map[string]any{"Mailbox": view, "LoginPath": h.loginPath})
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
	header.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
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
  <p><strong>{{len .Mailbox.Messages}} {{plural (len .Mailbox.Messages) "message" "messages"}}</strong> across <strong>{{len .Mailbox.Folders}} {{plural (len .Mailbox.Folders) "folder" "folders"}}</strong>. This view is read-only.</p>
  <div class="grid">
    <aside class="panel"><h2>Folders</h2><ul class="folders">{{range .Mailbox.Folders}}<li><span>{{.Name}}</span><span>{{.Count}}</span></li>{{else}}<li>No folders</li>{{end}}</ul></aside>
    <section class="panel"><h2>Messages</h2>
      <table><thead><tr><th>Subject / sender</th><th class="optional">Folder</th><th>Date</th><th class="optional">Size</th></tr></thead>
      <tbody>{{range .Mailbox.Messages}}<tr><td><div class="subject">{{.Subject}}</div><div class="muted">{{.From}}</div></td><td class="optional">{{.Folder}}</td><td>{{.Date}}</td><td class="optional">{{.Size}}</td></tr>{{else}}<tr><td colspan="4">No messages found in this private space.</td></tr>{{end}}</tbody></table>
    </section>
  </div>
  <p class="muted">Pinned space: {{.Mailbox.SpaceURI}}</p>
{{else}}
  <h1>Comail PDS Lab</h1>
  <p>This mailbox view requires your isolated HappyView session.</p>
  <p><a href="{{.LoginPath}}">Log in to HappyView</a>, then return to this page.</p>
{{end}}
</main></body></html>`
