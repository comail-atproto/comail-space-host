package mailboxviewer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/mail"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/comail-atproto/comail-pds-lab/internal/mailbox"
	"github.com/comail-atproto/comail-pds-lab/internal/providers/happyview"
	"github.com/comail-atproto/comail-pds-lab/internal/repository"
)

type HappyViewConfig struct {
	Origin     string
	BasePath   string
	PublicHost string
	DID        string
	SpaceKey   string
}

type HappyViewLoader struct {
	origin     string
	basePath   string
	publicHost string
	did        string
	target     repository.Target
	client     *http.Client
}

func NewHappyViewLoader(config HappyViewConfig) (*HappyViewLoader, error) {
	origin, err := url.Parse(config.Origin)
	if err != nil || origin.Scheme != "http" || origin.Hostname() != "127.0.0.1" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || (origin.Path != "" && origin.Path != "/") {
		return nil, errors.New("mailbox viewer: HappyView origin must be an exact IPv4 loopback HTTP origin")
	}
	if config.BasePath == "/" || (config.BasePath != "" && (!strings.HasPrefix(config.BasePath, "/") || strings.HasSuffix(config.BasePath, "/") || strings.Contains(config.BasePath, ".."))) {
		return nil, errors.New("mailbox viewer: invalid HappyView base path")
	}
	if config.PublicHost == "" || strings.ContainsAny(config.PublicHost, "/ :?#@") {
		return nil, errors.New("mailbox viewer: exact HappyView public host is required")
	}
	if _, err := syntax.ParseDID(config.DID); err != nil {
		return nil, errors.New("mailbox viewer: exact account DID is required")
	}
	if _, err := syntax.ParseRecordKey(config.SpaceKey); err != nil {
		return nil, errors.New("mailbox viewer: exact space key is required")
	}
	cleanOrigin := strings.TrimSuffix(config.Origin, "/")
	return &HappyViewLoader{
		origin:     cleanOrigin,
		basePath:   config.BasePath,
		publicHost: config.PublicHost,
		did:        config.DID,
		target: repository.Target{
			ProviderOrigin: cleanOrigin,
			SpaceURI:       fmt.Sprintf("at://%s/space/%s/%s", config.DID, mailbox.MailboxSpaceType, config.SpaceKey),
			RepoDID:        config.DID,
			Epoch:          happyview.CertifiedEpoch,
		},
		client: &http.Client{
			Timeout:       30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func (l *HappyViewLoader) Load(ctx context.Context, cookie string) (MailboxView, error) {
	if !validCookieValue(cookie) {
		return MailboxView{}, repository.ErrUnauthorized
	}
	if err := l.authenticate(ctx, cookie); err != nil {
		return MailboxView{}, err
	}
	doer := &cookieDoer{origin: l.origin, basePath: l.basePath, publicHost: l.publicHost, cookie: cookie, client: l.client}
	repo, err := happyview.New(happyview.Config{
		Origin: l.origin, DID: l.did, Epoch: happyview.CertifiedEpoch, AllowHTTP: true, AllowWrites: false,
	}, doer)
	if err != nil {
		return MailboxView{}, err
	}
	return l.loadRecords(ctx, repo)
}

func (l *HappyViewLoader) authenticate(ctx context.Context, cookie string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, l.origin+l.basePath+"/auth/me", nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	request.Header.Set("Cookie", "happyview_session="+cookie)
	request.Host = l.publicHost
	response, err := l.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Request == nil || response.Request.URL.Scheme != "http" || response.Request.URL.Host != strings.TrimPrefix(l.origin, "http://") {
		return repository.ErrUnauthorized
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil || len(data) > 4096 {
		return repository.ErrUnauthorized
	}
	var result struct {
		DID string `json:"did"`
	}
	if json.Unmarshal(data, &result) != nil || result.DID != l.did {
		return repository.ErrUnauthorized
	}
	return nil
}

func (l *HappyViewLoader) loadRecords(ctx context.Context, repo *happyview.Client) (MailboxView, error) {
	folderRecords, err := repo.ListRecords(ctx, l.target, mailbox.FolderCollection)
	if err != nil {
		return MailboxView{}, err
	}
	messageRecords, err := repo.ListRecords(ctx, l.target, mailbox.MessageCollection)
	if err != nil {
		return MailboxView{}, err
	}
	stateRecords, err := repo.ListRecords(ctx, l.target, mailbox.MessageStateCollection)
	if err != nil {
		return MailboxView{}, err
	}

	folderNames := make(map[string]string, len(folderRecords))
	counts := make(map[string]int, len(folderRecords))
	for _, stored := range folderRecords {
		var record mailbox.FolderRecord
		if json.Unmarshal(stored.Value, &record) != nil || record.Type != mailbox.FolderCollection || record.Name == "" {
			return MailboxView{}, mailbox.ErrIntegrity
		}
		folderNames[stored.RKey] = record.Name
		counts[stored.RKey] = 0
	}
	states := make(map[string]mailbox.MessageStateRecord, len(stateRecords))
	for _, stored := range stateRecords {
		var state mailbox.MessageStateRecord
		if json.Unmarshal(stored.Value, &state) != nil || state.Type != mailbox.MessageStateCollection || state.Message == "" {
			return MailboxView{}, mailbox.ErrIntegrity
		}
		states[state.Message] = state
		for _, folder := range state.MailboxIDs {
			counts[folder]++
		}
	}

	view := MailboxView{DID: l.did, SpaceURI: l.target.SpaceURI}
	for rkey, name := range folderNames {
		view.Folders = append(view.Folders, FolderView{Name: name, Count: counts[rkey]})
	}
	sort.Slice(view.Folders, func(i, j int) bool {
		if strings.EqualFold(view.Folders[i].Name, "INBOX") != strings.EqualFold(view.Folders[j].Name, "INBOX") {
			return strings.EqualFold(view.Folders[i].Name, "INBOX")
		}
		return strings.ToLower(view.Folders[i].Name) < strings.ToLower(view.Folders[j].Name)
	})

	for _, stored := range messageRecords {
		var record mailbox.MessageRecord
		if json.Unmarshal(stored.Value, &record) != nil || record.Type != mailbox.MessageCollection {
			return MailboxView{}, mailbox.ErrIntegrity
		}
		raw, err := repo.GetBlob(ctx, l.target, record.Raw.Ref.Link)
		if err != nil {
			return MailboxView{}, err
		}
		if err := mailbox.ValidateStoredMessage(l.did, stored.RKey, record, raw); err != nil {
			return MailboxView{}, err
		}
		message := summarizeMessage(raw, record)
		state := states[stored.RKey]
		folders := make([]string, 0, len(state.MailboxIDs))
		for _, rkey := range state.MailboxIDs {
			if name := folderNames[rkey]; name != "" {
				folders = append(folders, name)
			}
		}
		sort.Strings(folders)
		message.Folder = strings.Join(folders, ", ")
		if message.Folder == "" {
			message.Folder = record.InitialMailbox
		}
		view.Messages = append(view.Messages, message)
	}
	sort.SliceStable(view.Messages, func(i, j int) bool { return view.Messages[i].sortKey > view.Messages[j].sortKey })
	return view, nil
}

type cookieDoer struct {
	origin     string
	basePath   string
	publicHost string
	cookie     string
	client     *http.Client
}

func (d *cookieDoer) Do(ctx context.Context, request *http.Request, _ string) (*http.Response, error) {
	if request.URL == nil || request.URL.Scheme+"://"+request.URL.Host != d.origin {
		return nil, repository.ErrTarget
	}
	clone := request.Clone(ctx)
	clone.URL.Path = d.basePath + request.URL.Path
	clone.Host = d.publicHost
	clone.Header = request.Header.Clone()
	clone.Header.Set("Cookie", "happyview_session="+d.cookie)
	return d.client.Do(clone)
}

func summarizeMessage(raw []byte, record mailbox.MessageRecord) MessageView {
	view := MessageView{Subject: "(no subject)", From: "(unknown sender)", Date: "Unknown", Size: humanSize(record.Size)}
	parsed, err := mail.ReadMessage(bytes.NewReader(raw))
	if err == nil {
		if subject := decodeHeader(parsed.Header.Get("Subject")); subject != "" {
			view.Subject = subject
		}
		if from := decodeHeader(parsed.Header.Get("From")); from != "" {
			view.From = from
		}
	}
	date := parseDate(record.MessageDate)
	if date.IsZero() && err == nil {
		date, _ = mail.ParseDate(parsed.Header.Get("Date"))
	}
	if !date.IsZero() {
		date = date.UTC()
		view.Date = date.Format("Jan 2, 2006 15:04 UTC")
		view.sortKey = date.Format(time.RFC3339Nano)
	}
	return view
}

func decodeHeader(value string) string {
	decoded, err := new(mime.WordDecoder).DecodeHeader(value)
	if err != nil {
		return strings.TrimSpace(value)
	}
	return strings.TrimSpace(decoded)
}

func parseDate(value string) time.Time {
	parsed, _ := time.Parse(time.RFC3339Nano, value)
	return parsed
}

func humanSize(size int64) string {
	if size < 1024 {
		return strconv.FormatInt(size, 10) + " B"
	}
	if size < 1024*1024 {
		return strconv.FormatFloat(float64(size)/1024, 'f', 1, 64) + " KB"
	}
	return strconv.FormatFloat(float64(size)/(1024*1024), 'f', 1, 64) + " MB"
}
