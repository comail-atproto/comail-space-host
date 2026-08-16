package shadowagent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/comail-atproto/comail-pds-lab/internal/mailbox"
	"github.com/comail-atproto/comail-pds-lab/internal/mailboxstate"
	"github.com/comail-atproto/comail-pds-lab/internal/repository"
)

const (
	ProtocolVersion          = 1
	AuthorityProtocolVersion = 2
	maxRequestBytes          = 14 * 1024 * 1024
	maxInventoryPageJSON     = 15 * 1024 * 1024
)

type Config struct {
	Token                      string
	DID                        string
	Target                     repository.Target
	Repository                 repository.Repository
	AuthorityCertificateSHA256 string
}

type Handler struct {
	tokenHash                  [sha256.Size]byte
	did                        string
	target                     repository.Target
	repo                       repository.Repository
	authorityCertificateSHA256 string
}

type target struct {
	ProviderID                 string `json:"providerId"`
	Origin                     string `json:"origin"`
	SpaceURI                   string `json:"spaceUri"`
	RepoDID                    string `json:"repoDid"`
	Epoch                      string `json:"epoch"`
	AuthorityCertificateSHA256 string `json:"authorityCertificateSha256,omitempty"`
}

type capabilities struct {
	PrivateRecords             bool   `json:"privateRecords"`
	ReferencedBlobs            bool   `json:"referencedBlobs"`
	IdempotentWrite            bool   `json:"idempotentWrite"`
	ReadAfterWrite             bool   `json:"readAfterWrite"`
	AtomicStateWrite           bool   `json:"atomicStateWrite"`
	ConflictSafeState          bool   `json:"conflictSafeState"`
	InventoryRebuild           bool   `json:"inventoryRebuild"`
	Tombstones                 bool   `json:"tombstones"`
	AuthorityCertificateSHA256 string `json:"authorityCertificateSha256,omitempty"`
}

type capabilityRequest struct {
	Version int    `json:"version"`
	Target  target `json:"target"`
}

type capabilityResponse struct {
	Version      int          `json:"version"`
	ProviderID   string       `json:"providerId"`
	Target       target       `json:"target"`
	Capabilities capabilities `json:"capabilities"`
}

type protocolMessage struct {
	Raw []byte `json:"raw"`
}

type mirrorRequest struct {
	Version      int             `json:"version"`
	Target       target          `json:"target"`
	RecipientDID string          `json:"recipientDid"`
	Mailbox      string          `json:"mailbox"`
	Message      protocolMessage `json:"message"`
}

type receipt struct {
	Target      target `json:"target"`
	Fingerprint string `json:"fingerprint"`
	SHA256      string `json:"sha256"`
	Size        int64  `json:"size"`
	Verified    bool   `json:"verified"`
}

type mirrorResponse struct {
	Version int     `json:"version"`
	Receipt receipt `json:"receipt"`
}

type messageSnapshot struct {
	URI         string   `json:"uri"`
	RKey        string   `json:"rkey"`
	Fingerprint string   `json:"fingerprint"`
	SHA256      string   `json:"sha256"`
	Size        int64    `json:"size"`
	Mailbox     string   `json:"mailbox"`
	Keywords    []string `json:"keywords"`
	Revision    uint64   `json:"revision"`
	Tombstoned  bool     `json:"tombstoned"`
	Raw         []byte   `json:"raw"`
}

type inventoryRequest struct {
	Version int    `json:"version"`
	Target  target `json:"target"`
	Cursor  string `json:"cursor,omitempty"`
	Limit   int    `json:"limit"`
}

type inventoryResponse struct {
	Version    int               `json:"version"`
	ProviderID string            `json:"providerId"`
	Target     target            `json:"target"`
	Messages   []messageSnapshot `json:"messages"`
	NextCursor string            `json:"nextCursor,omitempty"`
}

type stateMutation struct {
	Fingerprint      string   `json:"fingerprint"`
	ExpectedRevision uint64   `json:"expectedRevision"`
	OperationID      string   `json:"operationId"`
	Mailbox          string   `json:"mailbox"`
	Keywords         []string `json:"keywords"`
	Tombstoned       bool     `json:"tombstoned"`
}

type stateMutationRequest struct {
	Version  int           `json:"version"`
	Target   target        `json:"target"`
	Mutation stateMutation `json:"mutation"`
}

type messageState struct {
	Fingerprint     string   `json:"fingerprint"`
	Mailbox         string   `json:"mailbox"`
	Keywords        []string `json:"keywords"`
	Revision        uint64   `json:"revision"`
	Tombstoned      bool     `json:"tombstoned"`
	LastOperationID string   `json:"lastOperationId"`
}

type stateMutationResponse struct {
	Version    int          `json:"version"`
	ProviderID string       `json:"providerId"`
	Target     target       `json:"target"`
	State      messageState `json:"state"`
}

func NewHandler(config Config) (*Handler, error) {
	if config.Token == "" || len(config.Token) > 16*1024 || strings.ContainsAny(config.Token, "\r\n\x00") {
		return nil, errors.New("shadow agent: exact bearer token is required")
	}
	if config.Repository == nil || config.DID == "" || config.Target.SpaceURI == "" || config.Target.RepoDID != config.DID || config.Target.Epoch == "" {
		return nil, errors.New("shadow agent: exact repository target is required")
	}
	if err := config.Target.ValidateFor(config.DID); err != nil {
		return nil, errors.New("shadow agent: invalid repository target")
	}
	if config.AuthorityCertificateSHA256 != "" && !validSHA256(config.AuthorityCertificateSHA256) {
		return nil, errors.New("shadow agent: invalid authority certificate digest")
	}
	return &Handler{
		tokenHash: sha256.Sum256([]byte(config.Token)), did: config.DID,
		target: config.Target, repo: config.Repository, authorityCertificateSHA256: config.AuthorityCertificateSHA256,
	}, nil
}

func (h *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	if request.Method != http.MethodPost {
		response.Header().Set("Allow", "POST")
		http.Error(response, `{"error":"MethodNotAllowed"}`, http.StatusMethodNotAllowed)
		return
	}
	if !h.authorized(request.Header.Get("Authorization")) {
		http.Error(response, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}
	request.Body = http.MaxBytesReader(response, request.Body, maxRequestBytes)
	switch request.URL.Path {
	case "/v1/capabilities":
		h.capability(response, request)
	case "/v1/mirror":
		h.mirror(response, request)
	case "/v2/inventory":
		h.inventory(response, request)
	case "/v2/state":
		h.state(response, request)
	default:
		http.NotFound(response, request)
	}
}

func (h *Handler) capability(response http.ResponseWriter, request *http.Request) {
	var input capabilityRequest
	if decodeStrict(request.Body, &input) != nil || input.Version != ProtocolVersion || input.Target != h.targetView() {
		http.Error(response, `{"error":"InvalidTarget"}`, http.StatusBadRequest)
		return
	}
	available, err := h.repo.Capabilities(request.Context())
	if err != nil {
		http.Error(response, `{"error":"ProviderUnavailable"}`, http.StatusBadGateway)
		return
	}
	_ = json.NewEncoder(response).Encode(capabilityResponse{
		Version: ProtocolVersion, ProviderID: h.repo.ProviderID(), Target: h.targetView(),
		Capabilities: capabilities{
			PrivateRecords: true, ReferencedBlobs: available.ReferencedBlobs,
			IdempotentWrite: true, ReadAfterWrite: true, AtomicStateWrite: available.AtomicApplyWrites,
			ConflictSafeState: available.CompareAndSwap && h.authorityCertificateSHA256 != "",
			InventoryRebuild:  h.authorityCertificateSHA256 != "", Tombstones: h.authorityCertificateSHA256 != "",
			AuthorityCertificateSHA256: h.authorityCertificateSHA256,
		},
	})
}

func (h *Handler) mirror(response http.ResponseWriter, request *http.Request) {
	var input mirrorRequest
	if decodeStrict(request.Body, &input) != nil || input.Version != ProtocolVersion || input.Target != h.targetView() || input.RecipientDID != h.did || len(input.Message.Raw) == 0 || len(input.Message.Raw) > mailbox.MaxRawMessageBytes {
		http.Error(response, `{"error":"InvalidRequest"}`, http.StatusBadRequest)
		return
	}
	input.Mailbox = canonicalMailbox(input.Mailbox)
	if input.Mailbox == "" {
		http.Error(response, `{"error":"InvalidRequest"}`, http.StatusBadRequest)
		return
	}
	receipt, err := h.storeAndVerify(request.Context(), input)
	if err != nil {
		http.Error(response, `{"error":"MirrorFailed"}`, http.StatusBadGateway)
		return
	}
	_ = json.NewEncoder(response).Encode(mirrorResponse{Version: ProtocolVersion, Receipt: receipt})
}

func (h *Handler) storeAndVerify(ctx context.Context, input mirrorRequest) (receipt, error) {
	imported := mailbox.ImportedMessage{
		RecipientDID: h.did, Raw: append([]byte(nil), input.Message.Raw...),
		Mailbox: input.Mailbox,
	}
	fingerprint := mailbox.ImportedFingerprint(imported)
	if err := h.ensureFolder(ctx, input.Mailbox); err != nil {
		return receipt{}, err
	}
	existing, err := h.repo.GetRecord(ctx, h.target, mailbox.MessageCollection, fingerprint)
	if err == nil {
		return h.verifyExisting(ctx, fingerprint, imported, existing)
	}
	if !errors.Is(err, repository.ErrNotFound) {
		return receipt{}, err
	}
	if _, stateErr := h.repo.GetRecord(ctx, h.target, mailbox.MessageStateCollection, fingerprint); stateErr == nil {
		return receipt{}, mailbox.ErrIntegrity
	} else if !errors.Is(stateErr, repository.ErrNotFound) {
		return receipt{}, stateErr
	}
	blob, err := h.repo.UploadBlob(ctx, h.target, imported.Raw, mailbox.MessageMIMEType)
	if err != nil {
		return receipt{}, err
	}
	pair, err := mailbox.NewMessagePair(imported, blob)
	if err != nil {
		return receipt{}, err
	}
	_, err = h.repo.ApplyWrites(ctx, h.target, []repository.Write{
		{Action: repository.Create, Collection: mailbox.MessageCollection, RKey: pair.RKey, Value: pair.Message},
		{Action: repository.Create, Collection: mailbox.MessageStateCollection, RKey: pair.RKey, Value: pair.State},
	})
	if err != nil && !errors.Is(err, repository.ErrExists) {
		return receipt{}, err
	}
	existing, err = h.repo.GetRecord(ctx, h.target, mailbox.MessageCollection, fingerprint)
	if err != nil {
		return receipt{}, err
	}
	return h.verifyExisting(ctx, fingerprint, imported, existing)
}

func (h *Handler) verifyExisting(ctx context.Context, fingerprint string, imported mailbox.ImportedMessage, stored repository.Record) (receipt, error) {
	var record mailbox.MessageRecord
	if json.Unmarshal(stored.Value, &record) != nil {
		return receipt{}, mailbox.ErrIntegrity
	}
	raw, err := h.repo.GetBlob(ctx, h.target, record.Raw.Ref.Link)
	if err != nil || !bytes.Equal(raw, imported.Raw) {
		return receipt{}, mailbox.ErrIntegrity
	}
	if err := mailbox.ValidateStoredMessage(h.did, fingerprint, record, raw); err != nil {
		return receipt{}, err
	}
	state, err := h.repo.GetRecord(ctx, h.target, mailbox.MessageStateCollection, fingerprint)
	if err != nil {
		return receipt{}, mailbox.ErrIntegrity
	}
	var decodedState mailbox.MessageStateRecord
	if json.Unmarshal(state.Value, &decodedState) != nil || decodedState.Type != mailbox.MessageStateCollection || decodedState.Message != fingerprint {
		return receipt{}, mailbox.ErrIntegrity
	}
	return receipt{
		Target: h.targetView(), Fingerprint: fingerprint, SHA256: rawSHA256(raw),
		Size: int64(len(raw)), Verified: true,
	}, nil
}

func (h *Handler) authorized(header string) bool {
	token := strings.TrimPrefix(header, "Bearer ")
	if token == header || token == "" {
		return false
	}
	presented := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(h.tokenHash[:], presented[:]) == 1
}

func (h *Handler) targetView() target {
	return targetView(h.repo.ProviderID(), h.target, h.authorityCertificateSHA256)
}

func targetView(providerID string, configured repository.Target, certificate ...string) target {
	var digest string
	if len(certificate) == 1 {
		digest = certificate[0]
	}
	return target{
		ProviderID: providerID, Origin: configured.ProviderOrigin, SpaceURI: configured.SpaceURI,
		RepoDID: configured.RepoDID, Epoch: configured.Epoch, AuthorityCertificateSHA256: digest,
	}
}

func decodeStrict(reader io.Reader, output any) error {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("shadow agent: trailing JSON")
	}
	return nil
}

func canonicalMailbox(value string) string {
	switch {
	case value == "", strings.EqualFold(value, "inbox"):
		return "INBOX"
	case strings.EqualFold(value, "junk"):
		return "Junk"
	default:
		return ""
	}
}

func rawSHA256(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func validSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}

func (h *Handler) ensureFolder(ctx context.Context, name string) error {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 255 || strings.ContainsAny(name, "\r\n\x00") {
		return mailbox.ErrInvalidRecord
	}
	rkey := mailbox.FolderRKey(name)
	stored, err := h.repo.GetRecord(ctx, h.target, mailbox.FolderCollection, rkey)
	if err == nil {
		var folder mailbox.FolderRecord
		if json.Unmarshal(stored.Value, &folder) != nil || folder.Name != name || folder.Type != mailbox.FolderCollection {
			return mailbox.ErrIntegrity
		}
		return nil
	}
	if !errors.Is(err, repository.ErrNotFound) {
		return err
	}
	role := ""
	switch strings.ToLower(name) {
	case "inbox":
		role = "inbox"
	case "junk":
		role = "junk"
	case "sent":
		role = "sent"
	case "drafts":
		role = "drafts"
	case "trash":
		role = "trash"
	case "archive":
		role = "archive"
	}
	folder := mailbox.NewFolder(name, role, mailbox.StableUIDValidity(h.did, name))
	_, err = h.repo.ApplyWrites(ctx, h.target, []repository.Write{{Action: repository.Create, Collection: mailbox.FolderCollection, RKey: folder.RKey, Value: folder.Record}})
	if errors.Is(err, repository.ErrExists) {
		return nil
	}
	return err
}

func (h *Handler) inventory(response http.ResponseWriter, request *http.Request) {
	if h.authorityCertificateSHA256 == "" {
		http.NotFound(response, request)
		return
	}
	var input inventoryRequest
	if decodeStrict(request.Body, &input) != nil || input.Version != AuthorityProtocolVersion || input.Target != h.targetView() || input.Limit < 1 || input.Limit > 100 {
		http.Error(response, `{"error":"InvalidRequest"}`, http.StatusBadRequest)
		return
	}
	offset := 0
	if input.Cursor != "" {
		parsed, err := strconv.Atoi(input.Cursor)
		if err != nil || parsed < 0 {
			http.Error(response, `{"error":"InvalidCursor"}`, http.StatusBadRequest)
			return
		}
		offset = parsed
	}
	messages, err := h.inventoryMessages(request.Context())
	if err != nil {
		http.Error(response, `{"error":"InventoryFailed"}`, http.StatusBadGateway)
		return
	}
	if offset > len(messages) {
		http.Error(response, `{"error":"InvalidCursor"}`, http.StatusBadRequest)
		return
	}
	end := offset + input.Limit
	if end > len(messages) {
		end = len(messages)
	}
	estimated := 0
	for index := offset; index < end; index++ {
		itemBytes := ((len(messages[index].Raw)+2)/3)*4 + 2048
		if index > offset && estimated+itemBytes > maxInventoryPageJSON {
			end = index
			break
		}
		estimated += itemBytes
	}
	next := ""
	if end < len(messages) {
		next = strconv.Itoa(end)
	}
	_ = json.NewEncoder(response).Encode(inventoryResponse{
		Version: AuthorityProtocolVersion, ProviderID: h.repo.ProviderID(), Target: h.targetView(),
		Messages: messages[offset:end], NextCursor: next,
	})
}

func (h *Handler) inventoryMessages(ctx context.Context) ([]messageSnapshot, error) {
	folderRecords, err := h.repo.ListRecords(ctx, h.target, mailbox.FolderCollection)
	if err != nil {
		return nil, err
	}
	folders := make(map[string]string, len(folderRecords))
	for _, stored := range folderRecords {
		var folder mailbox.FolderRecord
		if json.Unmarshal(stored.Value, &folder) != nil || folder.Type != mailbox.FolderCollection || folder.Name == "" || stored.RKey != mailbox.FolderRKey(folder.Name) {
			return nil, mailbox.ErrIntegrity
		}
		folders[stored.RKey] = folder.Name
	}
	states, err := h.repo.ListRecords(ctx, h.target, mailbox.MessageStateCollection)
	if err != nil {
		return nil, err
	}
	out := make([]messageSnapshot, 0, len(states))
	for _, storedState := range states {
		var state mailbox.MessageStateRecord
		if json.Unmarshal(storedState.Value, &state) != nil || state.Type != mailbox.MessageStateCollection || state.Message != storedState.RKey || state.Revision == 0 || len(state.MailboxIDs) != 1 {
			return nil, mailbox.ErrIntegrity
		}
		folder, ok := folders[state.MailboxIDs[0]]
		if !ok {
			return nil, mailbox.ErrIntegrity
		}
		storedMessage, err := h.repo.GetRecord(ctx, h.target, mailbox.MessageCollection, storedState.RKey)
		if err != nil {
			return nil, err
		}
		var message mailbox.MessageRecord
		if json.Unmarshal(storedMessage.Value, &message) != nil {
			return nil, mailbox.ErrIntegrity
		}
		item := messageSnapshot{
			URI:  h.target.SpaceURI + "/" + mailbox.MessageCollection + "/" + storedState.RKey,
			RKey: storedState.RKey, Fingerprint: storedState.RKey, SHA256: message.SHA256, Size: message.Size,
			Mailbox: folder, Keywords: append([]string(nil), state.Keywords...), Revision: state.Revision, Tombstoned: state.Tombstone,
		}
		if !state.Tombstone {
			item.Raw, err = h.repo.GetBlob(ctx, h.target, message.Raw.Ref.Link)
			if err != nil || mailbox.ValidateStoredMessage(h.did, storedState.RKey, message, item.Raw) != nil {
				return nil, mailbox.ErrIntegrity
			}
		}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RKey < out[j].RKey })
	return out, nil
}

func (h *Handler) state(response http.ResponseWriter, request *http.Request) {
	if h.authorityCertificateSHA256 == "" {
		http.NotFound(response, request)
		return
	}
	var input stateMutationRequest
	if decodeStrict(request.Body, &input) != nil || input.Version != AuthorityProtocolVersion || input.Target != h.targetView() ||
		input.Mutation.Fingerprint == "" || input.Mutation.ExpectedRevision == 0 || input.Mutation.OperationID == "" {
		http.Error(response, `{"error":"InvalidRequest"}`, http.StatusBadRequest)
		return
	}
	if err := h.ensureFolder(request.Context(), input.Mutation.Mailbox); err != nil {
		http.Error(response, `{"error":"InvalidMailbox"}`, http.StatusBadRequest)
		return
	}
	updated, err := mailboxstate.Replace(request.Context(), h.repo, h.target, mailboxstate.Replacement{
		MessageRKey: input.Mutation.Fingerprint, ExpectedRevision: input.Mutation.ExpectedRevision,
		OperationID: input.Mutation.OperationID, Mailbox: input.Mutation.Mailbox,
		Keywords: append([]string(nil), input.Mutation.Keywords...), Tombstone: input.Mutation.Tombstoned, Now: time.Now().UTC(),
	})
	if errors.Is(err, mailboxstate.ErrConflict) || errors.Is(err, mailboxstate.ErrStaleRevision) {
		http.Error(response, `{"error":"Conflict"}`, http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(response, `{"error":"StateFailed"}`, http.StatusBadGateway)
		return
	}
	_ = json.NewEncoder(response).Encode(stateMutationResponse{
		Version: AuthorityProtocolVersion, ProviderID: h.repo.ProviderID(), Target: h.targetView(),
		State: messageState{
			Fingerprint: input.Mutation.Fingerprint, Mailbox: input.Mutation.Mailbox,
			Keywords: append([]string(nil), updated.Keywords...), Revision: updated.Revision,
			Tombstoned: updated.Tombstone, LastOperationID: updated.LastOperation,
		},
	})
}
