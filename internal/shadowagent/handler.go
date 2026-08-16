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
	"strings"

	"github.com/comail-atproto/comail-pds-lab/internal/mailbox"
	"github.com/comail-atproto/comail-pds-lab/internal/repository"
)

const (
	ProtocolVersion = 1
	maxRequestBytes = 14 * 1024 * 1024
)

type Config struct {
	Token      string
	DID        string
	Target     repository.Target
	Repository repository.Repository
}

type Handler struct {
	tokenHash [sha256.Size]byte
	did       string
	target    repository.Target
	repo      repository.Repository
}

type target struct {
	ProviderID string `json:"providerId"`
	Origin     string `json:"origin"`
	SpaceURI   string `json:"spaceUri"`
	RepoDID    string `json:"repoDid"`
	Epoch      string `json:"epoch"`
}

type capabilities struct {
	PrivateRecords   bool `json:"privateRecords"`
	ReferencedBlobs  bool `json:"referencedBlobs"`
	IdempotentWrite  bool `json:"idempotentWrite"`
	ReadAfterWrite   bool `json:"readAfterWrite"`
	AtomicStateWrite bool `json:"atomicStateWrite"`
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
	return &Handler{
		tokenHash: sha256.Sum256([]byte(config.Token)), did: config.DID,
		target: config.Target, repo: config.Repository,
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

func (h *Handler) targetView() target { return targetView(h.repo.ProviderID(), h.target) }

func targetView(providerID string, configured repository.Target) target {
	return target{
		ProviderID: providerID, Origin: configured.ProviderOrigin, SpaceURI: configured.SpaceURI,
		RepoDID: configured.RepoDID, Epoch: configured.Epoch,
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
