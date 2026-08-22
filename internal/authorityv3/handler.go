// SPDX-License-Identifier: AGPL-3.0-or-later

package authorityv3

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/comail-atproto/comail-space-host/internal/mailbox"
)

const (
	maxRequestBytes  = 14 * 1024 * 1024
	maxSnapshotBytes = 64 * 1024 * 1024
	// maxSnapshotResponseBytes is the official-v3 whole-response cap shared
	// with the relay client. It fits the base64 expansion of the raw-byte
	// ceiling plus 42.66 MiB of metadata. Larger inventories fail closed
	// until the protocol grows pagination.
	maxSnapshotResponseBytes = 128 << 20
	maxFolders               = 4096
	maxMessages              = 100_000
	maxStateMailboxIDs       = 32
	maxStateKeywords         = 128
	maxStateRevisions        = 4096
)

type Config struct {
	Token  string
	Target Target
	Engine Engine
}

type Handler struct {
	tokenHash [sha256.Size]byte
	target    Target
	engine    Engine
}

func NewHandler(config Config) (*Handler, error) {
	if config.Token == "" || len(config.Token) > 16*1024 || strings.ContainsAny(config.Token, "\r\n\x00") {
		return nil, errors.New("authorityv3: exact bearer token is required")
	}
	if config.Engine == nil {
		return nil, errors.New("authorityv3: engine is required")
	}
	if !validTarget(config.Target) {
		return nil, errors.New("authorityv3: exact official-v3 target is required")
	}
	return &Handler{
		tokenHash: sha256.Sum256([]byte(config.Token)),
		target:    config.Target,
		engine:    config.Engine,
	}, nil
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	if request.Method != http.MethodPost {
		response.Header().Set("Allow", http.MethodPost)
		writeError(response, http.StatusMethodNotAllowed, "MethodNotAllowed")
		return
	}
	if !handler.authorized(request.Header.Get("Authorization")) {
		writeError(response, http.StatusUnauthorized, "Unauthorized")
		return
	}
	if request.URL.RawQuery != "" || !isJSONContentType(request.Header.Get("Content-Type")) {
		writeError(response, http.StatusBadRequest, "InvalidRequest")
		return
	}
	request.Body = http.MaxBytesReader(response, request.Body, maxRequestBytes)
	switch request.URL.Path {
	case "/v3/capabilities":
		handler.capabilities(response, request)
	case "/v3/messages/store":
		handler.store(response, request)
	case "/v3/snapshot":
		handler.snapshot(response, request)
	case "/v3/state/append":
		handler.appendState(response, request)
	default:
		writeError(response, http.StatusNotFound, "NotFound")
	}
}

func (handler *Handler) capabilities(response http.ResponseWriter, request *http.Request) {
	var input capabilityRequest
	if decodeStrict(request.Body, &input) != nil || input.Version != ProtocolVersion || input.Target != handler.target {
		writeError(response, http.StatusBadRequest, "InvalidTarget")
		return
	}
	capabilities, err := handler.engine.Capabilities(request.Context())
	if err != nil || !capabilities.supports(handler.target) {
		writeError(response, http.StatusBadGateway, "ProviderUnavailable")
		return
	}
	writeJSON(response, capabilityResponse{
		Version: ProtocolVersion, ProviderID: handler.target.ProviderID,
		Target: handler.target, Capabilities: capabilities,
	})
}

func (handler *Handler) store(response http.ResponseWriter, request *http.Request) {
	var input storeRequest
	if decodeStrict(request.Body, &input) != nil || input.Version != ProtocolVersion ||
		input.Target != handler.target || input.RecipientDID != handler.target.RepoDID ||
		len(input.Message.Raw) == 0 || len(input.Message.Raw) > mailbox.MaxRawMessageBytes ||
		!validPlacement(input.Placement) {
		writeError(response, http.StatusBadRequest, "InvalidRequest")
		return
	}
	receipt, err := handler.engine.Store(request.Context(), StoreInput{
		RecipientDID: input.RecipientDID,
		Placement:    clonePlacement(input.Placement),
		Raw:          bytes.Clone(input.Message.Raw),
	})
	wantFingerprint := sourceFingerprint(input.RecipientDID, input.Placement.SourceKey, input.Message.Raw)
	if err != nil || receipt.Target != handler.target || !receipt.Verified ||
		receipt.Fingerprint != wantFingerprint || receipt.SHA256 != rawSHA256(input.Message.Raw) ||
		receipt.Size != int64(len(input.Message.Raw)) {
		writeError(response, http.StatusBadGateway, "StoreFailed")
		return
	}
	writeJSON(response, storeResponse{
		Version: ProtocolVersion, ProviderID: handler.target.ProviderID,
		Target: handler.target, Receipt: receipt,
	})
}

func (handler *Handler) snapshot(response http.ResponseWriter, request *http.Request) {
	var input snapshotRequest
	if decodeStrict(request.Body, &input) != nil || input.Version != ProtocolVersion || input.Target != handler.target {
		writeError(response, http.StatusBadRequest, "InvalidTarget")
		return
	}
	snapshot, err := handler.engine.Snapshot(request.Context())
	if err != nil || !validSnapshot(snapshot, handler.target) {
		writeError(response, http.StatusBadGateway, "SnapshotFailed")
		return
	}
	defer clearSnapshot(&snapshot)
	payload := snapshotResponse{
		Version: ProtocolVersion, ProviderID: handler.target.ProviderID,
		Target: handler.target, Snapshot: snapshot,
	}
	encoded, err := encodeBoundedSnapshotJSON(payload, maxSnapshotResponseBytes)
	if err != nil {
		writeError(response, http.StatusBadGateway, "SnapshotTooLarge")
		return
	}
	response.WriteHeader(http.StatusOK)
	_ = encoded.writeTo(response)
}

func (handler *Handler) appendState(response http.ResponseWriter, request *http.Request) {
	var input stateRequest
	if decodeStrict(request.Body, &input) != nil || input.Version != ProtocolVersion ||
		input.Target != handler.target || !validMutation(input.Mutation) {
		writeError(response, http.StatusBadRequest, "InvalidRequest")
		return
	}
	state, err := handler.engine.AppendState(request.Context(), cloneMutation(input.Mutation))
	if errors.Is(err, ErrConflict) {
		writeError(response, http.StatusConflict, "Conflict")
		return
	}
	if err != nil || !validMutationResult(input.Mutation, state) {
		writeError(response, http.StatusBadGateway, "AppendFailed")
		return
	}
	writeJSON(response, stateResponse{
		Version: ProtocolVersion, ProviderID: handler.target.ProviderID,
		Target: handler.target, OperationID: input.Mutation.OperationID, State: state,
	})
}

func (handler *Handler) authorized(header string) bool {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) || len(header) <= len(prefix) || len(header) > len(prefix)+16*1024 {
		return false
	}
	presented := sha256.Sum256([]byte(strings.TrimPrefix(header, prefix)))
	return subtle.ConstantTimeCompare(presented[:], handler.tokenHash[:]) == 1
}

func (capabilities Capabilities) supports(target Target) bool {
	return capabilities.PrivateRecords && capabilities.ReferencedBlobs && capabilities.AtomicCreateBatch &&
		capabilities.IdempotentOperationClaims && capabilities.AuthenticatedStableRead && capabilities.CompleteInventory &&
		capabilities.ConcurrentHeads && capabilities.Tombstones && capabilities.SourceVersioning &&
		capabilities.AuthorityGeneration == AuthorityGeneration &&
		capabilities.AuthorityCertificateSHA256 == target.AuthorityCertificateSHA256
}

func validTarget(target Target) bool {
	if target.ProviderID == "" || target.Origin == "" || target.SpaceURI == "" || target.RepoDID == "" ||
		target.Epoch == "" || target.AuthorityCertificateGeneration != AuthorityGeneration ||
		!validRawSHA256(target.AuthorityCertificateSHA256) ||
		strings.ContainsAny(target.ProviderID+target.RepoDID+target.Epoch, " \t\r\n\x00") {
		return false
	}
	if _, err := syntax.ParseDID(target.RepoDID); err != nil {
		return false
	}
	origin, err := url.Parse(target.Origin)
	if err != nil || origin.Scheme != "https" || origin.Hostname() == "" || origin.User != nil ||
		origin.RawQuery != "" || origin.Fragment != "" || origin.RawPath != "" ||
		(origin.Path != "" && (origin.Path == "/" || path.Clean(origin.Path) != origin.Path || strings.HasSuffix(origin.Path, "/"))) {
		return false
	}
	if !strings.HasPrefix(target.SpaceURI, "at://") {
		return false
	}
	authority, spacePath, found := strings.Cut(strings.TrimPrefix(target.SpaceURI, "at://"), "/")
	if !found {
		return false
	}
	if _, err := syntax.ParseDID(authority); err != nil {
		return false
	}
	segments := strings.Split(spacePath, "/")
	if len(segments) != 3 || segments[0] != "space" || segments[1] != "email.atmos.mailbox" || strings.ContainsAny(spacePath, "?#") {
		return false
	}
	if _, err := syntax.ParseNSID(segments[1]); err != nil {
		return false
	}
	if _, err := syntax.ParseRecordKey(segments[2]); err != nil {
		return false
	}
	return true
}

func validPlacement(placement Placement) bool {
	if len(placement.SourceKey) > 512 || strings.ContainsAny(placement.SourceKey, "\r\n\x00") ||
		len(placement.Folders) == 0 || len(placement.Folders) > maxStateMailboxIDs ||
		len(placement.Keywords) > maxStateKeywords ||
		!validSortedUnique(placement.Keywords, func(value string) bool { return validText(value, 255) }) {
		return false
	}
	seen := make(map[string]struct{}, len(placement.Folders))
	for _, folder := range placement.Folders {
		if !validText(folder.SourceKey, 512) || !validText(folder.Name, 255) || !validRole(folder.Role) ||
			(folder.Role != "" && folder.Name != standardFolderName(folder.Role)) {
			return false
		}
		if _, exists := seen[folder.SourceKey]; exists {
			return false
		}
		seen[folder.SourceKey] = struct{}{}
	}
	return true
}

func validMutation(mutation StateMutation) bool {
	return validPrefixedSHA256(mutation.SnapshotID, "sha256-") &&
		validPrefixedSHA256(mutation.LogicalMessageID, "sha256-") && validText(mutation.OperationID, 128) &&
		validHeadSet(mutation.ExpectedHeads, "state-") &&
		mutation.ExpectedHeadsDigest == headsDigest("comail-message-state-heads-v1\x00", mutation.ExpectedHeads) &&
		validPrefixedSHA256(mutation.ExpectedStateDigest, "sha256-") && mutation.ExpectedHeight > 0 &&
		mutation.ExpectedRevisionCount >= len(mutation.ExpectedHeads) && mutation.ExpectedRevisionCount < maxStateRevisions &&
		uint64(mutation.ExpectedRevisionCount) >= mutation.ExpectedHeight &&
		validPrefixedSHA256(mutation.Version, "sha256-") &&
		len(mutation.MailboxIDs) <= maxStateMailboxIDs &&
		validSortedUnique(mutation.MailboxIDs, func(value string) bool { return validPrefixedSHA256(value, "folder-") }) &&
		len(mutation.Keywords) <= maxStateKeywords &&
		validSortedUnique(mutation.Keywords, func(value string) bool { return validText(value, 255) }) &&
		(mutation.Tombstone || len(mutation.MailboxIDs) > 0)
}

func validMutationResult(mutation StateMutation, state MessageState) bool {
	return state.SnapshotID != mutation.SnapshotID && validPrefixedSHA256(state.SnapshotID, "sha256-") &&
		state.LogicalMessageID == mutation.LogicalMessageID && state.Version == mutation.Version &&
		slices.Equal(state.MailboxIDs, mutation.MailboxIDs) && slices.Equal(state.Keywords, mutation.Keywords) &&
		state.DeletePending == mutation.DeletePending && state.Tombstone == mutation.Tombstone &&
		state.Height == mutation.ExpectedHeight+1 && state.RevisionCount == mutation.ExpectedRevisionCount+1 &&
		state.RevisionCount <= maxStateRevisions &&
		len(state.Heads) == 1 && validPrefixedSHA256(state.Heads[0], "state-") &&
		state.HeadsDigest == headsDigest("comail-message-state-heads-v1\x00", state.Heads) &&
		state.StateDigest == messageStateDigest(state)
}

func validSnapshot(snapshot Snapshot, target Target) bool {
	if snapshot.Version != ProtocolVersion || snapshot.Target != target || !validText(snapshot.Revision, 512) ||
		!validPrefixedSHA256(snapshot.SnapshotID, "sha256-") || !validPrefixedSHA256(snapshot.ManifestSHA256, "sha256-") ||
		len(snapshot.Folders) > maxFolders || len(snapshot.Messages) > maxMessages || len(snapshot.States) > maxMessages {
		return false
	}
	folders := make(map[string]FolderState, len(snapshot.Folders))
	standardRoles := make(map[string]struct{}, 7)
	var total int64
	for _, folder := range snapshot.Folders {
		if folder.SnapshotID != snapshot.SnapshotID || !validPrefixedSHA256(folder.FolderID, "folder-") ||
			!validText(folder.Name, 255) || !validRole(folder.Role) ||
			!validHeadSet(folder.Heads, "folder-state-") ||
			folder.HeadsDigest != headsDigest("comail-folder-state-heads-v1\x00", folder.Heads) ||
			folder.StateDigest != folderStateDigest(folder) ||
			folder.Height == 0 || folder.RevisionCount < len(folder.Heads) || folder.RevisionCount > maxStateRevisions ||
			uint64(folder.RevisionCount) < folder.Height {
			return false
		}
		if _, duplicate := folders[folder.FolderID]; duplicate {
			return false
		}
		folders[folder.FolderID] = folder
		if folder.Role != "" {
			if folder.FolderID != standardFolderID(target.RepoDID, folder.Role) ||
				folder.Name != standardFolderName(folder.Role) {
				return false
			}
			if _, duplicate := standardRoles[folder.Role]; duplicate {
				return false
			}
			standardRoles[folder.Role] = struct{}{}
		}
	}
	if len(standardRoles) != 7 {
		return false
	}
	versions := make(map[string]MessageVersion, len(snapshot.Messages))
	logicalVersions := make(map[string]int, len(snapshot.Messages))
	for _, message := range snapshot.Messages {
		if !validPrefixedSHA256(message.RKey, "sha256-") || message.Fingerprint != message.RKey ||
			message.URI != target.SpaceURI+"/"+target.RepoDID+"/email.atmos.message/"+message.RKey ||
			!validPrefixedSHA256(message.LogicalMessageID, "sha256-") || !validOptionalText(message.SourceKey, 512) ||
			len(message.Raw) == 0 || len(message.Raw) > mailbox.MaxRawMessageBytes ||
			message.Size != int64(len(message.Raw)) || message.SHA256 != rawSHA256(message.Raw) ||
			message.Fingerprint != sourceFingerprint(target.RepoDID, message.SourceKey, message.Raw) ||
			message.LogicalMessageID != logicalMessageID(target.RepoDID, message.SourceKey, message.Fingerprint) ||
			int64(len(message.Raw)) > maxSnapshotBytes-total {
			return false
		}
		if _, duplicate := versions[message.RKey]; duplicate {
			return false
		}
		total += int64(len(message.Raw))
		versions[message.RKey] = message
		logicalVersions[message.LogicalMessageID]++
	}
	states := make(map[string]struct{}, len(snapshot.States))
	for _, state := range snapshot.States {
		selected, exists := versions[state.Version]
		if state.SnapshotID != snapshot.SnapshotID || !validPrefixedSHA256(state.LogicalMessageID, "sha256-") ||
			!exists || selected.LogicalMessageID != state.LogicalMessageID ||
			len(state.MailboxIDs) > maxStateMailboxIDs ||
			!validSortedUnique(state.MailboxIDs, func(value string) bool { return validPrefixedSHA256(value, "folder-") }) ||
			len(state.Keywords) > maxStateKeywords ||
			!validSortedUnique(state.Keywords, func(value string) bool { return validText(value, 255) }) ||
			!validHeadSet(state.Heads, "state-") ||
			state.HeadsDigest != headsDigest("comail-message-state-heads-v1\x00", state.Heads) ||
			state.StateDigest != messageStateDigest(state) ||
			state.Height == 0 || state.RevisionCount < len(state.Heads) || state.RevisionCount > maxStateRevisions ||
			uint64(state.RevisionCount) < state.Height ||
			(!state.Tombstone && len(state.MailboxIDs) == 0) {
			return false
		}
		if _, duplicate := states[state.LogicalMessageID]; duplicate {
			return false
		}
		states[state.LogicalMessageID] = struct{}{}
		if !state.Tombstone {
			for _, folderID := range state.MailboxIDs {
				folder, exists := folders[folderID]
				if !exists || folder.Tombstone {
					return false
				}
			}
		}
	}
	if len(states) != len(logicalVersions) {
		return false
	}
	for logicalID := range logicalVersions {
		if _, exists := states[logicalID]; !exists {
			return false
		}
	}
	return true
}

func validRole(role string) bool {
	if role == "" {
		return true
	}
	switch role {
	case "archive", "drafts", "important", "inbox", "junk", "sent", "trash":
		return true
	default:
		return false
	}
}

func validText(value string, limit int) bool {
	return value != "" && len(value) <= limit && utf8.ValidString(value) && !strings.ContainsAny(value, "\r\n\x00")
}

func validOptionalText(value string, limit int) bool {
	return value == "" || validText(value, limit)
}

func standardFolderName(role string) string {
	switch role {
	case "archive":
		return "Archive"
	case "drafts":
		return "Drafts"
	case "important":
		return "Important"
	case "inbox":
		return "Inbox"
	case "junk":
		return "Junk"
	case "sent":
		return "Sent"
	case "trash":
		return "Trash"
	default:
		return ""
	}
}

func validSortedUnique(values []string, validate func(string) bool) bool {
	for index, value := range values {
		if !validate(value) || (index > 0 && strings.Compare(values[index-1], value) >= 0) {
			return false
		}
	}
	return true
}

func validHeadSet(values []string, prefix string) bool {
	return len(values) > 0 && len(values) <= 64 && validSortedUnique(values, func(value string) bool {
		return validPrefixedSHA256(value, prefix)
	})
}

func validRawSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}

func validPrefixedSHA256(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	return validRawSHA256(strings.TrimPrefix(value, prefix))
}

func sourceFingerprint(recipient, sourceKey string, raw []byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("comail-habitat-delivery-v2\x00"))
	_, _ = hash.Write([]byte(recipient))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(sourceKey))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(raw)
	return "sha256-" + hex.EncodeToString(hash.Sum(nil))
}

func logicalMessageID(recipient, sourceKey, fingerprint string) string {
	if sourceKey == "" {
		return fingerprint
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("comail-logical-message-v1\x00"))
	_, _ = hash.Write([]byte(recipient))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(sourceKey))
	return "sha256-" + hex.EncodeToString(hash.Sum(nil))
}

func rawSHA256(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func headsDigest(domain string, heads []string) string {
	var encoded canonicalWriter
	encoded.raw(domain)
	encoded.strings(heads)
	return prefixedDigest(encoded.bytes)
}

func messageStateDigest(state MessageState) string {
	var encoded canonicalWriter
	encoded.raw("comail-message-state-reduced-v1\x00")
	encoded.string(state.LogicalMessageID)
	encoded.string(state.Version)
	encoded.strings(state.MailboxIDs)
	encoded.strings(state.Keywords)
	encoded.boolean(state.DeletePending)
	encoded.boolean(state.Tombstone)
	encoded.strings(state.Heads)
	encoded.string(state.HeadsDigest)
	encoded.uint64(state.Height)
	encoded.uint64(uint64(state.RevisionCount))
	return prefixedDigest(encoded.bytes)
}

func folderStateDigest(state FolderState) string {
	var encoded canonicalWriter
	encoded.raw("comail-folder-state-reduced-v1\x00")
	encoded.string(state.FolderID)
	encoded.string(state.Name)
	encoded.string(state.Role)
	encoded.boolean(state.Tombstone)
	encoded.strings(state.Heads)
	encoded.string(state.HeadsDigest)
	encoded.uint64(state.Height)
	encoded.uint64(uint64(state.RevisionCount))
	return prefixedDigest(encoded.bytes)
}

func standardFolderID(repoDID, role string) string {
	var encoded canonicalWriter
	encoded.raw("comail-standard-folder-v1\x00")
	encoded.string(repoDID)
	encoded.string(role)
	return "folder-" + strings.TrimPrefix(prefixedDigest(encoded.bytes), "sha256-")
}

func prefixedDigest(encoded []byte) string {
	sum := sha256.Sum256(encoded)
	return "sha256-" + hex.EncodeToString(sum[:])
}

type canonicalWriter struct{ bytes []byte }

func (writer *canonicalWriter) raw(value string) {
	writer.bytes = append(writer.bytes, value...)
}

func (writer *canonicalWriter) boolean(value bool) {
	if value {
		writer.bytes = append(writer.bytes, 1)
		return
	}
	writer.bytes = append(writer.bytes, 0)
}

func (writer *canonicalWriter) uint64(value uint64) {
	var scratch [binary.MaxVarintLen64]byte
	length := binary.PutUvarint(scratch[:], value)
	writer.bytes = append(writer.bytes, scratch[:length]...)
}

func (writer *canonicalWriter) string(value string) {
	writer.uint64(uint64(len(value)))
	writer.bytes = append(writer.bytes, value...)
}

func (writer *canonicalWriter) strings(values []string) {
	writer.uint64(uint64(len(values)))
	for _, value := range values {
		writer.string(value)
	}
}

func clonePlacement(placement Placement) Placement {
	result := placement
	result.Folders = append([]FolderSelection(nil), placement.Folders...)
	result.Keywords = append([]string(nil), placement.Keywords...)
	return result
}

func cloneMutation(mutation StateMutation) StateMutation {
	result := mutation
	result.ExpectedHeads = append([]string(nil), mutation.ExpectedHeads...)
	result.MailboxIDs = append([]string(nil), mutation.MailboxIDs...)
	result.Keywords = append([]string(nil), mutation.Keywords...)
	return result
}

func decodeStrict(reader io.Reader, output any) error {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("authorityv3: trailing JSON")
	}
	return nil
}

func isJSONContentType(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && mediaType == "application/json"
}

func writeJSON(response http.ResponseWriter, value any) {
	if err := json.NewEncoder(response).Encode(value); err != nil {
		return
	}
}

var errSnapshotResponseTooLarge = errors.New("authorityv3: JSON response exceeded transport limit")

// boundedSnapshotJSON holds independently bounded JSON fragments. Snapshot
// arrays are encoded one item at a time, so preflighting an oversized inventory
// cannot first allocate an unbounded whole-response buffer. Nothing is written
// to the HTTP response until every fragment fits the shared transport cap.
type boundedSnapshotJSON struct {
	chunks [][]byte
	size   int
	limit  int
}

func encodeBoundedSnapshotJSON(value snapshotResponse, limit int) (*boundedSnapshotJSON, error) {
	if limit <= 0 {
		return nil, errSnapshotResponseTooLarge
	}
	encoded := &boundedSnapshotJSON{limit: limit}
	outerHeader := struct {
		Version    int    `json:"version"`
		ProviderID string `json:"providerId"`
		Target     Target `json:"target"`
	}{Version: value.Version, ProviderID: value.ProviderID, Target: value.Target}
	if err := encoded.appendObjectPrefix(outerHeader); err != nil {
		return nil, err
	}
	if err := encoded.appendLiteral(`,"snapshot":`); err != nil {
		return nil, err
	}
	snapshotHeader := struct {
		Version        int    `json:"version"`
		Target         Target `json:"target"`
		Revision       string `json:"revision"`
		SnapshotID     string `json:"snapshotId"`
		ManifestSHA256 string `json:"manifestSha256"`
	}{
		Version: value.Snapshot.Version, Target: value.Snapshot.Target,
		Revision: value.Snapshot.Revision, SnapshotID: value.Snapshot.SnapshotID,
		ManifestSHA256: value.Snapshot.ManifestSHA256,
	}
	if err := encoded.appendObjectPrefix(snapshotHeader); err != nil {
		return nil, err
	}
	if err := encoded.appendLiteral(`,"folders":`); err != nil {
		return nil, err
	}
	if err := appendSnapshotArray(encoded, value.Snapshot.Folders); err != nil {
		return nil, err
	}
	if err := encoded.appendLiteral(`,"messages":`); err != nil {
		return nil, err
	}
	if err := appendSnapshotArray(encoded, value.Snapshot.Messages); err != nil {
		return nil, err
	}
	if err := encoded.appendLiteral(`,"states":`); err != nil {
		return nil, err
	}
	if err := appendSnapshotArray(encoded, value.Snapshot.States); err != nil {
		return nil, err
	}
	if err := encoded.appendLiteral("}}\n"); err != nil {
		return nil, err
	}
	return encoded, nil
}

func (encoded *boundedSnapshotJSON) appendObjectPrefix(value any) error {
	chunk, err := json.Marshal(value)
	if err != nil || len(chunk) < 2 || chunk[0] != '{' || chunk[len(chunk)-1] != '}' {
		if err != nil {
			return err
		}
		return errors.New("authorityv3: invalid JSON object prefix")
	}
	return encoded.appendChunk(chunk[:len(chunk)-1])
}

func appendSnapshotArray[T any](encoded *boundedSnapshotJSON, values []T) error {
	if values == nil {
		return encoded.appendLiteral("null")
	}
	if err := encoded.appendLiteral("["); err != nil {
		return err
	}
	for index, value := range values {
		if index > 0 {
			if err := encoded.appendLiteral(","); err != nil {
				return err
			}
		}
		chunk, err := json.Marshal(value)
		if err != nil {
			return err
		}
		if err := encoded.appendChunk(chunk); err != nil {
			return err
		}
	}
	return encoded.appendLiteral("]")
}

func (encoded *boundedSnapshotJSON) appendLiteral(value string) error {
	return encoded.appendChunk([]byte(value))
}

func (encoded *boundedSnapshotJSON) appendChunk(chunk []byte) error {
	if len(chunk) > encoded.limit-encoded.size {
		return errSnapshotResponseTooLarge
	}
	encoded.chunks = append(encoded.chunks, chunk)
	encoded.size += len(chunk)
	return nil
}

func (encoded *boundedSnapshotJSON) writeTo(writer io.Writer) error {
	for _, chunk := range encoded.chunks {
		if _, err := writer.Write(chunk); err != nil {
			return err
		}
	}
	return nil
}

func writeError(response http.ResponseWriter, status int, code string) {
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(map[string]string{"error": code})
}

var _ http.Handler = (*Handler)(nil)
