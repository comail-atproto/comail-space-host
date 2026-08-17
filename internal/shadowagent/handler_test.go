package shadowagent

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/comail-atproto/comail-pds-lab/internal/mailbox"
	"github.com/comail-atproto/comail-pds-lab/internal/memory"
	"github.com/comail-atproto/comail-pds-lab/internal/repository"
)

const agentTestDID = "did:plc:comailshadowagenttest"

func TestHandlerMirrorsAndVerifiesExactPrivateTarget(t *testing.T) {
	backend := memory.NewBackend()
	repo := backend.OwnerSession(agentTestDID)
	target, err := repo.EnsureMailbox(t.Context(), agentTestDID, "default")
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(Config{Token: "test-token", DID: agentTestDID, Target: target, Repository: repo})
	if err != nil {
		t.Fatal(err)
	}
	wireTarget := targetView(repo.ProviderID(), target)

	capabilityRequest := capabilityRequest{Version: ProtocolVersion, Target: wireTarget}
	capabilityRecorder := performAgentRequest(t, handler, "/v1/capabilities", capabilityRequest)
	var capabilities capabilityResponse
	if err := json.Unmarshal(capabilityRecorder.Body.Bytes(), &capabilities); err != nil {
		t.Fatal(err)
	}
	if capabilityRecorder.Code != http.StatusOK || !capabilities.Capabilities.PrivateRecords || !capabilities.Capabilities.ReadAfterWrite || capabilities.Target != wireTarget {
		t.Fatalf("capability response status=%d body=%s", capabilityRecorder.Code, capabilityRecorder.Body.String())
	}

	raw := []byte("Message-ID: <agent@test>\r\nSubject: synthetic\r\n\r\nbody")
	mirrorRequest := mirrorRequest{
		Version: ProtocolVersion, Target: wireTarget, RecipientDID: agentTestDID,
		Mailbox: "INBOX", Message: protocolMessage{Raw: raw},
	}
	first := performAgentRequest(t, handler, "/v1/mirror", mirrorRequest)
	second := performAgentRequest(t, handler, "/v1/mirror", mirrorRequest)
	for _, response := range []*httptest.ResponseRecorder{first, second} {
		if response.Code != http.StatusOK {
			t.Fatalf("mirror status=%d body=%s", response.Code, response.Body.String())
		}
		var body mirrorResponse
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if !body.Receipt.Verified || body.Receipt.Size != int64(len(raw)) || body.Receipt.Target != wireTarget {
			t.Fatalf("receipt = %#v", body.Receipt)
		}
	}
}

func TestHandlerAuthorityInventoryAndCASState(t *testing.T) {
	backend := memory.NewBackend()
	repo := backend.OwnerSession(agentTestDID)
	target, err := repo.EnsureMailbox(t.Context(), agentTestDID, "authority")
	if err != nil {
		t.Fatal(err)
	}
	certificate := strings.Repeat("a", 64)
	handler, err := NewHandler(Config{
		Token: "test-token", DID: agentTestDID, Target: target, Repository: repo,
		AuthorityCertificateSHA256: certificate,
	})
	if err != nil {
		t.Fatal(err)
	}
	wireTarget := targetView(repo.ProviderID(), target, certificate)
	raw := []byte("Message-ID: <authority-agent@test>\r\nSubject: authority\r\n\r\nbody")
	mirrored := performAgentRequest(t, handler, "/v1/mirror", mirrorRequest{
		Version: ProtocolVersion, Target: wireTarget, RecipientDID: agentTestDID,
		Mailbox: "INBOX", Message: protocolMessage{Raw: raw},
	})
	if mirrored.Code != http.StatusOK {
		t.Fatalf("mirror status=%d body=%s", mirrored.Code, mirrored.Body.String())
	}
	fingerprint := mailbox.DeliveryFingerprint(agentTestDID, raw)
	inventory := performAgentRequest(t, handler, "/v2/inventory", inventoryRequest{
		Version: AuthorityProtocolVersion, Target: wireTarget, Limit: 100,
	})
	var listed inventoryResponse
	if err := json.Unmarshal(inventory.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	capability := performAgentRequest(t, handler, "/v1/capabilities", capabilityRequest{Version: ProtocolVersion, Target: wireTarget})
	var advertised capabilityResponse
	if err := json.Unmarshal(capability.Body.Bytes(), &advertised); err != nil {
		t.Fatal(err)
	}
	if advertised.Capabilities.SourceVersioning {
		t.Fatal("legacy authority certificate advertised uncertified source versioning")
	}
	if inventory.Code != http.StatusOK || listed.ProviderID != repo.ProviderID() || len(listed.Messages) != 1 || string(listed.Messages[0].Raw) != string(raw) || listed.Messages[0].Revision != 1 {
		t.Fatalf("inventory status=%d body=%s", inventory.Code, inventory.Body.String())
	}
	mutated := performAgentRequest(t, handler, "/v2/state", stateMutationRequest{
		Version: AuthorityProtocolVersion, Target: wireTarget,
		Mutation: stateMutation{
			Fingerprint: fingerprint, ExpectedRevision: 1, OperationID: "jmap-change-1",
			Mailbox: "Archive", Keywords: []string{"$flagged", "$seen"},
		},
	})
	var changed stateMutationResponse
	if err := json.Unmarshal(mutated.Body.Bytes(), &changed); err != nil {
		t.Fatal(err)
	}
	if mutated.Code != http.StatusOK || changed.State.Revision != 2 || changed.State.Mailbox != "Archive" || changed.State.LastOperationID != "jmap-change-1" {
		t.Fatalf("state status=%d body=%s", mutated.Code, mutated.Body.String())
	}
	replayed := performAgentRequest(t, handler, "/v2/state", stateMutationRequest{
		Version: AuthorityProtocolVersion, Target: wireTarget,
		Mutation: stateMutation{
			Fingerprint: fingerprint, ExpectedRevision: 1, OperationID: "jmap-change-1",
			Mailbox: "Archive", Keywords: []string{"$flagged", "$seen"},
		},
	})
	if replayed.Code != http.StatusOK {
		t.Fatalf("idempotent replay status=%d body=%s", replayed.Code, replayed.Body.String())
	}
	conflict := performAgentRequest(t, handler, "/v2/state", stateMutationRequest{
		Version: AuthorityProtocolVersion, Target: wireTarget,
		Mutation: stateMutation{
			Fingerprint: fingerprint, ExpectedRevision: 1, OperationID: "different-stale",
			Mailbox: "INBOX",
		},
	})
	if conflict.Code != http.StatusConflict {
		t.Fatalf("stale conflict status=%d body=%s", conflict.Code, conflict.Body.String())
	}
}

func TestHandlerAuthorityInventoryPreservesImportedSourceIdentity(t *testing.T) {
	backend := memory.NewBackend()
	repo := backend.OwnerSession(agentTestDID)
	target, err := repo.EnsureMailbox(t.Context(), agentTestDID, "imported")
	if err != nil {
		t.Fatal(err)
	}
	certificate := strings.Repeat("a", 64)
	handler, err := NewHandler(Config{
		Token: "test-token", DID: agentTestDID, Target: target, Repository: repo,
		AuthorityCertificateSHA256: certificate,
	})
	if err != nil {
		t.Fatal(err)
	}
	wireTarget := targetView(repo.ProviderID(), target, certificate)
	if response := performAgentRequest(t, handler, "/v1/mirror", mirrorRequest{
		Version: ProtocolVersion, Target: wireTarget, RecipientDID: agentTestDID,
		Mailbox: "INBOX", Message: protocolMessage{Raw: []byte("Subject: seed\r\n\r\nseed")},
	}); response.Code != http.StatusOK {
		t.Fatalf("seed mirror status=%d body=%s", response.Code, response.Body.String())
	}

	imported := mailbox.ImportedMessage{
		RecipientDID: agentTestDID, SourceKey: "legacy:42",
		Raw: []byte("Subject: imported\r\n\r\nbody"), Mailbox: "INBOX",
	}
	blob, err := repo.UploadBlob(t.Context(), target, imported.Raw, mailbox.MessageMIMEType)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := mailbox.NewMessagePair(imported, blob)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.ApplyWrites(t.Context(), target, []repository.Write{
		{Action: repository.Create, Collection: mailbox.MessageCollection, RKey: pair.RKey, Value: pair.Message},
		{Action: repository.Create, Collection: mailbox.MessageStateCollection, RKey: pair.RKey, Value: pair.State},
	}); err != nil {
		t.Fatal(err)
	}

	inventory := performAgentRequest(t, handler, "/v2/inventory", inventoryRequest{
		Version: AuthorityProtocolVersion, Target: wireTarget, Limit: 100,
	})
	var listed inventoryResponse
	if err := json.Unmarshal(inventory.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	for _, message := range listed.Messages {
		if message.RKey == pair.RKey {
			if message.SourceKey != imported.SourceKey {
				t.Fatalf("source key = %q, want %q", message.SourceKey, imported.SourceKey)
			}
			return
		}
	}
	t.Fatalf("imported message %q absent from inventory", pair.RKey)
}

func TestHandlerCapturesAndAtomicallyVersionsEditedDraft(t *testing.T) {
	backend := memory.NewBackend()
	repo := backend.OwnerSession(agentTestDID)
	target, err := repo.EnsureMailbox(t.Context(), agentTestDID, "capture")
	if err != nil {
		t.Fatal(err)
	}
	certificate := strings.Repeat("a", 64)
	handler, err := NewHandler(Config{
		Token: "test-token", DID: agentTestDID, Target: target, Repository: repo,
		AuthorityCertificateSHA256: certificate, SourceVersioningCertified: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	wireTarget := targetView(repo.ProviderID(), target, certificate)
	capability := performAgentRequest(t, handler, "/v1/capabilities", capabilityRequest{Version: ProtocolVersion, Target: wireTarget})
	var advertised capabilityResponse
	if err := json.Unmarshal(capability.Body.Bytes(), &advertised); err != nil {
		t.Fatal(err)
	}
	if capability.Code != http.StatusOK || !advertised.Capabilities.SourceVersioning {
		t.Fatalf("capability status=%d body=%s", capability.Code, capability.Body.String())
	}

	sourceKey := "jmap:account:draft-1"
	firstRaw := []byte("Subject: draft\r\n\r\nfirst")
	secondRaw := []byte("Subject: draft\r\n\r\nsecond")
	requests := []captureRequest{
		{Mailbox: "drafts", Keywords: []string{"$draft"}, Message: protocolMessage{Raw: firstRaw}},
		{Mailbox: "drafts", Keywords: []string{"$draft"}, Message: protocolMessage{Raw: firstRaw}},
		{Mailbox: "sent", Keywords: []string{"$seen"}, Message: protocolMessage{Raw: firstRaw}},
		{Mailbox: "sent", Keywords: []string{"$seen"}, Message: protocolMessage{Raw: secondRaw}},
	}
	for index, request := range requests {
		response := performAgentRequest(t, handler, "/v2/capture", captureRequest{
			Version: AuthorityProtocolVersion, Target: wireTarget, RecipientDID: agentTestDID,
			Mailbox: request.Mailbox, Keywords: request.Keywords, SourceKey: sourceKey, Message: request.Message,
		})
		if response.Code != http.StatusOK {
			t.Fatalf("capture status=%d body=%s", response.Code, response.Body.String())
		}
		if index == 2 {
			moved := performAgentRequest(t, handler, "/v2/inventory", inventoryRequest{
				Version: AuthorityProtocolVersion, Target: wireTarget, Limit: 100,
			})
			var movedList inventoryResponse
			if err := json.Unmarshal(moved.Body.Bytes(), &movedList); err != nil {
				t.Fatal(err)
			}
			if len(movedList.Messages) != 1 || movedList.Messages[0].Mailbox != "Sent" ||
				len(movedList.Messages[0].Keywords) != 1 || movedList.Messages[0].Keywords[0] != "$seen" {
				t.Fatalf("same-byte state move was not captured: %s", moved.Body.String())
			}
		}
	}
	inventory := performAgentRequest(t, handler, "/v2/inventory", inventoryRequest{
		Version: AuthorityProtocolVersion, Target: wireTarget, Limit: 100,
	})
	var listed inventoryResponse
	if err := json.Unmarshal(inventory.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if inventory.Code != http.StatusOK || len(listed.Messages) != 2 {
		t.Fatalf("inventory status=%d body=%s", inventory.Code, inventory.Body.String())
	}
	live, tombstoned := 0, 0
	for _, message := range listed.Messages {
		if message.SourceKey != sourceKey {
			t.Fatalf("source key=%q", message.SourceKey)
		}
		if message.Tombstoned {
			tombstoned++
			if len(message.Raw) != 0 {
				t.Fatal("tombstoned draft exposed bytes")
			}
		} else {
			live++
			if string(message.Raw) != string(secondRaw) || message.Mailbox != "Sent" || len(message.Keywords) != 1 || message.Keywords[0] != "$seen" {
				t.Fatalf("live raw=%q", message.Raw)
			}
		}
	}
	if live != 1 || tombstoned != 1 {
		t.Fatalf("live=%d tombstoned=%d messages=%#v", live, tombstoned, listed.Messages)
	}
}

func TestHandlerRejectsMissingTokenAndConfusedTarget(t *testing.T) {
	backend := memory.NewBackend()
	repo := backend.OwnerSession(agentTestDID)
	target, err := repo.EnsureMailbox(t.Context(), agentTestDID, "default")
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(Config{Token: "test-token", DID: agentTestDID, Target: target, Repository: repo})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "/v1/capabilities", bytes.NewReader([]byte(`{}`)))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("missing-token status = %d", response.Code)
	}

	wrong := targetView(repo.ProviderID(), target)
	wrong.RepoDID = "did:plc:other"
	response = performAgentRequest(t, handler, "/v1/capabilities", capabilityRequest{Version: ProtocolVersion, Target: wrong})
	if response.Code != http.StatusBadRequest {
		t.Fatalf("confused-target status = %d", response.Code)
	}

	response = performAgentRequest(t, handler, "/v1/mirror", mirrorRequest{
		Version: ProtocolVersion, Target: targetView(repo.ProviderID(), target), RecipientDID: agentTestDID,
		Mailbox: "Archive", Message: protocolMessage{Raw: []byte("Subject: synthetic\r\n\r\nbody")},
	})
	if response.Code != http.StatusBadRequest {
		t.Fatalf("non-delivery mailbox status = %d", response.Code)
	}
}

func TestNewHandlerRejectsBroadOrIncompleteConfiguration(t *testing.T) {
	backend := memory.NewBackend()
	repo := backend.OwnerSession(agentTestDID)
	target, err := repo.EnsureMailbox(context.Background(), agentTestDID, "default")
	if err != nil {
		t.Fatal(err)
	}
	for _, config := range []Config{
		{DID: agentTestDID, Target: target, Repository: repo},
		{Token: "token", Target: target, Repository: repo},
		{Token: "token", DID: agentTestDID, Repository: repo},
		{Token: "token", DID: agentTestDID, Target: target},
	} {
		if _, err := NewHandler(config); err == nil {
			t.Fatalf("invalid config was accepted: %#v", config)
		}
	}
}

func performAgentRequest(t *testing.T, handler http.Handler, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(encoded))
	request.Header.Set("Authorization", "Bearer test-token")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
