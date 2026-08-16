package shadowagent

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/comail-atproto/comail-pds-lab/internal/memory"
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
