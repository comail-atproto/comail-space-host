// SPDX-License-Identifier: AGPL-3.0-or-later

package authorityv3

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestHandlerServesExactAppendOnlyV3ContractWithoutFlattening(t *testing.T) {
	target := testTarget()
	raw := []byte("Message-ID: <authority-v3@test>\r\nSubject: v3\r\n\r\nbody")
	fingerprint := sourceFingerprint(target.RepoDID, "jmap:email-1", raw)
	logicalID := logicalMessageID(target.RepoDID, "jmap:email-1", fingerprint)
	snapshotID := "sha256-" + strings.Repeat("5", 64)
	customFolderID := "folder-" + strings.Repeat("2", 64)
	mailboxIDs := []string{standardFolderID(target.RepoDID, "inbox"), customFolderID}
	slices.Sort(mailboxIDs)
	heads := []string{"state-" + strings.Repeat("3", 64), "state-" + strings.Repeat("4", 64)}
	currentState := MessageState{
		LogicalMessageID: logicalID, SnapshotID: snapshotID, Version: fingerprint,
		MailboxIDs: mailboxIDs, Keywords: []string{"$flagged", "$seen"}, Heads: heads,
		Height: 2, RevisionCount: 2,
	}
	currentState.HeadsDigest = headsDigest("comail-message-state-heads-v1\x00", currentState.Heads)
	currentState.StateDigest = messageStateDigest(currentState)
	newState := MessageState{
		LogicalMessageID: logicalID, SnapshotID: "sha256-" + strings.Repeat("f", 64), Version: fingerprint,
		MailboxIDs: mailboxIDs, Keywords: []string{"$seen"}, Heads: []string{"state-" + strings.Repeat("a", 64)},
		Height: 3, RevisionCount: 3,
	}
	newState.HeadsDigest = headsDigest("comail-message-state-heads-v1\x00", newState.Heads)
	newState.StateDigest = messageStateDigest(newState)
	engine := &fakeEngine{
		capabilities: fullCapabilities(target),
		receipt: Receipt{
			Target: target, Fingerprint: fingerprint, SHA256: rawSHA256(raw),
			Size: int64(len(raw)), Verified: true,
		},
		snapshot: Snapshot{
			Version: ProtocolVersion, Target: target, Revision: "commit-1",
			SnapshotID:     snapshotID,
			ManifestSHA256: "sha256-" + strings.Repeat("6", 64),
			Folders:        testFolders(target, snapshotID, customFolderID),
			Messages: []MessageVersion{{
				URI:  target.SpaceURI + "/" + target.RepoDID + "/email.atmos.message/" + fingerprint,
				RKey: fingerprint, Fingerprint: fingerprint, LogicalMessageID: logicalID,
				SourceKey: "jmap:email-1", SHA256: rawSHA256(raw), Size: int64(len(raw)), Raw: raw,
			}},
			States: []MessageState{currentState},
		},
		state: newState,
	}
	handler := mustHandler(t, Config{Token: "relay-secret", Target: target, Engine: engine})

	capability := performRequest(t, handler, "/v3/capabilities", capabilityRequest{Version: ProtocolVersion, Target: target}, "relay-secret")
	var capabilityBody capabilityResponse
	decodeResponse(t, capability, &capabilityBody)
	if capability.Code != http.StatusOK || capabilityBody.Target != target || capabilityBody.Capabilities.AuthorityGeneration != AuthorityGeneration {
		t.Fatalf("capabilities status=%d body=%s", capability.Code, capability.Body.String())
	}

	placement := Placement{
		SourceKey: "jmap:email-1",
		Folders:   []FolderSelection{{SourceKey: "jmap:inbox", Name: "Inbox", Role: "inbox"}, {SourceKey: "jmap:project", Name: "Project"}},
		Keywords:  []string{"$flagged", "$seen"},
	}
	stored := performRequest(t, handler, "/v3/messages/store", storeRequest{
		Version: ProtocolVersion, Target: target, RecipientDID: target.RepoDID,
		Placement: placement, Message: protocolMessage{Raw: raw},
	}, "relay-secret")
	var storedBody storeResponse
	decodeResponse(t, stored, &storedBody)
	if stored.Code != http.StatusOK || storedBody.Receipt.Fingerprint != fingerprint || !reflect.DeepEqual(engine.gotStore.Placement, placement) {
		t.Fatalf("store status=%d body=%s input=%#v", stored.Code, stored.Body.String(), engine.gotStore)
	}

	read := performRequest(t, handler, "/v3/snapshot", snapshotRequest{Version: ProtocolVersion, Target: target}, "relay-secret")
	var readBody snapshotResponse
	decodeResponse(t, read, &readBody)
	if read.Code != http.StatusOK || !reflect.DeepEqual(readBody.Snapshot.States[0].MailboxIDs, mailboxIDs) ||
		!reflect.DeepEqual(readBody.Snapshot.States[0].Heads, heads) {
		t.Fatalf("snapshot flattened authority state: status=%d body=%s", read.Code, read.Body.String())
	}

	mutation := StateMutation{
		SnapshotID: engine.snapshot.SnapshotID, LogicalMessageID: engine.state.LogicalMessageID,
		OperationID: "jmap-state-2", ExpectedHeads: heads,
		ExpectedHeadsDigest: engine.snapshot.States[0].HeadsDigest,
		ExpectedStateDigest: engine.snapshot.States[0].StateDigest,
		ExpectedHeight:      2, ExpectedRevisionCount: 2, Version: fingerprint,
		MailboxIDs: mailboxIDs, Keywords: []string{"$seen"},
	}
	changed := performRequest(t, handler, "/v3/state/append", stateRequest{Version: ProtocolVersion, Target: target, Mutation: mutation}, "relay-secret")
	var changedBody stateResponse
	decodeResponse(t, changed, &changedBody)
	if changed.Code != http.StatusOK || changedBody.OperationID != mutation.OperationID ||
		!reflect.DeepEqual(engine.gotMutation.ExpectedHeads, heads) ||
		!reflect.DeepEqual(changedBody.State.MailboxIDs, mailboxIDs) {
		t.Fatalf("state append status=%d body=%s mutation=%#v", changed.Code, changed.Body.String(), engine.gotMutation)
	}
}

func TestHandlerRejectsUnauthorizedUnknownJSONAndWrongAuthorityBinding(t *testing.T) {
	target := testTarget()
	engine := &fakeEngine{capabilities: fullCapabilities(target)}
	handler := mustHandler(t, Config{Token: "relay-secret", Target: target, Engine: engine})

	unauthorized := performRequest(t, handler, "/v3/capabilities", capabilityRequest{Version: ProtocolVersion, Target: target}, "wrong")
	if unauthorized.Code != http.StatusUnauthorized || engine.capabilityCalls != 0 {
		t.Fatalf("unauthorized status=%d calls=%d", unauthorized.Code, engine.capabilityCalls)
	}

	unknown := performRawRequest(t, handler, "/v3/capabilities", []byte(`{"version":3,"target":{},"unexpected":true}`), "relay-secret")
	if unknown.Code != http.StatusBadRequest || engine.capabilityCalls != 0 {
		t.Fatalf("unknown field status=%d calls=%d", unknown.Code, engine.capabilityCalls)
	}

	wrong := target
	wrong.AuthorityCertificateGeneration = "legacy-v2"
	misbound := performRequest(t, handler, "/v3/capabilities", capabilityRequest{Version: ProtocolVersion, Target: wrong}, "relay-secret")
	if misbound.Code != http.StatusBadRequest || engine.capabilityCalls != 0 {
		t.Fatalf("misbound status=%d calls=%d", misbound.Code, engine.capabilityCalls)
	}
}

func TestHandlerMapsOnlyAppendConflictTo409(t *testing.T) {
	target := testTarget()
	engine := &fakeEngine{appendErr: ErrConflict}
	handler := mustHandler(t, Config{Token: "relay-secret", Target: target, Engine: engine})
	expectedHeads := []string{"state-" + strings.Repeat("3", 64)}
	mutation := StateMutation{
		SnapshotID: "sha256-" + strings.Repeat("1", 64), LogicalMessageID: "sha256-" + strings.Repeat("2", 64),
		OperationID: "op", ExpectedHeads: expectedHeads,
		ExpectedHeadsDigest: headsDigest("comail-message-state-heads-v1\x00", expectedHeads), ExpectedStateDigest: "sha256-" + strings.Repeat("5", 64),
		ExpectedHeight: 1, ExpectedRevisionCount: 1, Version: "sha256-" + strings.Repeat("6", 64),
		MailboxIDs: []string{"folder-" + strings.Repeat("7", 64)}, Keywords: []string{},
	}
	response := performRequest(t, handler, "/v3/state/append", stateRequest{Version: ProtocolVersion, Target: target, Mutation: mutation}, "relay-secret")
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

type fakeEngine struct {
	capabilities    Capabilities
	receipt         Receipt
	snapshot        Snapshot
	state           MessageState
	appendErr       error
	capabilityCalls int
	gotStore        StoreInput
	gotMutation     StateMutation
}

func (engine *fakeEngine) Capabilities(context.Context) (Capabilities, error) {
	engine.capabilityCalls++
	return engine.capabilities, nil
}

func (engine *fakeEngine) Store(_ context.Context, input StoreInput) (Receipt, error) {
	engine.gotStore = input
	return engine.receipt, nil
}

func (engine *fakeEngine) Snapshot(context.Context) (Snapshot, error) { return engine.snapshot, nil }

func (engine *fakeEngine) AppendState(_ context.Context, mutation StateMutation) (MessageState, error) {
	engine.gotMutation = mutation
	if engine.appendErr != nil {
		return MessageState{}, engine.appendErr
	}
	return engine.state, nil
}

func testTarget() Target {
	return Target{
		ProviderID: "official-spaces-alpha", Origin: "https://spaces-alpha.host.bsky.network",
		SpaceURI: "at://did:plc:spaceauthority/space/email.atmos.mailbox/primary",
		RepoDID:  "did:plc:mailboxmember", Epoch: "commit-epoch-1",
		AuthorityCertificateSHA256:     strings.Repeat("a", 64),
		AuthorityCertificateGeneration: AuthorityGeneration,
	}
}

func fullCapabilities(target Target) Capabilities {
	return Capabilities{
		PrivateRecords: true, ReferencedBlobs: true, AtomicCreateBatch: true,
		IdempotentOperationClaims: true, AuthenticatedStableRead: true, CompleteInventory: true,
		ConcurrentHeads: true, Tombstones: true, SourceVersioning: true,
		AuthorityCertificateSHA256: target.AuthorityCertificateSHA256, AuthorityGeneration: AuthorityGeneration,
	}
}

func testFolders(target Target, snapshotID, customFolderID string) []FolderState {
	roles := []struct {
		role string
		name string
	}{
		{role: "archive", name: "Archive"}, {role: "drafts", name: "Drafts"},
		{role: "important", name: "Important"}, {role: "inbox", name: "Inbox"},
		{role: "junk", name: "Junk"}, {role: "sent", name: "Sent"}, {role: "trash", name: "Trash"},
	}
	folders := make([]FolderState, 0, len(roles)+1)
	for index, role := range roles {
		folder := FolderState{
			FolderID: standardFolderID(target.RepoDID, role.role), SnapshotID: snapshotID,
			Name: role.name, Role: role.role,
			Heads:  []string{"folder-state-" + strings.Repeat(string(rune('1'+index)), 64)},
			Height: 1, RevisionCount: 1,
		}
		folder.HeadsDigest = headsDigest("comail-folder-state-heads-v1\x00", folder.Heads)
		folder.StateDigest = folderStateDigest(folder)
		folders = append(folders, folder)
	}
	custom := FolderState{
		FolderID: customFolderID, SnapshotID: snapshotID, Name: "Project",
		Heads: []string{"folder-state-" + strings.Repeat("a", 64)}, Height: 1, RevisionCount: 1,
	}
	custom.HeadsDigest = headsDigest("comail-folder-state-heads-v1\x00", custom.Heads)
	custom.StateDigest = folderStateDigest(custom)
	return append(folders, custom)
}

func mustHandler(t *testing.T, config Config) http.Handler {
	t.Helper()
	handler, err := NewHandler(config)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func performRequest(t *testing.T, handler http.Handler, path string, body any, token string) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return performRawRequest(t, handler, path, encoded, token)
}

func performRawRequest(t *testing.T, handler http.Handler, path string, body []byte, token string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func decodeResponse(t *testing.T, response *httptest.ResponseRecorder, output any) {
	t.Helper()
	if err := json.Unmarshal(response.Body.Bytes(), output); err != nil {
		t.Fatalf("decode response: %v body=%s", err, response.Body.String())
	}
}

func TestEncodeBoundedSnapshotJSONCountsWholeResponseBeforeWriting(t *testing.T) {
	target, snapshot := validLimitSnapshot()
	full := snapshotResponse{
		Version: ProtocolVersion, ProviderID: target.ProviderID,
		Target: target, Snapshot: snapshot,
	}
	nilInventories := full
	nilInventories.Snapshot.Messages = nil
	nilInventories.Snapshot.States = nil
	for name, value := range map[string]snapshotResponse{
		"full":            full,
		"nil inventories": nilInventories,
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := encodeBoundedSnapshotJSON(value, len(raw)+1)
			if err != nil {
				t.Fatal(err)
			}
			var got bytes.Buffer
			if err := encoded.writeTo(&got); err != nil {
				t.Fatal(err)
			}
			if encoded.size != len(raw)+1 || got.Len() != len(raw)+1 || got.Bytes()[got.Len()-1] != '\n' {
				t.Fatalf("encoded=%q size=%d err=%v", got.Bytes(), encoded.size, err)
			}
			if !bytes.Equal(got.Bytes()[:got.Len()-1], raw) {
				t.Fatalf("bounded encoding drifted from encoding/json\ngot:  %s\nwant: %s", got.Bytes(), raw)
			}
			if _, err := encodeBoundedSnapshotJSON(value, len(raw)); err == nil {
				t.Fatal("whole-response transport cap accepted an oversized JSON payload")
			}
		})
	}
}

var _ Engine = (*fakeEngine)(nil)
