package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/comail-atproto/comail-space-host/internal/mailbox"
	"github.com/comail-atproto/comail-space-host/internal/mailboxstate"
	"github.com/comail-atproto/comail-space-host/internal/oauthclient"
	"github.com/comail-atproto/comail-space-host/internal/projection"
	"github.com/comail-atproto/comail-space-host/internal/providers/officialspaces"
	"github.com/comail-atproto/comail-space-host/internal/repository"
	"github.com/comail-atproto/comail-space-host/internal/spacecredential"
)

const (
	messageCount = 99
	spaceKey     = "mailbox-validation-proof"
	fixedTime    = "2026-08-21T00:00:00Z"
)

type accountFile struct {
	DID       string `json:"did"`
	AccessJWT string `json:"accessJwt"`
}

type expectedRecord struct {
	collection string
	rkey       string
	value      json.RawMessage
}

type expectedMailbox struct {
	records     []expectedRecord
	folderID    string
	folderClaim mailboxstate.FolderOperationClaim
}

type counts struct {
	Messages               int `json:"messages"`
	MessageStateRevisions  int `json:"messageStateRevisions"`
	MessageStateOperations int `json:"messageStateOperations"`
	FolderRevisions        int `json:"folderRevisions"`
	FolderOperations       int `json:"folderOperations"`
}

type prepareReport struct {
	Captured int `json:"captured"`
	Skipped  int `json:"skipped"`
	Verified int `json:"verified"`
}

type proofOutput struct {
	Mode                          string        `json:"mode"`
	SourceMessages                int           `json:"sourceMessages"`
	First                         prepareReport `json:"first"`
	Second                        prepareReport `json:"second"`
	Inventory                     counts        `json:"inventory"`
	ValidReceipts                 int           `json:"validReceipts"`
	SchemaValidationAttempted     bool          `json:"schemaValidationAttempted"`
	InvalidKnownSchemaRejected    bool          `json:"invalidKnownSchemaRejected"`
	UnknownSchemaRejected         bool          `json:"unknownSchemaRejected"`
	AtomicRollbackVerified        bool          `json:"atomicRollbackVerified"`
	SpaceCredentialIssued         bool          `json:"spaceCredentialIssued"`
	DPoPReadVerified              bool          `json:"dpopReadVerified"`
	SourceAuthenticatedRecovery   bool          `json:"sourceAuthenticatedRecovery"`
	RecoveredMessages             int           `json:"recoveredMessages"`
	RecoveredFolders              int           `json:"recoveredFolders"`
	RecoveredStates               int           `json:"recoveredStates"`
	FreshProjectionRebuild        bool          `json:"freshProjectionRebuild"`
	ProjectionManifestsEqual      bool          `json:"projectionManifestsEqual"`
	ProjectionManifestSHA256      string        `json:"projectionManifestSHA256"`
	ProjectionMode0600            bool          `json:"projectionMode0600"`
	AuthorityCertified            bool          `json:"authorityCertified"`
	HostedBlueskyAcceptance       bool          `json:"hostedBlueskyAcceptance"`
	ActivationAttempted           bool          `json:"activationAttempted"`
	UnmodifiedBaseRejectsStrict   bool          `json:"unmodifiedBaseRejectsStrictSchemas"`
	UnmodifiedBaseCommittedRecord bool          `json:"unmodifiedBaseCommittedRecord"`
}

func main() {
	var mode, origin, plcOrigin, accountPath, projectionDirectory string
	flag.StringVar(&mode, "mode", "full", "base-rejection, full, or recovery-only")
	flag.StringVar(&origin, "origin", "http://127.0.0.1:2583", "exact disposable PDS origin")
	flag.StringVar(&plcOrigin, "plc-origin", "http://127.0.0.1:3001", "exact disposable PLC origin")
	flag.StringVar(&accountPath, "account-file", "/tmp/account.json", "synthetic account response")
	flag.StringVar(&projectionDirectory, "projection-dir", "/tmp", "new disposable projection directory")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	account, err := readAccount(accountPath)
	if err != nil {
		fatal(err)
	}
	if err := ensureSpace(ctx, origin, account); err != nil {
		fatal(err)
	}
	if mode == "base-rejection" {
		output, err := proveBaseRejection(ctx, origin, account)
		if err != nil {
			fatal(err)
		}
		writeOutput(output)
		return
	}
	if mode != "full" && mode != "recovery-only" {
		fatal(errors.New("unsupported proof mode"))
	}

	client, err := newOfficialClient(ctx, origin, plcOrigin, account)
	if err != nil {
		fatal(err)
	}
	var output proofOutput
	if mode == "full" {
		output, err = proveFull(ctx, client, origin, account, projectionDirectory)
	} else {
		output, err = proveRecovery(ctx, client, account.DID, projectionDirectory, mode)
	}
	if err != nil {
		fatal(err)
	}
	writeOutput(output)
}

func proveBaseRejection(ctx context.Context, origin string, account accountFile) (proofOutput, error) {
	folderID := "folder-" + strings.Repeat("a", 64)
	rkey := "folder-operation-" + strings.Repeat("b", 64)
	value := map[string]any{
		"$type": mailbox.FolderOperationCollection, "folderId": folderID,
		"operationId": "base-rejection", "revisionRkey": "folder-state-" + strings.Repeat("c", 64),
	}
	response, err := applyRaw(ctx, origin, account, true, []map[string]any{createWrite(mailbox.FolderOperationCollection, rkey, value)})
	if err != nil {
		return proofOutput{}, err
	}
	if response.Status != http.StatusBadRequest || response.Error != "InvalidRequest" || !strings.Contains(response.Message, mailbox.FolderOperationCollection) {
		return proofOutput{}, errors.New("unmodified alpha did not fail closed for strict third-party schema")
	}
	committed, err := rawRecordExists(ctx, origin, account, mailbox.FolderOperationCollection, rkey)
	if err != nil {
		return proofOutput{}, err
	}
	if committed {
		return proofOutput{}, errors.New("unmodified alpha committed a rejected strict record")
	}
	return proofOutput{
		Mode: "base-rejection", SchemaValidationAttempted: true,
		UnmodifiedBaseRejectsStrict: true, UnmodifiedBaseCommittedRecord: false,
		AuthorityCertified: false, HostedBlueskyAcceptance: false, ActivationAttempted: false,
	}, nil
}

func proveFull(ctx context.Context, client *officialspaces.Client, origin string, account accountFile, projectionDirectory string) (proofOutput, error) {
	expected, receipts, err := writeSyntheticMailbox(ctx, client, account.DID)
	if err != nil {
		return proofOutput{}, err
	}
	second, inventory, err := verifyExpectedInventory(ctx, client, expected)
	if err != nil {
		return proofOutput{}, err
	}
	invalidRejected, err := proveInvalidKnownSchema(ctx, origin, account)
	if err != nil {
		return proofOutput{}, err
	}
	unknownRejected, err := proveUnknownSchema(ctx, origin, account)
	if err != nil {
		return proofOutput{}, err
	}
	atomic, err := proveAtomicRollback(ctx, client, account.DID, expected)
	if err != nil {
		return proofOutput{}, err
	}
	recovery, err := proveRecovery(ctx, client, account.DID, projectionDirectory, "full")
	if err != nil {
		return proofOutput{}, err
	}
	recovery.First = prepareReport{Captured: messageCount, Verified: messageCount}
	recovery.Second = second
	recovery.Inventory = inventory
	recovery.ValidReceipts = receipts
	recovery.SchemaValidationAttempted = true
	recovery.InvalidKnownSchemaRejected = invalidRejected
	recovery.UnknownSchemaRejected = unknownRejected
	recovery.AtomicRollbackVerified = atomic
	return recovery, nil
}

func writeSyntheticMailbox(ctx context.Context, client *officialspaces.Client, repoDID string) (expectedMailbox, int, error) {
	standardFolders := []struct{ role, name string }{
		{role: "archive", name: "Archive"},
		{role: "drafts", name: "Drafts"},
		{role: "important", name: "Important"},
		{role: "inbox", name: "Inbox"},
		{role: "junk", name: "Junk"},
		{role: "sent", name: "Sent"},
		{role: "trash", name: "Trash"},
	}
	expected := expectedMailbox{}
	creates := make([]officialspaces.Create, 0, len(standardFolders)*2)
	for _, standard := range standardFolders {
		folderID, err := mailboxstate.StandardFolderID(repoDID, standard.role)
		if err != nil {
			return expectedMailbox{}, 0, err
		}
		folder := mailboxstate.FolderStateRevision{Record: mailboxstate.FolderRevisionRecord{
			Type: mailbox.FolderRevisionCollection, FolderID: folderID, OperationID: "initial",
			Parents: []string{}, Revision: 1, Name: standard.name, Role: standard.role, CreatedAt: fixedTime,
		}}
		folder.RKey, err = mailboxstate.FolderRevisionRKey(repoDID, folder.Record)
		if err != nil {
			return expectedMailbox{}, 0, err
		}
		claim, err := mailboxstate.NewFolderOperationClaim(repoDID, folder)
		if err != nil {
			return expectedMailbox{}, 0, err
		}
		folderValue, _ := json.Marshal(folder.Record)
		claimValue, _ := json.Marshal(claim.Record)
		creates = append(creates,
			officialspaces.Create{Collection: mailbox.FolderRevisionCollection, RKey: folder.RKey, Value: folderValue},
			officialspaces.Create{Collection: mailbox.FolderOperationCollection, RKey: claim.RKey, Value: claimValue},
		)
		if standard.role == "inbox" {
			expected.folderID = folderID
			expected.folderClaim = claim
		}
	}
	results, err := client.CreateBatch(ctx, creates)
	if err != nil || len(results) != len(creates) {
		return expectedMailbox{}, 0, fmt.Errorf("create validated standard folder set: %w", err)
	}
	for _, create := range creates {
		expected.records = append(expected.records, expectedRecord{collection: create.Collection, rkey: create.RKey, value: create.Value})
	}
	receipts := len(results)
	for index := 0; index < messageCount; index++ {
		raw, sourceKey, messageID := syntheticMessage(index)
		blob, err := client.UploadMessageBlob(ctx, raw)
		if err != nil {
			return expectedMailbox{}, 0, fmt.Errorf("upload synthetic message %d: %w", index, err)
		}
		pair, err := mailbox.NewMessagePair(mailbox.ImportedMessage{
			RecipientDID: repoDID, SourceKey: sourceKey, Raw: raw, Mailbox: "Inbox",
			MessageID: messageID, DeliveredAt: time.Date(2026, 8, 21, 0, 0, index, 0, time.UTC),
		}, blob)
		if err != nil {
			return expectedMailbox{}, 0, err
		}
		state := mailboxstate.StateRevision{Record: mailboxstate.RevisionRecord{
			Type: mailbox.MessageStateRevisionCollection, LogicalMessageID: pair.Message.LogicalMessageID,
			OperationID: "initial", Parents: []string{}, Revision: 1, Version: pair.RKey,
			MailboxIDs: []string{expected.folderID}, Keywords: []mailboxstate.KeywordAssignment{}, CreatedAt: fixedTime,
		}}
		state.RKey, err = mailboxstate.StateRevisionRKey(repoDID, state.Record)
		if err != nil {
			return expectedMailbox{}, 0, err
		}
		claim, err := mailboxstate.NewOperationClaim(repoDID, state)
		if err != nil {
			return expectedMailbox{}, 0, err
		}
		messageValue, _ := json.Marshal(pair.Message)
		stateValue, _ := json.Marshal(state.Record)
		claimValue, _ := json.Marshal(claim.Record)
		batch := []officialspaces.Create{
			{Collection: mailbox.MessageCollection, RKey: pair.RKey, Value: messageValue},
			{Collection: mailbox.MessageStateRevisionCollection, RKey: state.RKey, Value: stateValue},
			{Collection: mailbox.MessageStateOperationCollection, RKey: claim.RKey, Value: claimValue},
		}
		results, err := client.CreateBatch(ctx, batch)
		if err != nil || len(results) != len(batch) {
			return expectedMailbox{}, 0, fmt.Errorf("create validated synthetic message %d: %w", index, err)
		}
		receipts += len(results)
		for _, create := range batch {
			expected.records = append(expected.records, expectedRecord{collection: create.Collection, rkey: create.RKey, value: create.Value})
		}
	}
	return expected, receipts, nil
}

func verifyExpectedInventory(ctx context.Context, client *officialspaces.Client, expected expectedMailbox) (prepareReport, counts, error) {
	byCollection := make(map[string]map[string]json.RawMessage)
	var inventory counts
	for _, collection := range []string{
		mailbox.MessageCollection, mailbox.MessageStateRevisionCollection,
		mailbox.MessageStateOperationCollection, mailbox.FolderRevisionCollection,
		mailbox.FolderOperationCollection,
	} {
		records, err := client.InspectRecords(ctx, collection, false)
		if err != nil {
			return prepareReport{}, counts{}, err
		}
		items := make(map[string]json.RawMessage, len(records))
		for _, record := range records {
			items[record.RKey] = record.Value
		}
		byCollection[collection] = items
		switch collection {
		case mailbox.MessageCollection:
			inventory.Messages = len(records)
		case mailbox.MessageStateRevisionCollection:
			inventory.MessageStateRevisions = len(records)
		case mailbox.MessageStateOperationCollection:
			inventory.MessageStateOperations = len(records)
		case mailbox.FolderRevisionCollection:
			inventory.FolderRevisions = len(records)
		case mailbox.FolderOperationCollection:
			inventory.FolderOperations = len(records)
		}
	}
	for _, record := range expected.records {
		stored, ok := byCollection[record.collection][record.rkey]
		if !ok || !equalJSON(stored, record.value) {
			return prepareReport{}, counts{}, errors.New("authenticated inventory differed from the expected immutable record graph")
		}
	}
	if inventory != (counts{Messages: messageCount, MessageStateRevisions: messageCount, MessageStateOperations: messageCount, FolderRevisions: 7, FolderOperations: 7}) {
		return prepareReport{}, counts{}, fmt.Errorf("unexpected exact five-collection inventory: %#v", inventory)
	}
	return prepareReport{Captured: 0, Skipped: messageCount, Verified: messageCount}, inventory, nil
}

func proveInvalidKnownSchema(ctx context.Context, origin string, account accountFile) (bool, error) {
	rkey := "invalid-known-schema"
	value := map[string]any{
		"$type":    mailbox.FolderOperationCollection,
		"folderId": "folder-" + strings.Repeat("d", 64), "operationId": "invalid",
	}
	response, err := applyRaw(ctx, origin, account, true, []map[string]any{createWrite(mailbox.FolderOperationCollection, rkey, value)})
	if err != nil {
		return false, err
	}
	if response.Status != http.StatusBadRequest || response.Error != "InvalidRequest" || !strings.Contains(response.Message, mailbox.FolderOperationCollection) {
		return false, errors.New("invalid known-schema record did not fail closed")
	}
	exists, err := rawRecordExists(ctx, origin, account, mailbox.FolderOperationCollection, rkey)
	return !exists, err
}

func proveUnknownSchema(ctx context.Context, origin string, account accountFile) (bool, error) {
	const collection = "com.example.comailUnknown"
	const rkey = "unknown-schema"
	response, err := applyRaw(ctx, origin, account, true, []map[string]any{createWrite(collection, rkey, map[string]any{"$type": collection, "value": true})})
	if err != nil {
		return false, err
	}
	if response.Status != http.StatusBadRequest || response.Error != "InvalidRequest" || !strings.Contains(response.Message, collection) {
		return false, errors.New("unknown schema did not fail closed")
	}
	exists, err := rawRecordExists(ctx, origin, account, collection, rkey)
	return !exists, err
}

func proveAtomicRollback(ctx context.Context, client *officialspaces.Client, repoDID string, expected expectedMailbox) (bool, error) {
	probeID := "folder-" + strings.Repeat("e", 64)
	probe := mailboxstate.FolderStateRevision{Record: mailboxstate.FolderRevisionRecord{
		Type: mailbox.FolderRevisionCollection, FolderID: probeID, OperationID: "atomic-probe",
		Parents: []string{}, Revision: 1, Name: "Must Not Commit", CreatedAt: fixedTime,
	}}
	var err error
	probe.RKey, err = mailboxstate.FolderRevisionRKey(repoDID, probe.Record)
	if err != nil {
		return false, err
	}
	probeValue, _ := json.Marshal(probe.Record)
	existingClaim, _ := json.Marshal(expected.folderClaim.Record)
	_, err = client.CreateBatch(ctx, []officialspaces.Create{
		{Collection: mailbox.FolderRevisionCollection, RKey: probe.RKey, Value: probeValue},
		{Collection: mailbox.FolderOperationCollection, RKey: expected.folderClaim.RKey, Value: existingClaim},
	})
	if !errors.Is(err, repository.ErrExists) {
		return false, fmt.Errorf("atomic rollback batch returned the wrong failure: %w", err)
	}
	_, err = client.InspectRecord(ctx, mailbox.FolderRevisionCollection, probe.RKey)
	if err == nil {
		return false, errors.New("failed batch committed its valid first create")
	}
	if !errors.Is(err, repository.ErrNotFound) {
		return false, fmt.Errorf("atomic rollback probe read returned the wrong failure: %w", err)
	}
	return true, nil
}

func proveRecovery(ctx context.Context, client *officialspaces.Client, repoDID, projectionDirectory, mode string) (proofOutput, error) {
	sourceSnapshot, err := client.ReadSourceAuthenticatedRepository(ctx)
	if err != nil {
		return proofOutput{}, fmt.Errorf("source-authenticated CAR preflight: %w", err)
	}
	reducedSnapshot, err := mailboxstate.ReduceOfficialSpacesSource(ctx, sourceSnapshot)
	if err != nil {
		return proofOutput{}, fmt.Errorf("five-collection reduction preflight: %w", err)
	}
	if len(reducedSnapshot.Messages()) != messageCount || len(reducedSnapshot.Folders()) != 7 || len(reducedSnapshot.MessageStates()) != messageCount {
		return proofOutput{}, errors.New("five-collection reduction preflight returned unexpected counts")
	}

	source, err := mailboxstate.ReadOfficialSpacesRecoverySource(ctx, client)
	if err != nil {
		return proofOutput{}, err
	}
	defer source.Close()
	summary := source.Summary()
	folders := source.Folders()
	states := source.MessageStates()
	if summary.MessageVersions != messageCount || len(folders) != 7 || len(states) != messageCount {
		return proofOutput{}, errors.New("reduced recovery inventory did not match the exact synthetic mailbox")
	}
	verified := 0
	err = source.VisitMessages(ctx, func(message mailboxstate.ContentVerifiedMessage) error {
		version, raw, err := message.Open()
		if err != nil {
			return err
		}
		defer clear(raw)
		if mailbox.RawSHA256(raw) != version.Record.SHA256 || version.Record.LogicalMessageID == "" {
			return mailbox.ErrIntegrity
		}
		verified++
		return nil
	})
	if err != nil || verified != messageCount || source.ValidateSeal() != nil {
		return proofOutput{}, errors.New("byte-complete sealed recovery visitation failed")
	}
	firstPath := filepath.Join(projectionDirectory, "official-v3-projection-a.sqlite")
	secondPath := filepath.Join(projectionDirectory, "official-v3-projection-b.sqlite")
	first, err := projection.RebuildOfficial(ctx, source, firstPath)
	if err != nil {
		return proofOutput{}, err
	}
	second, err := projection.RebuildOfficial(ctx, source, secondPath)
	if err != nil {
		return proofOutput{}, err
	}
	firstInfo, firstErr := os.Stat(firstPath)
	secondInfo, secondErr := os.Stat(secondPath)
	mode0600 := firstErr == nil && secondErr == nil && firstInfo.Mode().Perm() == 0o600 && secondInfo.Mode().Perm() == 0o600
	if !first.Passed() || !second.Passed() || first.ManifestSHA256 != second.ManifestSHA256 || !mode0600 {
		return proofOutput{}, errors.New("two fresh official v3 projections were not semantically identical and private")
	}
	return proofOutput{
		Mode: mode, SourceMessages: messageCount,
		SpaceCredentialIssued: true, DPoPReadVerified: true, SourceAuthenticatedRecovery: true,
		RecoveredMessages: summary.MessageVersions, RecoveredFolders: len(folders), RecoveredStates: len(states),
		FreshProjectionRebuild: true, ProjectionManifestsEqual: true,
		ProjectionManifestSHA256: first.ManifestSHA256, ProjectionMode0600: true,
		AuthorityCertified: false, HostedBlueskyAcceptance: false, ActivationAttempted: false,
	}, nil
}

func newOfficialClient(ctx context.Context, origin, plcOrigin string, account accountFile) (*officialspaces.Client, error) {
	resolver, err := spacecredential.NewPLCSigningKeyResolver(plcOrigin, true)
	if err != nil {
		return nil, err
	}
	spaceURI := fmt.Sprintf("at://%s/space/%s/%s", account.DID, mailbox.MailboxSpaceType, spaceKey)
	exchanger, err := spacecredential.New(spacecredential.Config{
		SpaceURI: spaceURI, SpaceHostOrigin: origin, SigningKeys: resolver,
		AllowHTTP: true, AppAccess: spacecredential.AppAccessOpen,
	})
	if err != nil {
		return nil, err
	}
	writer := &bearerWriterSource{origin: origin, token: account.AccessJWT}
	delegations := &bearerDelegationSource{origin: origin, token: account.AccessJWT, spaceURI: spaceURI}
	preflight, err := exchanger.Acquire(ctx, delegations)
	if err != nil {
		return nil, fmt.Errorf("DPoP credential preflight: %w", err)
	}
	preflight.Close()
	reader := &credentialReaderSource{exchanger: exchanger, delegations: delegations}
	return officialspaces.New(officialspaces.Config{
		Origin: origin, SpaceAuthorityDID: account.DID, RepoDID: account.DID,
		SpaceKey: spaceKey, Epoch: officialspaces.PinnedEpoch, AllowHTTP: true,
		RepoSigningKeys: resolver,
	}, writer, reader)
}

type bearerWriterSource struct {
	origin string
	token  string
}

func (s *bearerWriterSource) AcquireWriter(context.Context, officialspaces.Target) (officialspaces.ScopedDoer, error) {
	if s == nil || s.token == "" {
		return nil, errors.New("synthetic bearer is unavailable")
	}
	return newBearerDoer(s.origin, s.token)
}

type credentialReaderSource struct {
	exchanger   *spacecredential.Exchanger
	delegations *bearerDelegationSource
}

func (s *credentialReaderSource) AcquireReader(ctx context.Context, _ officialspaces.Target) (officialspaces.ScopedDoer, error) {
	return s.exchanger.Acquire(ctx, s.delegations)
}

type bearerDelegationSource struct {
	origin   string
	token    string
	spaceURI string
}

func (s *bearerDelegationSource) WithDelegation(ctx context.Context, exchange func(string) error) error {
	doer, err := newBearerDoer(s.origin, s.token)
	if err != nil {
		return err
	}
	defer doer.Close()
	target := s.origin + "/xrpc/com.atproto.space.getDelegationToken?space=" + url.QueryEscape(s.spaceURI)
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	request.Header.Set("Accept", "application/json")
	response, err := doer.Do(ctx, request, "com.atproto.space.getDelegationToken")
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("delegation failed with HTTP %d", response.StatusCode)
	}
	var output struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 16*1024)).Decode(&output); err != nil || output.Token == "" {
		return errors.New("delegation response was invalid")
	}
	return exchange(output.Token)
}

type bearerDoer struct {
	origin string
	token  string
	client *http.Client
}

func newBearerDoer(origin, token string) (*bearerDoer, error) {
	client, cleanOrigin, err := oauthclient.NewPinnedHTTPClient(origin, true)
	if err != nil || cleanOrigin != origin || token == "" {
		return nil, errors.New("synthetic bearer target is not an exact pinned origin")
	}
	return &bearerDoer{
		origin: origin, token: token,
		client: client,
	}, nil
}

func (d *bearerDoer) Do(ctx context.Context, request *http.Request, endpoint string) (*http.Response, error) {
	if d == nil || d.token == "" || request == nil || request.URL == nil ||
		request.URL.Scheme+"://"+request.URL.Host != d.origin || request.URL.EscapedPath() != "/xrpc/"+endpoint {
		return nil, errors.New("synthetic bearer request target mismatch")
	}
	attempt := request.Clone(ctx)
	attempt.Header = request.Header.Clone()
	attempt.Header.Set("Authorization", "Bearer "+d.token)
	return d.client.Do(attempt)
}

func (d *bearerDoer) Close() {
	if d != nil {
		d.token = ""
		d.client.CloseIdleConnections()
	}
}

func ensureSpace(ctx context.Context, origin string, account accountFile) error {
	body := map[string]any{
		"type": mailbox.MailboxSpaceType, "skey": spaceKey,
		"policy":    map[string]any{"$type": "com.atproto.simplespace.defs#memberListPolicy"},
		"appAccess": map[string]any{"$type": "com.atproto.simplespace.defs#open"},
	}
	status, output, err := rawXRPC(ctx, origin, account.AccessJWT, http.MethodPost, "com.atproto.simplespace.createSpace", nil, body)
	if err != nil {
		return err
	}
	if status == http.StatusOK {
		if output["uri"] != fmt.Sprintf("at://%s/space/%s/%s", account.DID, mailbox.MailboxSpaceType, spaceKey) {
			return errors.New("createSpace returned the wrong URI")
		}
		return nil
	}
	if output["error"] != "SpaceAlreadyExists" {
		return fmt.Errorf("createSpace failed with HTTP %d", status)
	}
	return nil
}

type rawApplyResponse struct {
	Status  int
	Error   string
	Message string
	Results []struct {
		ValidationStatus string `json:"validationStatus"`
	} `json:"results"`
}

func applyRaw(ctx context.Context, origin string, account accountFile, validate bool, writes []map[string]any) (rawApplyResponse, error) {
	status, output, err := rawXRPC(ctx, origin, account.AccessJWT, http.MethodPost, "com.atproto.space.applyWrites", nil, map[string]any{
		"space": fmt.Sprintf("at://%s/space/%s/%s", account.DID, mailbox.MailboxSpaceType, spaceKey),
		"repo":  account.DID, "validate": validate, "writes": writes,
	})
	if err != nil {
		return rawApplyResponse{}, err
	}
	encoded, _ := json.Marshal(output)
	var response rawApplyResponse
	_ = json.Unmarshal(encoded, &response)
	response.Status = status
	response.Error, _ = output["error"].(string)
	response.Message, _ = output["message"].(string)
	return response, nil
}

func createWrite(collection, rkey string, value any) map[string]any {
	return map[string]any{
		"$type":      "com.atproto.space.applyWrites#create",
		"collection": collection, "rkey": rkey, "value": value,
	}
}

func rawRecordExists(ctx context.Context, origin string, account accountFile, collection, rkey string) (bool, error) {
	query := url.Values{
		"space": {fmt.Sprintf("at://%s/space/%s/%s", account.DID, mailbox.MailboxSpaceType, spaceKey)},
		"repo":  {account.DID}, "collection": {collection}, "rkey": {rkey},
	}
	status, output, err := rawXRPC(ctx, origin, account.AccessJWT, http.MethodGet, "com.atproto.space.getRecord", query, nil)
	if err != nil {
		return false, err
	}
	if status == http.StatusOK {
		return true, nil
	}
	if (status == http.StatusBadRequest || status == http.StatusNotFound) && output["error"] == "RecordNotFound" {
		return false, nil
	}
	return false, fmt.Errorf("getRecord returned HTTP %d", status)
}

func rawXRPC(ctx context.Context, origin, token, method, endpoint string, query url.Values, body any) (int, map[string]any, error) {
	target := origin + "/xrpc/" + endpoint
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	var input io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		input = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, target, input)
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	client, cleanOrigin, err := oauthclient.NewPinnedHTTPClient(origin, true)
	if err != nil || cleanOrigin != origin {
		return 0, nil, errors.New("raw XRPC target is not an exact pinned origin")
	}
	defer client.CloseIdleConnections()
	response, err := client.Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	var output map[string]any
	if err := json.NewDecoder(io.LimitReader(response.Body, 2<<20)).Decode(&output); err != nil {
		return 0, nil, err
	}
	return response.StatusCode, output, nil
}

func readAccount(path string) (accountFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return accountFile{}, err
	}
	var account accountFile
	if err := json.Unmarshal(data, &account); err != nil || !strings.HasPrefix(account.DID, "did:plc:") || account.AccessJWT == "" {
		return accountFile{}, errors.New("synthetic account file was invalid")
	}
	return account, nil
}

func syntheticMessage(index int) ([]byte, string, string) {
	serial := fmt.Sprintf("%03d", index+1)
	sourceKey := "synthetic-" + serial
	messageID := "comail-alpha-" + serial + "@synthetic.invalid"
	raw := []byte(fmt.Sprintf(
		"Message-ID: <%s>\r\nSubject: Comail alpha proof %s\r\nFrom: sender@synthetic.invalid\r\nTo: recipient@synthetic.invalid\r\n\r\nDisposable synthetic message %s.\r\n",
		messageID, serial, serial,
	))
	return raw, sourceKey, messageID
}

func equalJSON(left, right []byte) bool {
	var leftValue, rightValue any
	leftDecoder := json.NewDecoder(bytes.NewReader(left))
	leftDecoder.UseNumber()
	rightDecoder := json.NewDecoder(bytes.NewReader(right))
	rightDecoder.UseNumber()
	return leftDecoder.Decode(&leftValue) == nil && rightDecoder.Decode(&rightValue) == nil && reflect.DeepEqual(leftValue, rightValue)
}

func writeOutput(output proofOutput) {
	encoded, err := json.Marshal(output)
	if err != nil {
		fatal(err)
	}
	_, _ = os.Stdout.Write(append(encoded, '\n'))
}

func fatal(err error) {
	// Never print response bodies, record values, tokens, DIDs, rkeys, or CIDs.
	_, _ = fmt.Fprintln(os.Stderr, "official mailbox proof failed:", redactedError(err))
	os.Exit(1)
}

func redactedError(err error) string {
	if err == nil {
		return "unknown error"
	}
	message := err.Error()
	message = regexp.MustCompile(`did:[a-z0-9]+:[A-Za-z0-9._:%-]+`).ReplaceAllString(message, "did:[redacted]")
	message = regexp.MustCompile(`at://[^\s\"']+`).ReplaceAllString(message, "at://[redacted]")
	message = regexp.MustCompile(`(?i)(Bearer|DPoP)\s+[^\s\"']+`).ReplaceAllString(message, "$1 [redacted]")
	if len(message) > 512 {
		return message[:512] + "…"
	}
	return message
}
