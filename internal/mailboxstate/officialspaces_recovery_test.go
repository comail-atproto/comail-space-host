package mailboxstate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/comail-atproto/comail-space-host/internal/mailbox"
	"github.com/comail-atproto/comail-space-host/internal/providers/officialspaces"
	"github.com/ipfs/go-cid"
	"github.com/ipld/go-ipld-prime/codec"
	"github.com/ipld/go-ipld-prime/codec/dagcbor"
	"github.com/ipld/go-ipld-prime/datamodel"
	cidlink "github.com/ipld/go-ipld-prime/linking/cid"
	"github.com/ipld/go-ipld-prime/node/basicnode"
	"github.com/multiformats/go-multihash"
)

func TestReduceOfficialInventoryProducesSealedDeterministicState(t *testing.T) {
	inventory := validOfficialInventory(t)
	first, err := reduceOfficialSpacesInventory(context.Background(), inventory)
	if err != nil {
		t.Fatal(err)
	}
	reversed := inventory
	reversed.records = append([]officialspaces.SourceRecord(nil), inventory.records...)
	for left, right := 0, len(reversed.records)-1; left < right; left, right = left+1, right-1 {
		reversed.records[left], reversed.records[right] = reversed.records[right], reversed.records[left]
	}
	second, err := reduceOfficialSpacesInventory(context.Background(), reversed)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first.Messages(), second.Messages()) ||
		!reflect.DeepEqual(first.MessageStates(), second.MessageStates()) ||
		!reflect.DeepEqual(first.Folders(), second.Folders()) {
		t.Fatal("source record order changed deterministic recovery output")
	}
	if first.SnapshotID() != inventory.snapshotID || first.Revision() != inventory.revision ||
		first.CommitCID() != inventory.commitCID || first.IndexCID() != inventory.indexCID ||
		first.Target() != inventory.target {
		t.Fatalf("source binding was not preserved: %#v", first)
	}
	messages := first.Messages()
	states := first.MessageStates()
	folders := first.Folders()
	if len(messages) != 1 || len(states) != 1 || len(folders) != len(standardFolderRoles) {
		t.Fatalf("messages=%d states=%d folders=%d", len(messages), len(states), len(folders))
	}
	if messages[0].Record.LogicalMessageID != states[0].LogicalMessageID || states[0].Version != messages[0].RKey {
		t.Fatalf("message/state binding mismatch: message=%+v state=%+v", messages[0], states[0])
	}
	if states[0].MailboxIDs[0] != mustStandardFolderID(t, inventory.target.RepoDID, "inbox") {
		t.Fatalf("mailbox IDs=%v", states[0].MailboxIDs)
	}
	for index, folder := range folders {
		if index > 0 && folders[index-1].FolderID >= folder.FolderID {
			t.Fatal("folders are not canonically sorted")
		}
	}
	if err := first.ValidateSeal(); err != nil {
		t.Fatal(err)
	}
	if got := first.String(); got != "mailboxstate.ReducedSourceState(redacted)" || strings.Contains(got, inventory.target.RepoDID) {
		t.Fatalf("unsafe String=%q", got)
	}

	messages[0].Record.References = append(messages[0].Record.References, "mutated")
	states[0].MailboxIDs[0] = "folder-mutated"
	folders[0].Heads[0] = "folder-state-mutated"
	if reflect.DeepEqual(messages, first.Messages()) || reflect.DeepEqual(states, first.MessageStates()) || reflect.DeepEqual(folders, first.Folders()) {
		t.Fatal("recovery output escaped without defensive copies")
	}
	first.messageStates[0].MailboxIDs[0] = "folder-mutated"
	if !errors.Is(first.ValidateSeal(), ErrSourceReduction) || first.Messages() != nil {
		t.Fatal("mutated recovered capability retained validity")
	}
}

func TestReduceOfficialInventoryRejectsIncompleteOrOrphanedRecords(t *testing.T) {
	base := validOfficialInventory(t)
	tests := []struct {
		name   string
		mutate func(*officialSpacesInventory)
	}{
		{
			name: "missing message operation claim",
			mutate: func(input *officialSpacesInventory) {
				input.records = removeSourceCollection(input.records, mailbox.MessageStateOperationCollection, 1)
			},
		},
		{
			name: "missing folder operation claim",
			mutate: func(input *officialSpacesInventory) {
				input.records = removeSourceCollection(input.records, mailbox.FolderOperationCollection, 1)
			},
		},
		{
			name: "extra message operation claim",
			mutate: func(input *officialSpacesInventory) {
				for _, source := range input.records {
					if source.Collection != mailbox.MessageStateOperationCollection {
						continue
					}
					claim, err := decodeOfficialMessageClaim(source.Value)
					if err != nil {
						t.Fatal(err)
					}
					claim.OperationID = "unpaired-operation"
					rkey, err := OperationClaimRKey(input.target.RepoDID, claim.LogicalMessageID, claim.OperationID)
					if err != nil {
						t.Fatal(err)
					}
					input.records = append(input.records, sourceRecord(t, source.Collection, rkey, claim))
					return
				}
				t.Fatal("message claim not found")
			},
		},
		{
			name: "wrong message claim revision",
			mutate: func(input *officialSpacesInventory) {
				for index, source := range input.records {
					if source.Collection != mailbox.MessageStateOperationCollection {
						continue
					}
					claim, err := decodeOfficialMessageClaim(source.Value)
					if err != nil {
						t.Fatal(err)
					}
					claim.RevisionRKey += "x"
					input.records[index] = sourceRecord(t, source.Collection, source.RKey, claim)
					return
				}
				t.Fatal("message claim not found")
			},
		},
		{
			name: "noncanonical message claim key",
			mutate: func(input *officialSpacesInventory) {
				for index, source := range input.records {
					if source.Collection == mailbox.MessageStateOperationCollection {
						input.records[index].RKey += "x"
						return
					}
				}
				t.Fatal("message claim not found")
			},
		},
		{
			name: "orphan immutable version",
			mutate: func(input *officialSpacesInventory) {
				message := sourceMessageRecord(t, input.target.RepoDID, "draft-source", "orphan")
				input.records = append(input.records, sourceRecord(t, mailbox.MessageCollection, message.DeliveryFingerprint, message))
			},
		},
		{
			name: "missing standard folder",
			mutate: func(input *officialSpacesInventory) {
				folderID := mustStandardFolderID(t, input.target.RepoDID, "important")
				input.records = removeSourceRKey(input.records, mailbox.FolderRevisionCollection, folderRevisionKeyForID(t, input.records, folderID))
				input.records = removeFolderClaimForID(t, input.records, folderID)
			},
		},
		{
			name: "duplicate path",
			mutate: func(input *officialSpacesInventory) {
				input.records = append(input.records, input.records[0])
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := base.clone()
			test.mutate(&input)
			if _, err := reduceOfficialSpacesInventory(context.Background(), input); err == nil {
				t.Fatal("expected fail-closed reduction")
			}
		})
	}
}

func TestReduceOfficialInventoryRejectsMessageIntegrityDrift(t *testing.T) {
	base := validOfficialInventory(t)
	tests := []struct {
		name   string
		mutate func(*mailbox.MessageRecord)
	}{
		{name: "wrong logical identity", mutate: func(record *mailbox.MessageRecord) { record.LogicalMessageID = sourceSHA256ID("wrong") }},
		{name: "wrong fingerprint", mutate: func(record *mailbox.MessageRecord) { record.DeliveryFingerprint = sourceSHA256ID("wrong") }},
		{name: "wrong blob codec", mutate: func(record *mailbox.MessageRecord) {
			record.Raw.Ref.Link = sourceDAGCBORCID(t, []byte("not raw")).String()
		}},
		{name: "size mismatch", mutate: func(record *mailbox.MessageRecord) { record.Size++ }},
		{name: "bad lowercase SHA", mutate: func(record *mailbox.MessageRecord) { record.SHA256 = strings.ToUpper(record.SHA256) }},
		{name: "SHA disagrees with blob CID", mutate: func(record *mailbox.MessageRecord) {
			record.SHA256 = hex.EncodeToString(bytes.Repeat([]byte{0x42}, sha256.Size))
		}},
		{name: "bad time", mutate: func(record *mailbox.MessageRecord) { record.DeliveredAt = "yesterday" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := base.clone()
			for index, source := range input.records {
				if source.Collection != mailbox.MessageCollection {
					continue
				}
				message := sourceMessageRecord(t, input.target.RepoDID, "", "message")
				test.mutate(&message)
				input.records[index] = sourceRecord(t, source.Collection, source.RKey, message)
			}
			if _, err := reduceOfficialSpacesInventory(context.Background(), input); err == nil {
				t.Fatal("expected invalid message rejection")
			}
		})
	}
}

func TestReduceOfficialInventorySupportsEmptyMailboxAndMultipleVersions(t *testing.T) {
	empty := validOfficialInventory(t)
	empty.records = removeSourceCollection(empty.records, mailbox.MessageCollection, len(empty.records))
	empty.records = removeSourceCollection(empty.records, MessageStateRevisionCollection, len(empty.records))
	empty.records = removeSourceCollection(empty.records, MessageStateOperationCollection, len(empty.records))
	emptyState, err := reduceOfficialSpacesInventory(context.Background(), empty)
	if err != nil {
		t.Fatal(err)
	}
	if len(emptyState.Messages()) != 0 || len(emptyState.MessageStates()) != 0 || len(emptyState.Folders()) != len(standardFolderRoles) {
		t.Fatalf("empty mailbox messages=%d states=%d folders=%d", len(emptyState.Messages()), len(emptyState.MessageStates()), len(emptyState.Folders()))
	}

	multiple := validOfficialInventory(t)
	multiple.records = removeSourceCollection(multiple.records, mailbox.MessageCollection, len(multiple.records))
	multiple.records = removeSourceCollection(multiple.records, MessageStateRevisionCollection, len(multiple.records))
	multiple.records = removeSourceCollection(multiple.records, MessageStateOperationCollection, len(multiple.records))
	firstMessage := sourceMessageRecord(t, multiple.target.RepoDID, "draft-1", "draft-v1")
	secondMessage := sourceMessageRecord(t, multiple.target.RepoDID, "draft-1", "draft-v2")
	if firstMessage.LogicalMessageID != secondMessage.LogicalMessageID {
		t.Fatal("fixture versions do not share a logical identity")
	}
	root := StateRevision{Record: RevisionRecord{
		Type: MessageStateRevisionCollection, LogicalMessageID: firstMessage.LogicalMessageID,
		OperationID: "draft-create", Parents: []string{}, Revision: 1,
		Version:    firstMessage.DeliveryFingerprint,
		MailboxIDs: []string{mustStandardFolderID(t, multiple.target.RepoDID, "drafts")},
		CreatedAt:  time.Unix(4, 0).UTC().Format(time.RFC3339Nano),
	}}
	root.RKey, err = StateRevisionRKey(multiple.target.RepoDID, root.Record)
	if err != nil {
		t.Fatal(err)
	}
	update := StateRevision{Record: RevisionRecord{
		Type: MessageStateRevisionCollection, LogicalMessageID: firstMessage.LogicalMessageID,
		OperationID: "draft-edit", Parents: []string{root.RKey}, Revision: 2,
		Version:   secondMessage.DeliveryFingerprint,
		CreatedAt: time.Unix(5, 0).UTC().Format(time.RFC3339Nano),
	}}
	update.RKey, err = StateRevisionRKey(multiple.target.RepoDID, update.Record)
	if err != nil {
		t.Fatal(err)
	}
	rootClaim, err := NewOperationClaim(multiple.target.RepoDID, root)
	if err != nil {
		t.Fatal(err)
	}
	updateClaim, err := NewOperationClaim(multiple.target.RepoDID, update)
	if err != nil {
		t.Fatal(err)
	}
	multiple.records = append(multiple.records,
		sourceRecord(t, mailbox.MessageCollection, firstMessage.DeliveryFingerprint, firstMessage),
		sourceRecord(t, mailbox.MessageCollection, secondMessage.DeliveryFingerprint, secondMessage),
		sourceRecord(t, MessageStateRevisionCollection, root.RKey, root.Record),
		sourceRecord(t, MessageStateRevisionCollection, update.RKey, update.Record),
		sourceRecord(t, MessageStateOperationCollection, rootClaim.RKey, rootClaim.Record),
		sourceRecord(t, MessageStateOperationCollection, updateClaim.RKey, updateClaim.Record),
	)
	reduced, err := reduceOfficialSpacesInventory(context.Background(), multiple)
	if err != nil {
		t.Fatal(err)
	}
	if len(reduced.Messages()) != 2 || len(reduced.MessageStates()) != 1 || reduced.MessageStates()[0].Version != secondMessage.DeliveryFingerprint {
		t.Fatalf("multi-version result messages=%+v states=%+v", reduced.Messages(), reduced.MessageStates())
	}
}

func TestReduceOfficialInventoryRequiresActualDAGCBORLinkAndStrictFields(t *testing.T) {
	base := validOfficialInventory(t)
	for _, test := range []struct {
		name   string
		mutate func(*officialSpacesInventory)
	}{
		{
			name: "plain link-shaped map",
			mutate: func(input *officialSpacesInventory) {
				for index, record := range input.records {
					if record.Collection != mailbox.MessageCollection {
						continue
					}
					message := sourceMessageRecord(t, input.target.RepoDID, "", "message")
					input.records[index] = sourceRecordWithLinkMode(t, record.Collection, record.RKey, message, false)
				}
			},
		},
		{
			name: "unknown message field",
			mutate: func(input *officialSpacesInventory) {
				for index, record := range input.records {
					if record.Collection != mailbox.MessageCollection {
						continue
					}
					value := sourceJSONValue(t, sourceMessageRecord(t, input.target.RepoDID, "", "message"))
					value.(map[string]any)["unexpected"] = true
					input.records[index] = sourceRecordWithLinkMode(t, record.Collection, record.RKey, value, true)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := base.clone()
			test.mutate(&input)
			if _, err := reduceOfficialSpacesInventory(context.Background(), input); err == nil {
				t.Fatal("expected strict source record rejection")
			}
		})
	}
}

func TestReduceOfficialSpacesSourceRejectsNilAndCancellation(t *testing.T) {
	if _, err := ReduceOfficialSpacesSource(context.Background(), nil); !errors.Is(err, ErrSourceReduction) {
		t.Fatalf("nil source error=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := reduceOfficialSpacesInventory(ctx, validOfficialInventory(t)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled error=%v", err)
	}
}

func TestReduceOfficialMessagesBoundsFolderMessageCrossProduct(t *testing.T) {
	folders := make(map[string]verifiedFolderReference, maxFolderCount)
	for index := 0; index < maxFolderCount; index++ {
		folders["folder-"+sourceSHA256ID(strconv.Itoa(index))] = verifiedFolderReference{}
	}
	messageCount := maxOfficialFolderMessageBindings/maxFolderCount + 1
	versions := make(map[string]map[string]string, messageCount)
	revisions := make(map[string][]StateRevision, messageCount)
	claims := make(map[string]map[string]string, messageCount)
	for index := 0; index < messageCount; index++ {
		logicalID := sourceSHA256ID("logical-" + strconv.Itoa(index))
		versions[logicalID] = map[string]string{}
		revisions[logicalID] = []StateRevision{{}}
		claims[logicalID] = map[string]string{}
	}
	_, _, err := reduceOfficialMessages(
		context.Background(), "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb", sourceSHA256ID("snapshot"),
		versions, revisions, claims, folders,
	)
	if !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("folder/message amplification error=%v", err)
	}
}

func validOfficialInventory(t *testing.T) officialSpacesInventory {
	t.Helper()
	repoDID := "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb"
	target := officialspaces.Target{
		Origin:   "https://spaces.example",
		SpaceURI: "at://did:plc:aaaaaaaaaaaaaaaaaaaaaaaa/space/email.atmos.mailbox/primary",
		RepoDID:  repoDID,
		Epoch:    officialspaces.PinnedEpoch,
	}
	var records []officialspaces.SourceRecord
	roles := make([]string, 0, len(standardFolderRoles))
	for role := range standardFolderRoles {
		roles = append(roles, role)
	}
	sort.Strings(roles)
	for _, role := range roles {
		folderID := mustStandardFolderID(t, repoDID, role)
		revision := FolderStateRevision{Record: FolderRevisionRecord{
			Type: FolderRevisionCollection, FolderID: folderID, OperationID: "initial-" + role,
			Parents: []string{}, Revision: 1, Name: standardFolderNames[role], Role: role,
			CreatedAt: time.Unix(1, 0).UTC().Format(time.RFC3339Nano),
		}}
		var err error
		revision.RKey, err = FolderRevisionRKey(repoDID, revision.Record)
		if err != nil {
			t.Fatal(err)
		}
		claim, err := NewFolderOperationClaim(repoDID, revision)
		if err != nil {
			t.Fatal(err)
		}
		records = append(records,
			sourceRecord(t, FolderRevisionCollection, revision.RKey, revision.Record),
			sourceRecord(t, FolderOperationCollection, claim.RKey, claim.Record),
		)
	}

	message := sourceMessageRecord(t, repoDID, "", "message")
	records = append(records, sourceRecord(t, mailbox.MessageCollection, message.DeliveryFingerprint, message))
	revision := StateRevision{Record: RevisionRecord{
		Type: MessageStateRevisionCollection, LogicalMessageID: message.LogicalMessageID,
		OperationID: "initial", Parents: []string{}, Revision: 1, Version: message.DeliveryFingerprint,
		MailboxIDs: []string{mustStandardFolderID(t, repoDID, "inbox")},
		CreatedAt:  time.Unix(2, 0).UTC().Format(time.RFC3339Nano),
	}}
	var err error
	revision.RKey, err = StateRevisionRKey(repoDID, revision.Record)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := NewOperationClaim(repoDID, revision)
	if err != nil {
		t.Fatal(err)
	}
	records = append(records,
		sourceRecord(t, MessageStateRevisionCollection, revision.RKey, revision.Record),
		sourceRecord(t, MessageStateOperationCollection, claim.RKey, claim.Record),
	)
	return officialSpacesInventory{
		target: target, revision: "3jzfcijpj2z2a", snapshotID: sourceSHA256ID("snapshot"),
		commitCID: sourceDAGCBORCID(t, []byte("commit")).String(),
		indexCID:  sourceDAGCBORCID(t, []byte("index")).String(),
		records:   records,
	}
}

func sourceMessageRecord(t *testing.T, repoDID, sourceKey, seed string) mailbox.MessageRecord {
	t.Helper()
	raw := []byte("synthetic non-sensitive RFC 5322 bytes: " + seed)
	rawHash := sha256.Sum256(raw)
	version := sourceSHA256ID("version-" + seed)
	blobCID, err := (cid.Prefix{Version: 1, Codec: cid.Raw, MhType: multihash.SHA2_256, MhLength: sha256.Size}).Sum(raw)
	if err != nil {
		t.Fatal(err)
	}
	return mailbox.MessageRecord{
		Type: mailbox.MessageCollection,
		Raw: mailbox.BlobRef{
			Type: "blob", Ref: mailbox.CIDLink{Link: blobCID.String()},
			MIMEType: mailbox.MessageMIMEType, Size: int64(len(raw)),
		},
		SHA256: hex.EncodeToString(rawHash[:]), Size: int64(len(raw)),
		DeliveryFingerprint: version, LogicalMessageID: mailbox.LogicalMessageID(repoDID, sourceKey, version),
		SourceKey: sourceKey, InitialMailbox: "Inbox", DeliveredAt: time.Unix(3, 0).UTC().Format(time.RFC3339Nano),
		References: []string{"<synthetic@example.invalid>"},
	}
}

func sourceRecord(t *testing.T, collection, rkey string, value any) officialspaces.SourceRecord {
	return sourceRecordWithLinkMode(t, collection, rkey, value, true)
}

func sourceRecordWithLinkMode(t *testing.T, collection, rkey string, value any, convertLinks bool) officialspaces.SourceRecord {
	t.Helper()
	object := sourceJSONValue(t, value)
	builder := basicnode.Prototype.Any.NewBuilder()
	if err := assignSourceNode(builder, object, convertLinks); err != nil {
		t.Fatal(err)
	}
	var encoded bytes.Buffer
	if err := (dagcbor.EncodeOptions{AllowLinks: true, MapSortMode: codec.MapSortMode_RFC7049}).Encode(builder.Build(), &encoded); err != nil {
		t.Fatal(err)
	}
	encodedCBOR := encoded.Bytes()
	return officialspaces.SourceRecord{
		Collection: collection, RKey: rkey, CID: sourceDAGCBORCID(t, encodedCBOR).String(), Value: encodedCBOR,
	}
}

func sourceJSONValue(t *testing.T, value any) any {
	t.Helper()
	encodedJSON, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encodedJSON))
	decoder.UseNumber()
	var object any
	if err := decoder.Decode(&object); err != nil {
		t.Fatal(err)
	}
	return object
}

func assignSourceNode(assembler datamodel.NodeAssembler, value any, convertLinks bool) error {
	switch value := value.(type) {
	case nil:
		return assembler.AssignNull()
	case bool:
		return assembler.AssignBool(value)
	case string:
		return assembler.AssignString(value)
	case json.Number:
		integer, err := value.Int64()
		if err != nil {
			return err
		}
		return assembler.AssignInt(integer)
	case []any:
		list, err := assembler.BeginList(int64(len(value)))
		if err != nil {
			return err
		}
		for _, item := range value {
			if err := assignSourceNode(list.AssembleValue(), item, convertLinks); err != nil {
				return err
			}
		}
		return list.Finish()
	case map[string]any:
		if convertLinks && len(value) == 1 {
			if encoded, ok := value["$link"].(string); ok {
				linkCID, err := cid.Parse(encoded)
				if err != nil {
					return err
				}
				return assembler.AssignLink(cidlink.Link{Cid: linkCID})
			}
		}
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		object, err := assembler.BeginMap(int64(len(value)))
		if err != nil {
			return err
		}
		for _, key := range keys {
			if err := object.AssembleKey().AssignString(key); err != nil {
				return err
			}
			if err := assignSourceNode(object.AssembleValue(), value[key], convertLinks); err != nil {
				return err
			}
		}
		return object.Finish()
	default:
		return errors.New("unsupported source test value")
	}
}

func sourceDAGCBORCID(t *testing.T, value []byte) cid.Cid {
	t.Helper()
	result, err := (cid.Prefix{Version: 1, Codec: cid.DagCBOR, MhType: multihash.SHA2_256, MhLength: sha256.Size}).Sum(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func sourceSHA256ID(seed string) string {
	digest := sha256.Sum256([]byte(seed))
	return "sha256-" + hex.EncodeToString(digest[:])
}

func mustStandardFolderID(t *testing.T, repoDID, role string) string {
	t.Helper()
	folderID, err := StandardFolderID(repoDID, role)
	if err != nil {
		t.Fatal(err)
	}
	return folderID
}

func removeSourceCollection(records []officialspaces.SourceRecord, collection string, count int) []officialspaces.SourceRecord {
	result := make([]officialspaces.SourceRecord, 0, len(records))
	for _, record := range records {
		if record.Collection == collection && count > 0 {
			count--
			continue
		}
		result = append(result, record)
	}
	return result
}

func removeSourceRKey(records []officialspaces.SourceRecord, collection, rkey string) []officialspaces.SourceRecord {
	result := make([]officialspaces.SourceRecord, 0, len(records))
	for _, record := range records {
		if record.Collection == collection && record.RKey == rkey {
			continue
		}
		result = append(result, record)
	}
	return result
}

func folderRevisionKeyForID(t *testing.T, records []officialspaces.SourceRecord, folderID string) string {
	t.Helper()
	for _, record := range records {
		if record.Collection != FolderRevisionCollection {
			continue
		}
		decoded, err := decodeOfficialFolderRevision(record.Value)
		if err == nil && decoded.FolderID == folderID {
			return record.RKey
		}
		if err != nil {
			t.Logf("decode folder revision: %v", err)
		}
	}
	t.Fatal("folder revision not found")
	return ""
}

func removeFolderClaimForID(t *testing.T, records []officialspaces.SourceRecord, folderID string) []officialspaces.SourceRecord {
	t.Helper()
	result := make([]officialspaces.SourceRecord, 0, len(records))
	for _, record := range records {
		if record.Collection == FolderOperationCollection {
			decoded, err := decodeOfficialFolderClaim(record.Value)
			if err != nil {
				t.Fatal(err)
			}
			if decoded.FolderID == folderID {
				continue
			}
		}
		result = append(result, record)
	}
	return result
}

func (input officialSpacesInventory) clone() officialSpacesInventory {
	records := input.records
	input.records = make([]officialspaces.SourceRecord, len(records))
	for index, record := range records {
		input.records[index] = record
		input.records[index].Value = bytes.Clone(record.Value)
	}
	return input
}
