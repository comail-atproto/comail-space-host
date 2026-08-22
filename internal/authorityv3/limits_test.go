// SPDX-License-Identifier: AGPL-3.0-or-later

package authorityv3

import (
	"fmt"
	"strings"
	"testing"
)

func TestSnapshotEnforcesReducerCollectionAndRevisionLimits(t *testing.T) {
	target, original := validLimitSnapshot()

	snapshot := cloneLimitSnapshot(original)
	snapshot.States[0].Keywords = limitKeywords(128)
	snapshot.States[0].RevisionCount = 4096
	snapshot.States[0].StateDigest = messageStateDigest(snapshot.States[0])
	snapshot.Folders[0].RevisionCount = 4096
	snapshot.Folders[0].StateDigest = folderStateDigest(snapshot.Folders[0])
	if !validSnapshot(snapshot, target) {
		t.Fatal("snapshot at reducer limits was rejected")
	}

	tooManyKeywords := cloneLimitSnapshot(snapshot)
	tooManyKeywords.States[0].Keywords = limitKeywords(129)
	tooManyKeywords.States[0].StateDigest = messageStateDigest(tooManyKeywords.States[0])
	if validSnapshot(tooManyKeywords, target) {
		t.Fatal("snapshot state above the reducer keyword limit was accepted")
	}

	tooManyStateRevisions := cloneLimitSnapshot(snapshot)
	tooManyStateRevisions.States[0].RevisionCount = 4097
	tooManyStateRevisions.States[0].StateDigest = messageStateDigest(tooManyStateRevisions.States[0])
	if validSnapshot(tooManyStateRevisions, target) {
		t.Fatal("snapshot state above the reducer revision limit was accepted")
	}

	tooManyFolderRevisions := cloneLimitSnapshot(snapshot)
	tooManyFolderRevisions.Folders[0].RevisionCount = 4097
	tooManyFolderRevisions.Folders[0].StateDigest = folderStateDigest(tooManyFolderRevisions.Folders[0])
	if validSnapshot(tooManyFolderRevisions, target) {
		t.Fatal("snapshot folder above the reducer revision limit was accepted")
	}
}

func TestMutationEnforcesReducerCollectionAndRevisionLimits(t *testing.T) {
	_, snapshot := validLimitSnapshot()
	state := snapshot.States[0]
	mutation := StateMutation{
		SnapshotID: state.SnapshotID, LogicalMessageID: state.LogicalMessageID,
		OperationID: "reducer-limits", ExpectedHeads: append([]string(nil), state.Heads...),
		ExpectedHeadsDigest: state.HeadsDigest, ExpectedStateDigest: state.StateDigest,
		ExpectedHeight: state.Height, ExpectedRevisionCount: 4095, Version: state.Version,
		MailboxIDs: limitFolderIDs(32), Keywords: limitKeywords(128),
	}
	if !validMutation(mutation) {
		t.Fatal("mutation at reducer limits was rejected")
	}

	tooManyMailboxes := mutation
	tooManyMailboxes.MailboxIDs = limitFolderIDs(33)
	if validMutation(tooManyMailboxes) {
		t.Fatal("mutation above the reducer mailbox limit was accepted")
	}

	tooManyKeywords := mutation
	tooManyKeywords.Keywords = limitKeywords(129)
	if validMutation(tooManyKeywords) {
		t.Fatal("mutation above the reducer keyword limit was accepted")
	}

	tooManyRevisions := mutation
	tooManyRevisions.ExpectedRevisionCount = 4096
	if validMutation(tooManyRevisions) {
		t.Fatal("mutation whose result would exceed the reducer revision limit was accepted")
	}
}

func validLimitSnapshot() (Target, Snapshot) {
	target := testTarget()
	raw := []byte("Message-ID: <limits@example.test>\r\nSubject: limits\r\n\r\nbody")
	fingerprint := sourceFingerprint(target.RepoDID, "", raw)
	logicalID := logicalMessageID(target.RepoDID, "", fingerprint)
	snapshotID := "sha256-" + strings.Repeat("5", 64)
	head := []string{"state-" + strings.Repeat("3", 64)}
	state := MessageState{
		LogicalMessageID: logicalID, SnapshotID: snapshotID, Version: fingerprint,
		MailboxIDs: []string{standardFolderID(target.RepoDID, "inbox")},
		Keywords:   []string{"$seen"}, Heads: head, Height: 1, RevisionCount: 1,
	}
	state.HeadsDigest = headsDigest("comail-message-state-heads-v1\x00", state.Heads)
	state.StateDigest = messageStateDigest(state)
	return target, Snapshot{
		Version: ProtocolVersion, Target: target, Revision: "commit-limits",
		SnapshotID: snapshotID, ManifestSHA256: "sha256-" + strings.Repeat("6", 64),
		Folders: testFolders(target, snapshotID, "folder-"+strings.Repeat("2", 64)),
		Messages: []MessageVersion{{
			URI:  target.SpaceURI + "/" + target.RepoDID + "/email.atmos.message/" + fingerprint,
			RKey: fingerprint, Fingerprint: fingerprint, LogicalMessageID: logicalID,
			SHA256: rawSHA256(raw), Size: int64(len(raw)), Raw: raw,
		}},
		States: []MessageState{state},
	}
}

func cloneLimitSnapshot(snapshot Snapshot) Snapshot {
	result := snapshot
	result.Folders = append([]FolderState(nil), snapshot.Folders...)
	result.Messages = append([]MessageVersion(nil), snapshot.Messages...)
	result.States = append([]MessageState(nil), snapshot.States...)
	for index := range result.Folders {
		result.Folders[index].Heads = append([]string(nil), snapshot.Folders[index].Heads...)
	}
	for index := range result.Messages {
		result.Messages[index].Raw = append([]byte(nil), snapshot.Messages[index].Raw...)
	}
	for index := range result.States {
		result.States[index].MailboxIDs = append([]string(nil), snapshot.States[index].MailboxIDs...)
		result.States[index].Keywords = append([]string(nil), snapshot.States[index].Keywords...)
		result.States[index].Heads = append([]string(nil), snapshot.States[index].Heads...)
	}
	return result
}

func limitFolderIDs(count int) []string {
	values := make([]string, count)
	for index := range values {
		values[index] = fmt.Sprintf("folder-%064x", index+1)
	}
	return values
}

func limitKeywords(count int) []string {
	values := make([]string, count)
	for index := range values {
		values[index] = fmt.Sprintf("keyword-%03d", index)
	}
	return values
}
