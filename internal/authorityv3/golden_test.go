// SPDX-License-Identifier: AGPL-3.0-or-later

package authorityv3

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const officialV3ManifestSHA256 = "298c89ce791b7bd257c875d1266fa1a9cee789a17ff7282636fee5ef452fbf56"

type officialV3GoldenManifest struct {
	FixtureVersion           int    `json:"fixtureVersion"`
	ProtocolVersion          int    `json:"protocolVersion"`
	SnapshotResponseMaxBytes int    `json:"snapshotResponseMaxBytes"`
	VectorFile               string `json:"vectorFile"`
	VectorSHA256             string `json:"vectorSha256"`
}

type officialV3GoldenVectors struct {
	RawSHA256          string `json:"rawSha256"`
	SourceFingerprint  string `json:"sourceFingerprint"`
	LogicalMessageID   string `json:"logicalMessageId"`
	InboxFolderID      string `json:"inboxFolderId"`
	MessageURI         string `json:"messageUri"`
	FolderHeadsDigest  string `json:"folderHeadsDigest"`
	FolderStateDigest  string `json:"folderStateDigest"`
	MessageHeadsDigest string `json:"messageHeadsDigest"`
	MessageStateDigest string `json:"messageStateDigest"`
}

type officialV3GoldenContract struct {
	FixtureVersion           int                     `json:"fixtureVersion"`
	SnapshotResponseMaxBytes int                     `json:"snapshotResponseMaxBytes"`
	CapabilityResponse       capabilityResponse      `json:"capabilityResponse"`
	SnapshotResponse         snapshotResponse        `json:"snapshotResponse"`
	StateRequest             stateRequest            `json:"stateRequest"`
	Vectors                  officialV3GoldenVectors `json:"vectors"`
}

func TestOfficialV3GoldenContract(t *testing.T) {
	directory := filepath.Join("testdata", "official-v3")
	manifestBytes := readGoldenFile(t, filepath.Join(directory, "manifest.json"))
	if got := goldenSHA256(manifestBytes); got != officialV3ManifestSHA256 {
		t.Fatalf("manifest hash=%s, want %s", got, officialV3ManifestSHA256)
	}
	var manifest officialV3GoldenManifest
	if err := decodeStrict(bytes.NewReader(manifestBytes), &manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	if manifest.FixtureVersion != 1 || manifest.ProtocolVersion != ProtocolVersion ||
		manifest.SnapshotResponseMaxBytes != maxSnapshotResponseBytes || manifest.VectorFile != "vector.json" {
		t.Fatalf("invalid golden manifest: %#v", manifest)
	}

	vectorBytes := readGoldenFile(t, filepath.Join(directory, manifest.VectorFile))
	if got := goldenSHA256(vectorBytes); got != manifest.VectorSHA256 {
		t.Fatalf("vector hash=%s, want %s", got, manifest.VectorSHA256)
	}
	var fixture officialV3GoldenContract
	if err := decodeStrict(bytes.NewReader(vectorBytes), &fixture); err != nil {
		t.Fatalf("decode vector: %v", err)
	}
	if fixture.FixtureVersion != manifest.FixtureVersion ||
		fixture.SnapshotResponseMaxBytes != maxSnapshotResponseBytes {
		t.Fatalf("fixture metadata drifted: %#v", fixture)
	}
	encoded, err := json.Marshal(fixture)
	if err != nil || !bytes.Equal(encoded, bytes.TrimSpace(vectorBytes)) {
		t.Fatalf("fixture DTO field encoding drifted: err=%v", err)
	}

	capability := fixture.CapabilityResponse
	snapshotResponse := fixture.SnapshotResponse
	mutationRequest := fixture.StateRequest
	target := capability.Target
	if capability.Version != ProtocolVersion || capability.ProviderID != target.ProviderID ||
		!capability.Capabilities.supports(target) || snapshotResponse.Version != ProtocolVersion ||
		snapshotResponse.ProviderID != target.ProviderID || snapshotResponse.Target != target ||
		mutationRequest.Version != ProtocolVersion || mutationRequest.Target != target ||
		!validSnapshot(snapshotResponse.Snapshot, target) || !validMutation(mutationRequest.Mutation) {
		t.Fatal("golden DTOs no longer satisfy the official-v3 contract")
	}
	if len(snapshotResponse.Snapshot.Messages) != 1 || len(snapshotResponse.Snapshot.States) != 1 ||
		len(snapshotResponse.Snapshot.Folders) == 0 {
		t.Fatal("golden snapshot shape is incomplete")
	}
	message := snapshotResponse.Snapshot.Messages[0]
	state := snapshotResponse.Snapshot.States[0]
	folder := snapshotResponse.Snapshot.Folders[0]
	vectors := fixture.Vectors
	if vectors.RawSHA256 != rawSHA256(message.Raw) ||
		vectors.SourceFingerprint != sourceFingerprint(target.RepoDID, message.SourceKey, message.Raw) ||
		vectors.LogicalMessageID != logicalMessageID(target.RepoDID, message.SourceKey, message.Fingerprint) ||
		vectors.InboxFolderID != standardFolderID(target.RepoDID, "inbox") ||
		vectors.MessageURI != target.SpaceURI+"/"+target.RepoDID+"/email.atmos.message/"+message.RKey ||
		vectors.FolderHeadsDigest != headsDigest("comail-folder-state-heads-v1\x00", folder.Heads) ||
		vectors.FolderStateDigest != folderStateDigest(folder) ||
		vectors.MessageHeadsDigest != headsDigest("comail-message-state-heads-v1\x00", state.Heads) ||
		vectors.MessageStateDigest != messageStateDigest(state) {
		t.Fatal("golden canonical digest or URI vector drifted")
	}
}

func readGoldenFile(t *testing.T, name string) []byte {
	t.Helper()
	value, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func goldenSHA256(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
