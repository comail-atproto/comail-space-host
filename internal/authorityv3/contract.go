// SPDX-License-Identifier: AGPL-3.0-or-later

// Package authorityv3 defines the relay-facing HTTP contract for the
// member-authored, append-only official Spaces authority generation.
//
// It is deliberately separate from shadowagent's legacy-v2 inventory and CAS
// DTOs. In particular, mailbox memberships and causal heads remain plural.
package authorityv3

import (
	"context"
	"errors"
)

const ProtocolVersion = 3

const AuthorityGeneration = "official-v3"

var ErrConflict = errors.New("authorityv3: concurrent append conflict")

type Target struct {
	ProviderID                     string `json:"providerId"`
	Origin                         string `json:"origin"`
	SpaceURI                       string `json:"spaceUri"`
	RepoDID                        string `json:"repoDid"`
	Epoch                          string `json:"epoch"`
	AuthorityCertificateSHA256     string `json:"authorityCertificateSha256,omitempty"`
	AuthorityCertificateGeneration string `json:"authorityCertificateGeneration,omitempty"`
}

type Capabilities struct {
	PrivateRecords             bool   `json:"privateRecords"`
	ReferencedBlobs            bool   `json:"referencedBlobs"`
	AtomicCreateBatch          bool   `json:"atomicCreateBatch"`
	IdempotentOperationClaims  bool   `json:"idempotentOperationClaims"`
	AuthenticatedStableRead    bool   `json:"authenticatedStableRead"`
	CompleteInventory          bool   `json:"completeInventory"`
	ConcurrentHeads            bool   `json:"concurrentHeads"`
	Tombstones                 bool   `json:"tombstones"`
	SourceVersioning           bool   `json:"sourceVersioning"`
	AuthorityCertificateSHA256 string `json:"authorityCertificateSha256"`
	AuthorityGeneration        string `json:"authorityCertificateGeneration"`
}

type FolderState struct {
	FolderID      string   `json:"folderId"`
	SnapshotID    string   `json:"snapshotId"`
	Name          string   `json:"name"`
	Role          string   `json:"role,omitempty"`
	Tombstone     bool     `json:"tombstone"`
	Heads         []string `json:"heads"`
	HeadsDigest   string   `json:"headsDigest"`
	StateDigest   string   `json:"stateDigest"`
	Height        uint64   `json:"height"`
	RevisionCount int      `json:"revisionCount"`
}

type MessageVersion struct {
	URI              string `json:"uri"`
	RKey             string `json:"rkey"`
	Fingerprint      string `json:"fingerprint"`
	LogicalMessageID string `json:"logicalMessageId"`
	SourceKey        string `json:"sourceKey,omitempty"`
	SHA256           string `json:"sha256"`
	Size             int64  `json:"size"`
	Raw              []byte `json:"raw"`
}

type MessageState struct {
	LogicalMessageID string   `json:"logicalMessageId"`
	SnapshotID       string   `json:"snapshotId"`
	Version          string   `json:"version"`
	MailboxIDs       []string `json:"mailboxIds"`
	Keywords         []string `json:"keywords"`
	DeletePending    bool     `json:"deletePending"`
	Tombstone        bool     `json:"tombstone"`
	Heads            []string `json:"heads"`
	HeadsDigest      string   `json:"headsDigest"`
	StateDigest      string   `json:"stateDigest"`
	Height           uint64   `json:"height"`
	RevisionCount    int      `json:"revisionCount"`
}

type Snapshot struct {
	Version        int              `json:"version"`
	Target         Target           `json:"target"`
	Revision       string           `json:"revision"`
	SnapshotID     string           `json:"snapshotId"`
	ManifestSHA256 string           `json:"manifestSha256"`
	Folders        []FolderState    `json:"folders"`
	Messages       []MessageVersion `json:"messages"`
	States         []MessageState   `json:"states"`
}

type FolderSelection struct {
	SourceKey string `json:"sourceKey"`
	Name      string `json:"name"`
	Role      string `json:"role,omitempty"`
}

type Placement struct {
	SourceKey string            `json:"sourceKey,omitempty"`
	Folders   []FolderSelection `json:"folders"`
	Keywords  []string          `json:"keywords"`
}

type StateMutation struct {
	SnapshotID            string   `json:"snapshotId"`
	LogicalMessageID      string   `json:"logicalMessageId"`
	OperationID           string   `json:"operationId"`
	ExpectedHeads         []string `json:"expectedHeads"`
	ExpectedHeadsDigest   string   `json:"expectedHeadsDigest"`
	ExpectedStateDigest   string   `json:"expectedStateDigest"`
	ExpectedHeight        uint64   `json:"expectedHeight"`
	ExpectedRevisionCount int      `json:"expectedRevisionCount"`
	Version               string   `json:"version"`
	MailboxIDs            []string `json:"mailboxIds"`
	Keywords              []string `json:"keywords"`
	DeletePending         bool     `json:"deletePending"`
	Tombstone             bool     `json:"tombstone"`
}

type Receipt struct {
	Target      Target `json:"target"`
	Fingerprint string `json:"fingerprint"`
	SHA256      string `json:"sha256"`
	Size        int64  `json:"size"`
	Verified    bool   `json:"verified"`
}

type StoreInput struct {
	RecipientDID string
	Placement    Placement
	Raw          []byte
}

// Engine owns all provider credentials and append-only repository mechanics.
// The HTTP handler has already authenticated and exact-target-validated every
// request before invoking it.
type Engine interface {
	Capabilities(context.Context) (Capabilities, error)
	Store(context.Context, StoreInput) (Receipt, error)
	Snapshot(context.Context) (Snapshot, error)
	AppendState(context.Context, StateMutation) (MessageState, error)
}

type capabilityRequest struct {
	Version int    `json:"version"`
	Target  Target `json:"target"`
}

type capabilityResponse struct {
	Version      int          `json:"version"`
	ProviderID   string       `json:"providerId"`
	Target       Target       `json:"target"`
	Capabilities Capabilities `json:"capabilities"`
}

type protocolMessage struct {
	Raw []byte `json:"raw"`
}

type storeRequest struct {
	Version      int             `json:"version"`
	Target       Target          `json:"target"`
	RecipientDID string          `json:"recipientDid"`
	Placement    Placement       `json:"placement"`
	Message      protocolMessage `json:"message"`
}

type storeResponse struct {
	Version    int     `json:"version"`
	ProviderID string  `json:"providerId"`
	Target     Target  `json:"target"`
	Receipt    Receipt `json:"receipt"`
}

type snapshotRequest struct {
	Version int    `json:"version"`
	Target  Target `json:"target"`
}

type snapshotResponse struct {
	Version    int      `json:"version"`
	ProviderID string   `json:"providerId"`
	Target     Target   `json:"target"`
	Snapshot   Snapshot `json:"snapshot"`
}

type stateRequest struct {
	Version  int           `json:"version"`
	Target   Target        `json:"target"`
	Mutation StateMutation `json:"mutation"`
}

type stateResponse struct {
	Version     int          `json:"version"`
	ProviderID  string       `json:"providerId"`
	Target      Target       `json:"target"`
	OperationID string       `json:"operationId"`
	State       MessageState `json:"state"`
}
