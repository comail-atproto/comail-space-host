package repository

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/comail-atproto/comail-space-host/internal/mailbox"
)

var (
	ErrUnauthorized = errors.New("repository: unauthorized")
	ErrNotFound     = errors.New("repository: not found")
	ErrExists       = errors.New("repository: already exists")
	ErrConflict     = errors.New("repository: compare-and-swap conflict")
	ErrRevoked      = errors.New("repository: authorization revoked")
	ErrUnsupported  = errors.New("repository: capability unsupported")
	ErrTarget       = errors.New("repository: target binding mismatch")
)

type Target struct {
	ProviderOrigin string `json:"providerOrigin"`
	SpaceURI       string `json:"spaceUri"`
	RepoDID        string `json:"repoDid"`
	Epoch          string `json:"epoch"`
}

func (t Target) ValidateFor(recipientDID string) error {
	if t.ProviderOrigin == "" || t.SpaceURI == "" || t.RepoDID == "" || t.Epoch == "" {
		return ErrTarget
	}
	if recipientDID != "" && t.RepoDID != recipientDID {
		return ErrTarget
	}
	if _, err := syntax.ParseDID(t.RepoDID); err != nil || !strings.HasPrefix(t.SpaceURI, "at://") {
		return ErrTarget
	}
	spaceAuthority, path, found := strings.Cut(strings.TrimPrefix(t.SpaceURI, "at://"), "/")
	if _, err := syntax.ParseDID(spaceAuthority); !found || err != nil {
		return ErrTarget
	}
	segments := strings.Split(path, "/")
	if len(segments) != 3 || segments[0] != "space" {
		return ErrTarget
	}
	spaceType, spaceKey := segments[1], segments[2]
	if _, err := syntax.ParseNSID(spaceType); err != nil || spaceType != mailbox.MailboxSpaceType {
		return ErrTarget
	}
	if _, err := syntax.ParseRecordKey(spaceKey); err != nil || strings.ContainsAny(path, "?# \t\r\n") {
		return ErrTarget
	}
	return nil
}

type Capabilities struct {
	AtomicApplyWrites bool `json:"atomicApplyWrites"`
	CompareAndSwap    bool `json:"compareAndSwap"`
	ReferencedBlobs   bool `json:"referencedBlobs"`
	RepoOplog         bool `json:"repoOplog"`
	CARExport         bool `json:"carExport"`
	Notifications     bool `json:"notifications"`
}

type Record struct {
	URI        string          `json:"uri"`
	Collection string          `json:"collection"`
	RKey       string          `json:"rkey"`
	CID        string          `json:"cid"`
	Value      json.RawMessage `json:"value,omitempty"`
}

type WriteAction string

const (
	Create WriteAction = "create"
	Update WriteAction = "update"
	Delete WriteAction = "delete"
)

type Write struct {
	Action     WriteAction
	Collection string
	RKey       string
	Value      any
	SwapCID    string
}

type WriteResult struct {
	URI string `json:"uri,omitempty"`
	CID string `json:"cid,omitempty"`
}

type Commit struct {
	Rev     string        `json:"rev"`
	Hash    string        `json:"hash"`
	Results []WriteResult `json:"results,omitempty"`
}

// Repository is an authenticated, session-scoped permissioned-space client.
// Implementations must bind every operation to the exact target and must not
// infer or accept a target from message content.
type Repository interface {
	ProviderID() string
	Capabilities(context.Context) (Capabilities, error)
	EnsureMailbox(context.Context, string, string) (Target, error)
	UploadBlob(context.Context, Target, []byte, string) (mailbox.BlobRef, error)
	ApplyWrites(context.Context, Target, []Write) (Commit, error)
	PutRecordCAS(context.Context, Target, string, string, any, string) (Record, error)
	GetRecord(context.Context, Target, string, string) (Record, error)
	ListRecords(context.Context, Target, string) ([]Record, error)
	GetBlob(context.Context, Target, string) ([]byte, error)
}
