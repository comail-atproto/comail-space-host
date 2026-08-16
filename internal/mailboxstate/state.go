// Package mailboxstate applies conflict-safe mutations to the authoritative
// email.atmos.messageState record in one exact permissioned mailbox space.
package mailboxstate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/comail-atproto/comail-pds-lab/internal/mailbox"
	"github.com/comail-atproto/comail-pds-lab/internal/repository"
)

var (
	ErrConflict      = errors.New("mailboxstate: concurrent update conflict")
	ErrStaleRevision = errors.New("mailboxstate: stale expected revision")
	ErrInvalid       = errors.New("mailboxstate: invalid mutation")
)

type Operation string

const (
	MarkRead   Operation = "markRead"
	MarkUnread Operation = "markUnread"
	Flag       Operation = "flag"
	Unflag     Operation = "unflag"
	Move       Operation = "move"
	Tombstone  Operation = "tombstone"
)

type Mutation struct {
	MessageRKey      string
	ExpectedRevision uint64
	OperationID      string
	Operation        Operation
	Mailbox          string
	Now              time.Time
}

// Apply reads the current state and replaces it with provider-enforced CAS.
// OperationID makes a response-lost retry of the most recent operation
// idempotent; a different operation against an old revision fails closed.
func Apply(ctx context.Context, repo repository.Repository, target repository.Target, mutation Mutation) (mailbox.MessageStateRecord, error) {
	if repo == nil || target.ValidateFor(target.RepoDID) != nil || !validMutation(mutation) {
		return mailbox.MessageStateRecord{}, ErrInvalid
	}
	capabilities, err := repo.Capabilities(ctx)
	if err != nil {
		return mailbox.MessageStateRecord{}, err
	}
	if !capabilities.CompareAndSwap {
		return mailbox.MessageStateRecord{}, repository.ErrUnsupported
	}
	if _, err := repo.GetRecord(ctx, target, mailbox.MessageCollection, mutation.MessageRKey); err != nil {
		return mailbox.MessageStateRecord{}, fmt.Errorf("mailboxstate: immutable message: %w", err)
	}
	stored, err := repo.GetRecord(ctx, target, mailbox.MessageStateCollection, mutation.MessageRKey)
	if err != nil {
		return mailbox.MessageStateRecord{}, fmt.Errorf("mailboxstate: read state: %w", err)
	}
	var state mailbox.MessageStateRecord
	if json.Unmarshal(stored.Value, &state) != nil || !validState(state, mutation.MessageRKey) {
		return mailbox.MessageStateRecord{}, mailbox.ErrIntegrity
	}
	if state.LastOperation == mutation.OperationID {
		return state, nil
	}
	if state.Revision != mutation.ExpectedRevision {
		return mailbox.MessageStateRecord{}, ErrStaleRevision
	}
	if state.Tombstone {
		return mailbox.MessageStateRecord{}, ErrInvalid
	}

	switch mutation.Operation {
	case MarkRead:
		state.Keywords = add(state.Keywords, "$seen")
	case MarkUnread:
		state.Keywords = remove(state.Keywords, "$seen")
	case Flag:
		state.Keywords = add(state.Keywords, "$flagged")
	case Unflag:
		state.Keywords = remove(state.Keywords, "$flagged")
	case Move:
		folderID := mailbox.FolderRKey(mutation.Mailbox)
		folder, err := repo.GetRecord(ctx, target, mailbox.FolderCollection, folderID)
		if err != nil {
			return mailbox.MessageStateRecord{}, fmt.Errorf("mailboxstate: destination folder: %w", err)
		}
		var value mailbox.FolderRecord
		if json.Unmarshal(folder.Value, &value) != nil || value.Type != mailbox.FolderCollection || value.Name != mutation.Mailbox || folder.RKey != folderID {
			return mailbox.MessageStateRecord{}, mailbox.ErrIntegrity
		}
		state.MailboxIDs = []string{folderID}
	case Tombstone:
		state.Tombstone = true
		state.DeletePending = false
	default:
		return mailbox.MessageStateRecord{}, ErrInvalid
	}
	state.Revision++
	state.UpdatedAt = mutation.Now.UTC().Format(time.RFC3339Nano)
	state.LastOperation = mutation.OperationID
	updated, err := repo.PutRecordCAS(ctx, target, mailbox.MessageStateCollection, mutation.MessageRKey, state, stored.CID)
	if errors.Is(err, repository.ErrConflict) {
		return mailbox.MessageStateRecord{}, ErrConflict
	}
	if err != nil {
		return mailbox.MessageStateRecord{}, fmt.Errorf("mailboxstate: write state: %w", err)
	}
	var verified mailbox.MessageStateRecord
	if json.Unmarshal(updated.Value, &verified) != nil || !validState(verified, mutation.MessageRKey) || verified.Revision != state.Revision || verified.LastOperation != mutation.OperationID {
		return mailbox.MessageStateRecord{}, mailbox.ErrIntegrity
	}
	return verified, nil
}

func validMutation(mutation Mutation) bool {
	if mutation.MessageRKey == "" || len(mutation.MessageRKey) > 512 || mutation.ExpectedRevision == 0 || mutation.Now.IsZero() ||
		mutation.OperationID == "" || len(mutation.OperationID) > 128 || strings.ContainsAny(mutation.OperationID, " \t\r\n\x00") {
		return false
	}
	switch mutation.Operation {
	case MarkRead, MarkUnread, Flag, Unflag, Tombstone:
		return mutation.Mailbox == ""
	case Move:
		return mutation.Mailbox != "" && len(mutation.Mailbox) <= 255 && !strings.ContainsAny(mutation.Mailbox, "\r\n\x00")
	default:
		return false
	}
}

func validState(state mailbox.MessageStateRecord, rkey string) bool {
	if state.Type != mailbox.MessageStateCollection || state.Message != rkey || state.Revision == 0 || len(state.MailboxIDs) == 0 || len(state.MailboxIDs) > 32 || len(state.Keywords) > 128 {
		return false
	}
	for _, value := range append(append([]string(nil), state.MailboxIDs...), state.Keywords...) {
		if value == "" {
			return false
		}
	}
	return true
}

func add(values []string, value string) []string {
	for _, current := range values {
		if current == value {
			return append([]string(nil), values...)
		}
	}
	out := append(append([]string(nil), values...), value)
	sort.Strings(out)
	return out
}

func remove(values []string, value string) []string {
	out := make([]string, 0, len(values))
	for _, current := range values {
		if current != value {
			out = append(out, current)
		}
	}
	return out
}
