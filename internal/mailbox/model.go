package mailbox

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	MailboxSpaceType       = "email.atmos.mailbox"
	MessageCollection      = "email.atmos.message"
	MessageStateCollection = "email.atmos.messageState"
	FolderCollection       = "email.atmos.folder"
	MessageMIMEType        = "message/rfc822"
	MaxRawMessageBytes     = 10 * 1024 * 1024

	fingerprintPrefix = "sha256-"
)

var (
	ErrIntegrity       = errors.New("mailbox: integrity check failed")
	ErrMessageTooLarge = errors.New("mailbox: message exceeds configured maximum")
	ErrInvalidRecord   = errors.New("mailbox: invalid record")
)

type CIDLink struct {
	Link string `json:"$link"`
}

type BlobRef struct {
	Type     string  `json:"$type"`
	Ref      CIDLink `json:"ref"`
	MIMEType string  `json:"mimeType"`
	Size     int64   `json:"size"`
}

type MessageRecord struct {
	Type                string   `json:"$type"`
	Raw                 BlobRef  `json:"raw"`
	SHA256              string   `json:"sha256"`
	Size                int64    `json:"size"`
	DeliveryFingerprint string   `json:"deliveryFingerprint"`
	SourceKey           string   `json:"sourceKey,omitempty"`
	InitialMailbox      string   `json:"initialMailbox"`
	DeliveredAt         string   `json:"deliveredAt,omitempty"`
	SourceMessageID     string   `json:"sourceMessageId,omitempty"`
	MessageDate         string   `json:"messageDate,omitempty"`
	InReplyTo           string   `json:"inReplyTo,omitempty"`
	References          []string `json:"references,omitempty"`
}

type ProjectionIdentity struct {
	UID         uint32 `json:"uid,omitempty"`
	UIDValidity uint32 `json:"uidValidity,omitempty"`
	ModSeq      uint64 `json:"modSeq,omitempty"`
}

type MessageStateRecord struct {
	Type          string             `json:"$type"`
	Message       string             `json:"message"`
	MailboxIDs    []string           `json:"mailboxIds"`
	Keywords      []string           `json:"keywords"`
	DeletePending bool               `json:"deletePending,omitempty"`
	Tombstone     bool               `json:"tombstone,omitempty"`
	Revision      uint64             `json:"revision"`
	UpdatedAt     string             `json:"updatedAt"`
	Projection    ProjectionIdentity `json:"projection,omitempty"`
}

type FolderRecord struct {
	Type        string `json:"$type"`
	Name        string `json:"name"`
	Role        string `json:"role,omitempty"`
	UIDValidity uint32 `json:"uidValidity,omitempty"`
	Revision    uint64 `json:"revision"`
	UpdatedAt   string `json:"updatedAt"`
}

type Folder struct {
	RKey   string
	Record FolderRecord
}

type MessagePair struct {
	RKey    string
	Message MessageRecord
	State   MessageStateRecord
}

type ImportedMessage struct {
	RecipientDID  string
	SourceKey     string
	Raw           []byte
	Mailbox       string
	Mailboxes     []string
	MessageID     string
	MessageDate   time.Time
	InReplyTo     string
	References    []string
	Keywords      []string
	DeletePending bool
	UID           uint32
	UIDValidity   uint32
	ModSeq        uint64
	DeliveredAt   time.Time
}

func DeliveryFingerprint(recipientDID string, raw []byte) string {
	return deliveryFingerprint(recipientDID, "", raw)
}

func ImportedFingerprint(src ImportedMessage) string {
	return deliveryFingerprint(src.RecipientDID, src.SourceKey, src.Raw)
}

func deliveryFingerprint(recipientDID, sourceKey string, raw []byte) string {
	h := sha256.New()
	_, _ = h.Write([]byte("comail-habitat-delivery-v2\x00"))
	_, _ = h.Write([]byte(recipientDID))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(sourceKey))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(raw)
	return fingerprintPrefix + hex.EncodeToString(h.Sum(nil))
}

func RawSHA256(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func NewMessagePair(src ImportedMessage, blob BlobRef) (MessagePair, error) {
	if src.RecipientDID == "" || !strings.HasPrefix(src.RecipientDID, "did:") {
		return MessagePair{}, fmt.Errorf("%w: recipient DID is required", ErrInvalidRecord)
	}
	if len(src.Raw) == 0 {
		return MessagePair{}, fmt.Errorf("%w: RFC 5322 bytes are empty", ErrInvalidRecord)
	}
	if len(src.Raw) > MaxRawMessageBytes {
		return MessagePair{}, fmt.Errorf("%w: got %d bytes, maximum %d", ErrMessageTooLarge, len(src.Raw), MaxRawMessageBytes)
	}
	if len(src.SourceKey) > 512 {
		return MessagePair{}, fmt.Errorf("%w: source key exceeds 512 bytes", ErrInvalidRecord)
	}
	mailboxes := normalizeStrings(src.Mailboxes)
	if src.Mailbox != "" {
		mailboxes = normalizeStrings(append(mailboxes, src.Mailbox))
	}
	if len(mailboxes) == 0 {
		mailboxes = []string{"INBOX"}
	}
	if len(mailboxes) > 32 {
		return MessagePair{}, fmt.Errorf("%w: message belongs to more than 32 mailboxes", ErrInvalidRecord)
	}
	for _, name := range mailboxes {
		if len(name) > 255 {
			return MessagePair{}, fmt.Errorf("%w: mailbox name exceeds 255 bytes", ErrInvalidRecord)
		}
	}
	if len(src.MessageID) > 998 || len(src.InReplyTo) > 998 || len(src.References) > 100 {
		return MessagePair{}, fmt.Errorf("%w: RFC 5322 metadata exceeds contract limits", ErrInvalidRecord)
	}
	for _, reference := range src.References {
		if len(reference) > 998 {
			return MessagePair{}, fmt.Errorf("%w: reference exceeds 998 bytes", ErrInvalidRecord)
		}
	}
	keywords := normalizeStrings(src.Keywords)
	if len(keywords) > 128 {
		return MessagePair{}, fmt.Errorf("%w: more than 128 keywords", ErrInvalidRecord)
	}
	for _, keyword := range keywords {
		if len(keyword) > 255 {
			return MessagePair{}, fmt.Errorf("%w: keyword exceeds 255 bytes", ErrInvalidRecord)
		}
	}
	src.Mailbox = mailboxes[0]
	stateTime := src.DeliveredAt
	if stateTime.IsZero() {
		// Legacy SQLite rows do not carry a trustworthy delivery/update time.
		// Epoch is a deterministic "unknown baseline" for mutable state; do not
		// invent a delivery time for the immutable message record.
		stateTime = time.Unix(0, 0).UTC()
	}
	if blob.Type == "" {
		blob.Type = "blob"
	}
	if blob.Ref.Link == "" || blob.MIMEType != MessageMIMEType || blob.Size != int64(len(src.Raw)) {
		return MessagePair{}, fmt.Errorf("%w: blob reference does not match message", ErrInvalidRecord)
	}
	rkey := ImportedFingerprint(src)
	message := MessageRecord{
		Type:                MessageCollection,
		Raw:                 blob,
		SHA256:              RawSHA256(src.Raw),
		Size:                int64(len(src.Raw)),
		DeliveryFingerprint: rkey,
		SourceKey:           src.SourceKey,
		InitialMailbox:      src.Mailbox,
		SourceMessageID:     src.MessageID,
		InReplyTo:           src.InReplyTo,
		References:          append([]string(nil), src.References...),
	}
	if !src.DeliveredAt.IsZero() {
		message.DeliveredAt = src.DeliveredAt.UTC().Format(time.RFC3339Nano)
	}
	if !src.MessageDate.IsZero() {
		message.MessageDate = src.MessageDate.UTC().Format(time.RFC3339Nano)
	}
	state := MessageStateRecord{
		Type:          MessageStateCollection,
		Message:       rkey,
		MailboxIDs:    folderRKeys(mailboxes),
		Keywords:      keywords,
		DeletePending: src.DeletePending,
		Revision:      1,
		UpdatedAt:     stateTime.UTC().Format(time.RFC3339Nano),
	}
	// UID is folder-local. Preserve the legacy identity only when the message
	// has exactly one mailbox; multi-mailbox JMAP sources get stable identities
	// when a standards projection is rebuilt.
	if len(mailboxes) == 1 {
		state.Projection = ProjectionIdentity{UID: src.UID, UIDValidity: src.UIDValidity, ModSeq: src.ModSeq}
	}
	return MessagePair{RKey: rkey, Message: message, State: state}, nil
}

func folderRKeys(names []string) []string {
	out := make([]string, 0, len(names))
	for _, name := range names {
		out = append(out, FolderRKey(name))
	}
	sort.Strings(out)
	return out
}

// StableUIDValidity derives a non-zero projection identity from the account
// and full mailbox path. It is deterministic across clean rebuilds.
func StableUIDValidity(recipientDID, mailboxName string) uint32 {
	sum := sha256.Sum256([]byte("comail-uidvalidity-v1\x00" + recipientDID + "\x00" + mailboxName))
	value := uint32(sum[0])<<24 | uint32(sum[1])<<16 | uint32(sum[2])<<8 | uint32(sum[3])
	if value == 0 {
		return 1
	}
	return value
}

func ValidateStoredMessage(recipientDID, rkey string, record MessageRecord, raw []byte) error {
	if record.Type != MessageCollection {
		return fmt.Errorf("%w: record type %q", ErrIntegrity, record.Type)
	}
	if len(raw) == 0 || len(raw) > MaxRawMessageBytes {
		return fmt.Errorf("%w: raw size %d", ErrIntegrity, len(raw))
	}
	wantFingerprint := deliveryFingerprint(recipientDID, record.SourceKey, raw)
	if rkey != wantFingerprint || record.DeliveryFingerprint != wantFingerprint {
		return fmt.Errorf("%w: delivery fingerprint mismatch", ErrIntegrity)
	}
	if record.SHA256 != RawSHA256(raw) || record.Size != int64(len(raw)) {
		return fmt.Errorf("%w: message hash or size mismatch", ErrIntegrity)
	}
	if record.Raw.Ref.Link == "" || record.Raw.MIMEType != MessageMIMEType || record.Raw.Size != int64(len(raw)) {
		return fmt.Errorf("%w: blob reference mismatch", ErrIntegrity)
	}
	return nil
}

func FolderRKey(name string) string {
	sum := sha256.Sum256([]byte("comail-folder-v1\x00" + name))
	return "folder-" + hex.EncodeToString(sum[:])
}

func NewFolder(name, role string, uidValidity uint32) Folder {
	return Folder{
		RKey: FolderRKey(name),
		Record: FolderRecord{
			Type: FolderCollection, Name: name, Role: role,
			UIDValidity: uidValidity, Revision: 1,
			UpdatedAt: time.Unix(0, 0).UTC().Format(time.RFC3339Nano),
		},
	}
}

func normalizeStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
