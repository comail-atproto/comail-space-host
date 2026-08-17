package mailbox

import (
	"strings"
	"testing"
	"time"
)

func TestDeliveryFingerprintIsStableAndRecipientScoped(t *testing.T) {
	raw := []byte("From: sender@example.com\r\nTo: me@example.com\r\n\r\nhello\r\n")
	a := DeliveryFingerprint("did:plc:alice", raw)
	b := DeliveryFingerprint("did:plc:alice", append([]byte(nil), raw...))
	c := DeliveryFingerprint("did:plc:bob", raw)
	if a != b {
		t.Fatalf("same delivery changed fingerprint: %q != %q", a, b)
	}
	if a == c {
		t.Fatal("fingerprint must be scoped to recipient DID")
	}
	if !strings.HasPrefix(a, "sha256-") || len(a) != 71 {
		t.Fatalf("fingerprint shape = %q", a)
	}
}

func TestNewMessagePairNormalizesStateAndPreservesMigrationIdentity(t *testing.T) {
	raw := []byte("Message-ID: <m@example.com>\r\n\r\nbody\r\n")
	pair, err := NewMessagePair(ImportedMessage{
		RecipientDID:  "did:plc:alice",
		Raw:           raw,
		Mailbox:       "INBOX",
		MessageID:     "m@example.com",
		MessageDate:   time.Date(2026, 8, 15, 12, 0, 0, 0, time.FixedZone("offset", -4*60*60)),
		Keywords:      []string{"$seen", "$flagged", "$seen"},
		DeletePending: true,
		UID:           42,
		UIDValidity:   7,
		ModSeq:        99,
	}, BlobRef{Type: "blob", Ref: CIDLink{Link: "bafk-test"}, MIMEType: MessageMIMEType, Size: int64(len(raw))})
	if err != nil {
		t.Fatal(err)
	}
	if pair.Message.DeliveryFingerprint != pair.RKey || pair.State.Message != pair.RKey {
		t.Fatal("message and state are not tied to their deterministic rkey")
	}
	if got := strings.Join(pair.State.Keywords, ","); got != "$flagged,$seen" {
		t.Fatalf("keywords = %q", got)
	}
	if pair.Message.MessageDate != "2026-08-15T16:00:00Z" {
		t.Fatalf("messageDate = %q", pair.Message.MessageDate)
	}
	if pair.State.Projection.UID != 42 || pair.State.Projection.UIDValidity != 7 || pair.State.Projection.ModSeq != 99 {
		t.Fatalf("projection identity = %#v", pair.State.Projection)
	}
	if !pair.State.DeletePending {
		t.Fatal("IMAP delete-pending state was lost")
	}
}

func TestValidateStoredMessageRejectsByteSubstitution(t *testing.T) {
	raw := []byte("Subject: private\r\n\r\nsecret\r\n")
	blob := BlobRef{Type: "blob", Ref: CIDLink{Link: "bafk-private"}, MIMEType: MessageMIMEType, Size: int64(len(raw))}
	pair, err := NewMessagePair(ImportedMessage{RecipientDID: "did:plc:alice", Raw: raw, Mailbox: "INBOX"}, blob)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateStoredMessage("did:plc:alice", pair.RKey, pair.Message, raw); err != nil {
		t.Fatalf("valid record: %v", err)
	}
	changed := append([]byte(nil), raw...)
	changed[len(changed)-2] = '!'
	if err := ValidateStoredMessage("did:plc:alice", pair.RKey, pair.Message, changed); err == nil {
		t.Fatal("changed blob bytes were accepted")
	}
}

func TestFolderIdentityIsDeterministicButNameSensitive(t *testing.T) {
	a := NewFolder("INBOX", "inbox", 10)
	b := NewFolder("INBOX", "inbox", 10)
	c := NewFolder("Inbox", "inbox", 10)
	if a.RKey != b.RKey {
		t.Fatal("same source folder changed identity")
	}
	if a.RKey == c.RKey {
		t.Fatal("case-preserved source folders collided")
	}
}
