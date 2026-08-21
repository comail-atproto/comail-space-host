package repository

import "testing"

func TestTargetValidateForAcceptsOnlyOfficialSpaceAddress(t *testing.T) {
	const repoDID = "did:plc:rfwhywgeym2ek7ioeyxkvsn6"
	target := Target{
		ProviderOrigin: "https://spaces-alpha.host.bsky.network",
		SpaceURI:       "at://did:web:spaces.example/space/email.atmos.mailbox/default",
		RepoDID:        repoDID,
		Epoch:          "epoch",
	}
	if err := target.ValidateFor(repoDID); err != nil {
		t.Fatalf("official target: %v", err)
	}
}

func TestTargetValidateForRejectsLegacyAndMalformedSpaceAddresses(t *testing.T) {
	const repoDID = "did:plc:rfwhywgeym2ek7ioeyxkvsn6"
	for _, uri := range []string{
		"ats://" + repoDID + "/email.atmos.mailbox/default",
		"at://" + repoDID + "/email.atmos.mailbox/default",
		"at://" + repoDID + "/space/email.atmos.mailbox",
		"at://" + repoDID + "/space/email.atmos.mailbox/default/extra",
		"at://" + repoDID + "/space/email.atmos.mailbox/default?other=true",
		"at://not-a-did/space/email.atmos.mailbox/default",
		"at://" + repoDID + "/space/app.example.other/default",
	} {
		target := Target{ProviderOrigin: "https://pds.example.test", SpaceURI: uri, RepoDID: repoDID, Epoch: "epoch"}
		if err := target.ValidateFor(repoDID); err == nil {
			t.Errorf("accepted invalid space URI %q", uri)
		}
	}
}

func TestTargetValidateForRejectsCrossRepositoryTarget(t *testing.T) {
	target := Target{
		ProviderOrigin: "https://pds.example.test",
		SpaceURI:       "at://did:web:spaces.example/space/email.atmos.mailbox/default",
		RepoDID:        "did:plc:rfwhywgeym2ek7ioeyxkvsn6",
		Epoch:          "epoch",
	}
	if err := target.ValidateFor("did:plc:ewvi7nxzyoun6zhxrhs64oiz"); err == nil {
		t.Fatal("cross-repository target was accepted")
	}
}

func TestRecordURIIncludesDistinctSpaceAuthorityAndAuthorRepository(t *testing.T) {
	target := Target{
		ProviderOrigin: "https://spaces-alpha.host.bsky.network",
		SpaceURI:       "at://did:web:spaces.example/space/email.atmos.mailbox/default",
		RepoDID:        "did:plc:rfwhywgeym2ek7ioeyxkvsn6",
		Epoch:          "epoch",
	}
	got, err := RecordURI(target, "email.atmos.message", "sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	want := target.SpaceURI + "/" + target.RepoDID + "/email.atmos.message/sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if got != want {
		t.Fatalf("record URI = %q, want %q", got, want)
	}
	if _, err := RecordURI(target, "not a collection", "bad/key"); err == nil {
		t.Fatal("malformed record path was accepted")
	}
	legacyServiceURI := target.SpaceURI + "/did:web:comail.example/email.atmos.message/sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := ValidateRecordURI(target, legacyServiceURI, "email.atmos.message", "sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); err != nil {
		t.Fatalf("pinned legacy service-author record: %v", err)
	}
	if err := ValidateRecordURI(target, target.SpaceURI+"/did:web:comail.example/email.atmos.message/other/extra", "email.atmos.message", "other"); err == nil {
		t.Fatal("malformed provider record URI was accepted")
	}
}
