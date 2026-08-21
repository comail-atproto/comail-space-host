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
