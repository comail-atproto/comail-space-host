package repository

import "testing"

func TestTargetValidateForPinsLegacyAndStandardSpaceOwner(t *testing.T) {
	const did = "did:plc:targetowner"
	for _, uri := range []string{
		"at://did:plc:targetowner/space/email.atmos.mailbox/default",
		"ats://did:plc:targetowner/email.atmos.mailbox/default",
	} {
		target := Target{ProviderOrigin: "https://pds.example.test", SpaceURI: uri, RepoDID: did, Epoch: "epoch"}
		if err := target.ValidateFor(did); err != nil {
			t.Errorf("ValidateFor(%q): %v", uri, err)
		}
	}
}

func TestTargetValidateForRejectsCrossRepositorySpace(t *testing.T) {
	target := Target{
		ProviderOrigin: "https://pds.example.test",
		SpaceURI:       "ats://did:plc:other/email.atmos.mailbox/default",
		RepoDID:        "did:plc:targetowner",
		Epoch:          "epoch",
	}
	if err := target.ValidateFor("did:plc:targetowner"); err == nil {
		t.Fatal("cross-repository space target was accepted")
	}
}
