package main

import "testing"

func TestValidateOptionsRequiresExactLoopbackListener(t *testing.T) {
	valid := options{
		Listen: "127.0.0.1:39093", HappyViewOrigin: "http://127.0.0.1:39090",
		HappyViewPublicHost: "happyview.example.test",
		HappyViewBasePath:   "/comail-pds-lab", DID: "did:plc:comailmailboxviewertest", SpaceKey: "default",
		LoginPath: "/comail-pds-lab/login/", PublicOrigin: "https://viewer.example.test", CookiePath: "/comail-pds-mailbox/",
	}
	if err := validateOptions(valid); err != nil {
		t.Fatalf("valid options: %v", err)
	}
	for _, listen := range []string{"0.0.0.0:39093", "[::1]:39093", "localhost:39093", ":39093"} {
		invalid := valid
		invalid.Listen = listen
		if err := validateOptions(invalid); err == nil {
			t.Fatalf("listener %q was accepted", listen)
		}
	}
}

func TestValidateOptionsRequiresPinnedIdentityAndLocalPaths(t *testing.T) {
	valid := options{
		Listen: "127.0.0.1:39093", HappyViewOrigin: "http://127.0.0.1:39090",
		HappyViewPublicHost: "happyview.example.test",
		HappyViewBasePath:   "/comail-pds-lab", DID: "did:plc:comailmailboxviewertest", SpaceKey: "default",
		LoginPath: "/comail-pds-lab/login/", PublicOrigin: "https://viewer.example.test", CookiePath: "/comail-pds-mailbox/",
	}
	tests := []options{
		func() options { value := valid; value.DID = ""; return value }(),
		func() options { value := valid; value.DID = "alice.test"; return value }(),
		func() options { value := valid; value.SpaceKey = "../other"; return value }(),
		func() options { value := valid; value.LoginPath = "https://evil.example/login"; return value }(),
		func() options { value := valid; value.HappyViewPublicHost = "bad.example/path"; return value }(),
	}
	for i, invalid := range tests {
		if err := validateOptions(invalid); err == nil {
			t.Fatalf("invalid option set %d was accepted", i)
		}
	}
}
