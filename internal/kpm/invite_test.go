package kpm

import "testing"

func TestDecodeInvite(t *testing.T) {
	// base64url({"v":1,"url":"https://127.0.0.1:8443","ca_fp":"abc123","token":"test","user":"alice","exp":9999999999})
	code := "kpmi1_eyJ2IjoxLCJ1cmwiOiJodHRwczovLzEyNy4wLjAuMTo4NDQzIiwiY2FfZnAiOiJhYmMxMjMiLCJ0b2tlbiI6InRlc3QiLCJ1c2VyIjoiYWxpY2UiLCJleHAiOjk5OTk5OTk5OTl9"
	got, err := DecodeInvite(code)
	if err != nil {
		t.Fatal(err)
	}
	if got.ServerURL != "https://127.0.0.1:8443" || got.UserID != "alice" {
		t.Fatalf("unexpected payload: %+v", got)
	}
}

func TestIsInviteCode(t *testing.T) {
	if !IsInviteCode("kpmi1_abc") {
		t.Fatal("expected invite prefix match")
	}
	if IsInviteCode("not-an-invite") {
		t.Fatal("expected false")
	}
}
