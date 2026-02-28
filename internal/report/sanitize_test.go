package report

import "testing"

func TestSanitizeTextAndURL(t *testing.T) {
	in := "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456 token=supersecretvalue1234567890"
	got := SanitizeText(in)
	if got == in {
		t.Fatalf("expected sanitized text, got unchanged")
	}

	u := "https://example.com/api?token=abc123456789012345678901&x=1"
	su := SanitizeURL(u)
	if su == u {
		t.Fatalf("expected sanitized URL, got unchanged")
	}
	if su == "" {
		t.Fatalf("sanitized URL must not be empty")
	}
}
