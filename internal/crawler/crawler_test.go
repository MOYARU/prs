package crawler

import "testing"

func TestNormalizeURL(t *testing.T) {
	c, err := New("https://Example.com", 1, 0)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	tests := []struct {
		raw  string
		want string
		ok   bool
	}{
		{raw: "HTTPS://Example.com", want: "https://example.com/", ok: true},
		{raw: "https://example.com:443/path/", want: "https://example.com/path", ok: true},
		{raw: "http://example.com:80/a?b=2&a=1", want: "http://example.com/a?a=1&b=2", ok: true},
		{raw: "javascript:alert(1)", want: "", ok: false},
	}

	for _, tt := range tests {
		got, ok := c.normalizeURL(tt.raw)
		if ok != tt.ok {
			t.Fatalf("normalizeURL(%q) ok=%v want=%v", tt.raw, ok, tt.ok)
		}
		if got != tt.want {
			t.Fatalf("normalizeURL(%q) got=%q want=%q", tt.raw, got, tt.want)
		}
	}
}

func TestDedupeAndLimitLinks(t *testing.T) {
	in := []string{
		" /a ", "/a", "", "   ", "/b", "/c", "/b", "/d",
	}

	got := dedupeAndLimitLinks(in, 3)
	want := []string{"/a", "/b", "/c"}

	if len(got) != len(want) {
		t.Fatalf("len mismatch: got=%d want=%d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("index %d mismatch: got=%q want=%q", i, got[i], want[i])
		}
	}
}
