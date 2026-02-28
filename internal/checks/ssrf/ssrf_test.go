package ssrf

import "testing"

func TestIsInternalLikeSSRFValue(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"http://127.0.0.1/admin", true},
		{"http://169.254.169.254/latest/meta-data/", true},
		{"http://metadata.google.internal/computeMetadata/v1/", true},
		{"https://example.com/callback", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := isInternalLikeSSRFValue(tc.in); got != tc.want {
			t.Fatalf("isInternalLikeSSRFValue(%q)=%v want %v", tc.in, got, tc.want)
		}
	}
}

func TestIsUnsafeSSRFScheme(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"file:///etc/passwd", true},
		{"gopher://127.0.0.1:11211/_stats", true},
		{"data:text/plain,hello", true},
		{"http://example.com", false},
	}
	for _, tc := range cases {
		if got := isUnsafeSSRFScheme(tc.in); got != tc.want {
			t.Fatalf("isUnsafeSSRFScheme(%q)=%v want %v", tc.in, got, tc.want)
		}
	}
}

func TestDetectMarkerSignal(t *testing.T) {
	body := `{"instanceId":"i-12345","meta-data":"ok"}`
	base := `{"status":"ok"}`
	ok, evidence := detectMarkerSignal(body, base, []string{"instanceId", "meta-data"})
	if !ok {
		t.Fatal("expected marker signal")
	}
	if evidence == "" {
		t.Fatal("expected evidence")
	}
}
