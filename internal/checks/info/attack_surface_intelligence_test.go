package info

import "testing"

func TestIsLikelyAPIPathCandidate(t *testing.T) {
	cases := []struct {
		in              string
		requireAPIToken bool
		want            bool
	}{
		{"/api/users", true, true},
		{"/v1/profile", true, true},
		{"/graphql", true, true},
		{"/service/health", true, true},
		{"/assets/app.js", true, false},
		{"/static/app.css", true, false},
		{"/images/logo.png", true, false},
		{"/contributors", true, false},
		{"/contributors", false, true},
		{"", true, false},
	}

	for _, tc := range cases {
		got := isLikelyAPIPathCandidate(tc.in, tc.requireAPIToken)
		if got != tc.want {
			t.Fatalf("isLikelyAPIPathCandidate(%q, %v) = %v, want %v", tc.in, tc.requireAPIToken, got, tc.want)
		}
	}
}

func TestNormalizePathCandidate(t *testing.T) {
	in := "/api/users?debug=true"
	got := normalizePathCandidate(in, true)
	if got != "/api/users" {
		t.Fatalf("normalizePathCandidate(%q) = %q, want %q", in, got, "/api/users")
	}

	if v := normalizePathCandidate("/assets/app.js", true); v != "" {
		t.Fatalf("normalizePathCandidate(static) = %q, want empty", v)
	}

	if v := normalizePathCandidate("/contributors?tab=all", false); v != "/contributors" {
		t.Fatalf("normalizePathCandidate(non-api, permissive) = %q, want %q", v, "/contributors")
	}
}

func TestASIDocsAndWebSocketPathSignals(t *testing.T) {
	if !isLikelyAPIDocsPath("/v3/api-docs") {
		t.Fatal("expected /v3/api-docs to be recognized as docs path")
	}
	if !isLikelyAPIDocsPath("/swagger-ui/index.html") {
		t.Fatal("expected swagger-ui path to be recognized as docs path")
	}
	if isLikelyAPIDocsPath("/assets/app.js") {
		t.Fatal("did not expect static asset path to be recognized as docs path")
	}

	if !isLikelyWebSocketPath("/ws/notifications") {
		t.Fatal("expected websocket path signal")
	}
	if !isLikelyWebSocketPath("/sockjs/info") {
		t.Fatal("expected sockjs path signal")
	}
	if isLikelyWebSocketPath("/profile/settings") {
		t.Fatal("did not expect normal route to be websocket path")
	}
}
