package web

import "testing"

func TestCheckSecretsFiltersPlaceholders(t *testing.T) {
	content := `const apiKey = "your_api_key_here"; const token = "replace-me";`
	findings := checkSecrets(content)
	if len(findings) != 0 {
		t.Fatalf("expected no findings for placeholders, got %d", len(findings))
	}
}

func TestCheckSecretsFiltersUUIDLikeToken(t *testing.T) {
	content := `token="82a3cb7d-e38f-467d-b80c-758f19269e5c"`
	findings := checkSecrets(content)
	if len(findings) != 0 {
		t.Fatalf("expected no findings for UUID-like token, got %d", len(findings))
	}
}

func TestCheckSecretsDetectsKnownPatterns(t *testing.T) {
	content := `const aws = "AKIA1234567890ABCDEF";`
	findings := checkSecrets(content)
	if len(findings) == 0 {
		t.Fatal("expected finding for AWS key pattern")
	}
}

func TestCheckSecretsDetectsGoogleAPIKey(t *testing.T) {
	content := `const g = "AIzaSyD8fJf2mP9x1R2s3T4u5V6w7X8y9Z0abCDef";`
	findings := checkSecrets(content)
	if len(findings) == 0 {
		t.Fatal("expected finding for Google/Firebase API key pattern")
	}
}
