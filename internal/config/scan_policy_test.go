package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadScanPolicyFromPRS(t *testing.T) {
	tmp := t.TempDir()
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error: %v", err)
	}
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("Chdir(tmp) error: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldwd) })

	content := "max_concurrency: 9\nrequest_budget: 777\nactive_cross_domain: true\npassive_profile: strict\ntop_remediation_limit: 7\nasi_max_shadow_candidates: 15\nasi_require_api_token: false\ninfoleak_min_stack_signals: 3\ninfoleak_min_body_len: 120\nsecrets_entropy_min: 3.5\nsqli_min_diff_bytes: 120\nsqli_min_diff_ratio: 0.2\n"
	if err := os.WriteFile(filepath.Join(tmp, ".prs.yaml"), []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	p := LoadScanPolicyFromPRS()
	if p.MaxConcurrency != 9 {
		t.Fatalf("unexpected MaxConcurrency: %d", p.MaxConcurrency)
	}
	if p.RequestBudget != 777 {
		t.Fatalf("unexpected RequestBudget: %d", p.RequestBudget)
	}
	if !p.ActiveCrossDomain {
		t.Fatalf("expected ActiveCrossDomain=true")
	}
	if p.PassiveProfile != "strict" {
		t.Fatalf("unexpected PassiveProfile: %s", p.PassiveProfile)
	}
	if p.TopRemediationLimit != 7 {
		t.Fatalf("unexpected TopRemediationLimit: %d", p.TopRemediationLimit)
	}
	if p.ASIMaxShadowCandidates != 15 {
		t.Fatalf("unexpected ASIMaxShadowCandidates: %d", p.ASIMaxShadowCandidates)
	}
	if p.ASIRequireAPIToken {
		t.Fatalf("expected ASIRequireAPIToken=false")
	}
	if p.InfoLeakMinStackSignals != 3 {
		t.Fatalf("unexpected InfoLeakMinStackSignals: %d", p.InfoLeakMinStackSignals)
	}
	if p.InfoLeakMinBodyLen != 120 {
		t.Fatalf("unexpected InfoLeakMinBodyLen: %d", p.InfoLeakMinBodyLen)
	}
	if p.SecretsEntropyMin != 3.5 {
		t.Fatalf("unexpected SecretsEntropyMin: %f", p.SecretsEntropyMin)
	}
	if p.SQLiMinDiffBytes != 120 {
		t.Fatalf("unexpected SQLiMinDiffBytes: %d", p.SQLiMinDiffBytes)
	}
	if p.SQLiMinDiffRatio != 0.2 {
		t.Fatalf("unexpected SQLiMinDiffRatio: %f", p.SQLiMinDiffRatio)
	}
}
