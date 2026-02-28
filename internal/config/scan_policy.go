package config

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

type ScanPolicy struct {
	MaxConcurrency          int
	RequestBudget           int64
	ActiveCrossDomain       bool
	PassiveProfile          string
	TopRemediationLimit     int
	ASIMaxShadowCandidates  int
	ASIRequireAPIToken      bool
	InfoLeakMinStackSignals int
	InfoLeakMinBodyLen      int
	SecretsEntropyMin       float64
	SQLiMinDiffBytes        int
	SQLiMinDiffRatio        float64
}

var scanPolicyCache struct {
	mu      sync.RWMutex
	path    string
	exists  bool
	modTime int64
	policy  ScanPolicy
}

func DefaultScanPolicy() ScanPolicy {
	return ScanPolicy{
		MaxConcurrency:          5,
		RequestBudget:           0, // 0 means auto-calculate
		ActiveCrossDomain:       false,
		PassiveProfile:          "balanced",
		TopRemediationLimit:     10,
		ASIMaxShadowCandidates:  30,
		ASIRequireAPIToken:      true,
		InfoLeakMinStackSignals: 2,
		InfoLeakMinBodyLen:      50,
		SecretsEntropyMin:       3.2,
		SQLiMinDiffBytes:        80,
		SQLiMinDiffRatio:        0.12,
	}
}

// LoadScanPolicyFromPRS reads optional top-level keys from ".prs.yaml":
// max_concurrency: 8
// request_budget: 1200
// active_cross_domain: true
// passive_profile: strict|balanced|aggressive
// top_remediation_limit: 10
// asi_max_shadow_candidates: 30
// asi_require_api_token: true
// infoleak_min_stack_signals: 2
// infoleak_min_body_len: 50
// secrets_entropy_min: 3.2
// sqli_min_diff_bytes: 80
// sqli_min_diff_ratio: 0.12
func LoadScanPolicyFromPRS() ScanPolicy {
	p := DefaultScanPolicy()
	path := ".prs.yaml"
	absPath, err := filepath.Abs(path)
	if err == nil {
		path = absPath
	}

	st, statErr := os.Stat(path)
	if statErr != nil {
		scanPolicyCache.mu.RLock()
		if scanPolicyCache.path == path && !scanPolicyCache.exists {
			cached := scanPolicyCache.policy
			scanPolicyCache.mu.RUnlock()
			return cached
		}
		scanPolicyCache.mu.RUnlock()
		scanPolicyCache.mu.Lock()
		scanPolicyCache.path = path
		scanPolicyCache.exists = false
		scanPolicyCache.modTime = 0
		scanPolicyCache.policy = p
		scanPolicyCache.mu.Unlock()
		return p
	}

	modTime := st.ModTime().UnixNano()
	scanPolicyCache.mu.RLock()
	if scanPolicyCache.path == path && scanPolicyCache.exists && scanPolicyCache.modTime == modTime {
		cached := scanPolicyCache.policy
		scanPolicyCache.mu.RUnlock()
		return cached
	}
	scanPolicyCache.mu.RUnlock()

	f, err := os.Open(path)
	if err != nil {
		return p
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		kv := strings.SplitN(line, ":", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		val := strings.Trim(strings.TrimSpace(kv[1]), `"'`)

		switch key {
		case "max_concurrency":
			if n, err := strconv.Atoi(val); err == nil && n > 0 {
				p.MaxConcurrency = n
			}
		case "request_budget":
			if n, err := strconv.ParseInt(val, 10, 64); err == nil && n >= 0 {
				p.RequestBudget = n
			}
		case "active_cross_domain":
			if b, err := strconv.ParseBool(strings.ToLower(val)); err == nil {
				p.ActiveCrossDomain = b
			}
		case "passive_profile":
			profile := strings.ToLower(strings.TrimSpace(val))
			if profile == "strict" || profile == "balanced" || profile == "aggressive" {
				p.PassiveProfile = profile
			}
		case "top_remediation_limit":
			if n, err := strconv.Atoi(val); err == nil && n > 0 {
				p.TopRemediationLimit = n
			}
		case "asi_max_shadow_candidates":
			if n, err := strconv.Atoi(val); err == nil && n > 0 {
				p.ASIMaxShadowCandidates = n
			}
		case "asi_require_api_token":
			if b, err := strconv.ParseBool(strings.ToLower(val)); err == nil {
				p.ASIRequireAPIToken = b
			}
		case "infoleak_min_stack_signals":
			if n, err := strconv.Atoi(val); err == nil && n > 0 {
				p.InfoLeakMinStackSignals = n
			}
		case "infoleak_min_body_len":
			if n, err := strconv.Atoi(val); err == nil && n > 0 {
				p.InfoLeakMinBodyLen = n
			}
		case "secrets_entropy_min":
			if n, err := strconv.ParseFloat(val, 64); err == nil && n > 0 {
				p.SecretsEntropyMin = n
			}
		case "sqli_min_diff_bytes":
			if n, err := strconv.Atoi(val); err == nil && n > 0 {
				p.SQLiMinDiffBytes = n
			}
		case "sqli_min_diff_ratio":
			if n, err := strconv.ParseFloat(val, 64); err == nil && n > 0 {
				p.SQLiMinDiffRatio = n
			}
		}
	}

	scanPolicyCache.mu.Lock()
	scanPolicyCache.path = path
	scanPolicyCache.exists = true
	scanPolicyCache.modTime = modTime
	scanPolicyCache.policy = p
	scanPolicyCache.mu.Unlock()

	return p
}
