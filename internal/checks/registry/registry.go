package registry

import (
	"github.com/MOYARU/prs/internal/checks"
	"github.com/MOYARU/prs/internal/checks/api"
	"github.com/MOYARU/prs/internal/checks/application"
	"github.com/MOYARU/prs/internal/checks/authsession"
	"github.com/MOYARU/prs/internal/checks/components"
	ctxpkg "github.com/MOYARU/prs/internal/checks/context"
	"github.com/MOYARU/prs/internal/checks/deserialization"
	"github.com/MOYARU/prs/internal/checks/headers"
	"github.com/MOYARU/prs/internal/checks/http"
	"github.com/MOYARU/prs/internal/checks/info"
	"github.com/MOYARU/prs/internal/checks/injection"
	"github.com/MOYARU/prs/internal/checks/input"
	"github.com/MOYARU/prs/internal/checks/network"
	"github.com/MOYARU/prs/internal/checks/packet"
	"github.com/MOYARU/prs/internal/checks/ssrf"
	"github.com/MOYARU/prs/internal/checks/web"
)

func DefaultChecks() []checks.Check {
	return []checks.Check{
		{
			ID:          "NETWORK_TRANSPORT_SECURITY",
			Category:    checks.CategoryNetwork,
			Title:       "Network Transport Security Check",
			Description: "Checks HTTPS usage and secure transport baseline settings.",
			Mode:        ctxpkg.Passive,
			Run:         network.CheckTransportSecurity,
		},
		{
			ID:          "SECURITY_HEADERS",
			Category:    checks.CategorySecurityHeaders,
			Title:       "Security Headers Check",
			Description: "Checks key security headers such as CSP, HSTS, and X-Frame-Options.",
			Mode:        ctxpkg.Passive,
			Run:         headers.CheckSecurityHeaders,
		},
		{
			ID:          "TLS_CONFIGURATION",
			Category:    checks.CategoryNetwork,
			Title:       "TLS Configuration Check",
			Description: "Checks TLS versions, weak ciphers, certificate validity, hostname match, and OCSP stapling.",
			Mode:        ctxpkg.Passive,
			Run:         network.CheckTLSConfiguration,
		},
		{
			ID:          "HTTP_CONFIGURATION",
			Category:    checks.CategoryHTTPProtocol,
			Title:       "HTTP Protocol Configuration Check",
			Description: "Checks risky HTTP methods and protocol-level misconfigurations.",
			Mode:        ctxpkg.Active,
			Run:         http.CheckHTTPConfiguration,
		},
		{
			ID:          "AUTH_SESSION_HARDENING",
			Category:    checks.CategoryAuthSession,
			Title:       "Auth/Session Hardening Check",
			Description: "Checks cookie hardening attributes such as Secure, HttpOnly, SameSite, and expiration policy.",
			Mode:        ctxpkg.Passive,
			Run:         authsession.CheckAuthSessionHardening,
		},
		{
			ID:          "SESSION_MANAGEMENT",
			Category:    checks.CategoryAuthSession,
			Title:       "Session Management Check",
			Description: "Checks session lifecycle and cookie/session behavior around authentication flows.",
			Mode:        ctxpkg.Active,
			Run:         authsession.CheckSessionManagement,
		},
		{
			ID:          "PARAMETER_POLLUTION",
			Category:    checks.CategoryInputHandling,
			Title:       "Parameter Pollution Check",
			Description: "Checks how duplicate parameters are processed and whether ambiguous parsing creates security issues.",
			Mode:        ctxpkg.Active,
			Run:         input.CheckParameterPollution,
		},
		{
			ID:          "CONTENT_TYPE_CONFUSION",
			Category:    checks.CategoryAPISecurity,
			Title:       "Content-Type Confusion Check",
			Description: "Checks JSON API behavior for mismatched Content-Type and Accept headers.",
			Mode:        ctxpkg.Active,
			Run:         api.CheckContentTypeConfusion,
		},
		{
			ID:          "METHOD_OVERRIDE_ALLOWED",
			Category:    checks.CategoryAPISecurity,
			Title:       "HTTP Method Override Check",
			Description: "Checks whether unsafe method override headers are accepted.",
			Mode:        ctxpkg.Active,
			Run:         api.CheckMethodOverride,
		},
		{
			ID:          "CORS_CONFIGURATION",
			Category:    checks.CategoryNetwork,
			Title:       "CORS Configuration Check",
			Description: "Checks CORS policy for risky trust relationships and origin handling.",
			Mode:        ctxpkg.Passive,
			Run:         network.CheckCORSConfiguration,
		},
		{
			ID:          "INFORMATION_LEAKAGE",
			Category:    checks.CategoryInformationLeakage,
			Title:       "Information Leakage Check",
			Description: "Checks for exposed debug data, stack traces, framework fingerprints, and sensitive metadata.",
			Mode:        ctxpkg.Passive,
			Run:         info.CheckInformationLeakage,
		},
		{
			ID:          "JSON_UNEXPECTED_FIELD_INSERTION",
			Category:    checks.CategoryAPISecurity,
			Title:       "JSON Unexpected Field Insertion Check",
			Description: "Checks whether the API accepts unexpected JSON fields without validation.",
			Mode:        ctxpkg.Active,
			Run:         api.CheckJSONUnexpectedField,
		},
		{
			ID:          "RATE_LIMIT_ABSENCE",
			Category:    checks.CategoryAPISecurity,
			Title:       "Rate Limit Absence Check",
			Description: "Checks for missing rate-limit signals such as Retry-After or X-RateLimit headers.",
			Mode:        ctxpkg.Passive,
			Run:         api.CheckRateLimitAbsence,
		},
		{
			ID:          "APPLICATION_SECURITY",
			Category:    checks.CategoryAppLogic,
			Title:       "Application Security Check",
			Description: "Checks reflection, IDOR indicators, CSRF token presence, and business-logic issues.",
			Mode:        ctxpkg.Active,
			Run:         application.CheckApplicationSecurity,
		},
		{
			ID:          "PACKET_ANALYSIS",
			Category:    checks.CategoryHTTPProtocol,
			Title:       "Packet-based Anomaly Analysis",
			Description: "Analyzes request/response patterns for protocol anomalies and suspicious behavior.",
			Mode:        ctxpkg.Passive,
			Run:         packet.CheckPacketAnomalies,
		},
		{
			ID:          "WEB_CONTENT_EXPOSURE",
			Category:    checks.CategoryFileExposure,
			Title:       "Web Content and File Exposure Check",
			Description: "Checks exposed content, unsafe resources, and mixed-content related risks.",
			Mode:        ctxpkg.Passive,
			Run:         web.CheckWebContentExposure,
		},
		{
			ID:          "SQL_INJECTION",
			Category:    checks.CategoryInputHandling,
			Title:       "SQL Injection Check",
			Description: "Checks for error-based SQL injection indicators in query parameter handling.",
			Mode:        ctxpkg.Active,
			Run:         injection.CheckSQLInjection,
		},
		{
			ID:          "REFLECTED_XSS",
			Category:    checks.CategoryClientSecurity,
			Title:       "Reflected XSS Check",
			Description: "Checks whether injected payloads are reflected and executable in responses.",
			Mode:        ctxpkg.Active,
			Run:         injection.CheckReflectedXSS,
		},
		// TODO: Add boolean-based blind SQL injection check.
		{
			ID:          "BLIND_SQL_INJECTION",
			Category:    checks.CategoryInputHandling,
			Title:       "Blind SQL Injection Check (Time-based)",
			Description: "Checks for time-based response delays caused by SQL payload injection.",
			Mode:        ctxpkg.Active,
			Run:         injection.CheckBlindSQLInjection,
		},
		{
			ID:          "OS_COMMAND_INJECTION",
			Category:    checks.CategoryInputHandling,
			Title:       "OS Command Injection Check (Time-based)",
			Description: "Checks for command-injection indicators via time-delay payload execution.",
			Mode:        ctxpkg.Active,
			Run:         injection.CheckOSCommandInjection,
		},
		{
			ID:          "SSTI_INJECTION",
			Category:    checks.CategoryInputHandling,
			Title:       "SSTI Check",
			Description: "Checks server-side template injection indicators in rendered responses.",
			Mode:        ctxpkg.Active,
			Run:         injection.CheckSSTI,
		},
		{
			ID:          "XXE_INJECTION",
			Category:    checks.CategoryInputHandling,
			Title:       "XXE Check",
			Description: "Checks XML parser behavior for external entity resolution risks.",
			Mode:        ctxpkg.Active,
			Run:         injection.CheckXXE,
		},
		// TODO: Add Stored XSS, DOM XSS, NoSQL, and LDAP injection checks.
		{
			ID:          "SSRF_DETECTION",
			Category:    checks.CategorySSRF,
			Title:       "SSRF Detection",
			Description: "Checks whether the server can be abused to send requests to unintended targets.",
			Mode:        ctxpkg.Active,
			Run:         ssrf.CheckSSRF,
		},
		{
			ID:          "INSECURE_DESERIALIZATION",
			Category:    checks.CategoryIntegrityFailures,
			Title:       "Insecure Deserialization Detection",
			Description: "Checks serialized input handling for unsafe deserialization patterns.",
			Mode:        ctxpkg.Passive,
			Run:         deserialization.CheckInsecureDeserialization,
		},
		{
			ID:          "VULNERABLE_COMPONENTS",
			Category:    checks.CategoryVulnerableComponents,
			Title:       "Vulnerable Component Identification",
			Description: "Checks server/client metadata for known outdated or vulnerable components.",
			Mode:        ctxpkg.Passive,
			Run:         components.CheckVulnerableComponents,
		},
	}
}
