package network

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/MOYARU/prs/internal/checks"
	ctxpkg "github.com/MOYARU/prs/internal/checks/context"
	"github.com/MOYARU/prs/internal/engine"
	msges "github.com/MOYARU/prs/internal/messages"
	"github.com/MOYARU/prs/internal/report"
)

func CheckTransportSecurity(ctx *ctxpkg.Context) ([]report.Finding, error) {
	if ctx.InitialURL == nil {
		return nil, nil
	}

	var findings []report.Finding

	if ctx.InitialURL.Scheme != "https" {
		msg := msges.GetMessage("HTTPS_NOT_USED")
		findings = append(findings, report.Finding{
			ID:       "HTTPS_NOT_USED",
			Category: string(checks.CategoryNetwork),
			Severity: report.SeverityHigh,
			Title:    msg.Title,
			Message:  msg.Message,
			Fix:      msg.Fix,
		})
	}

	if ctx.InitialURL.Scheme == "http" && !ctx.RedirectedToHTTPS {
		msg := msges.GetMessage("HTTP_TO_HTTPS_REDIRECT_MISSING")
		findings = append(findings, report.Finding{
			ID:       "HTTP_TO_HTTPS_REDIRECT_MISSING",
			Category: string(checks.CategoryNetwork),
			Severity: report.SeverityHigh,
			Title:    msg.Title,
			Message:  msg.Message,
			Fix:      msg.Fix,
		})
	}

	if ctx.FinalURL != nil && ctx.FinalURL.Scheme == "http" && ctx.InitialURL.Scheme == "https" {
		msg := msges.GetMessage("HTTPS_DOWNGRADE")
		findings = append(findings, report.Finding{
			ID:       "HTTPS_DOWNGRADE",
			Category: string(checks.CategoryNetwork),
			Severity: report.SeverityHigh,
			Title:    msg.Title,
			Message:  msg.Message,
			Fix:      msg.Fix,
		})
	}

	return findings, nil
}

var weakCiphers = map[uint16]string{}

func CheckTLSConfiguration(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding

	if ctx.Response == nil || ctx.Response.TLS == nil {
		return findings, nil
	}

	connState := ctx.Response.TLS
	targetHost := ctx.FinalURL.Hostname()
	currentTime := time.Now()

	for _, minVersion := range []uint16{tls.VersionTLS10, tls.VersionTLS11} {
		func(version uint16) {
			if version >= tls.VersionTLS12 { // Skip if probing for current or stronger versions
				return
			}

			tlsConfig := &tls.Config{
				MinVersion:         version,
				InsecureSkipVerify: true, // Ignore certificate errors for TLS version probing
			}

			tempResult, err := engine.FetchWithTLSConfig(ctx.FinalURL.String(), tlsConfig)
			if err != nil {
				if opErr, ok := err.(*net.OpError); ok && opErr.Op == "read" {
					return
				}
				if _, ok := err.(tls.RecordHeaderError); ok {
					return
				}
				return
			}
			if tempResult.Response != nil {
				defer tempResult.Response.Body.Close()
			}

			if tempResult.Response != nil && tempResult.Response.TLS != nil && tempResult.Response.TLS.Version == version {
				msg := msges.GetMessage("TLS_VERSION_SUPPORTED_V") // ID without %d
				findings = append(findings, report.Finding{
					ID:       fmt.Sprintf("TLS_VERSION_SUPPORTED_V%d", version),
					Category: string(checks.CategoryNetwork),
					Severity: report.SeverityHigh,
					Title:    fmt.Sprintf(msg.Title, tlsVersionToString(version)),
					Message:  fmt.Sprintf(msg.Message, tlsVersionToString(version)),
					Fix:      msg.Fix,
				})
			}
		}(minVersion)
	}

	// If the connection was established using TLS 1.0 or 1.1 with the main fetch
	if connState.Version < tls.VersionTLS12 {
		msg := msges.GetMessage("TLS_VERSION_DETECTED_V") // ID without %d
		findings = append(findings, report.Finding{
			ID:       fmt.Sprintf("TLS_VERSION_DETECTED_V%d", connState.Version),
			Category: string(checks.CategoryNetwork),
			Severity: report.SeverityHigh,
			Title:    fmt.Sprintf(msg.Title, tlsVersionToString(connState.Version)),
			Message:  fmt.Sprintf(msg.Message, tlsVersionToString(connState.Version)),
			Fix:      msg.Fix,
		})
	}

	// --- Check Weak Cipher Suite ---
	cipherName := tls.CipherSuiteName(connState.CipherSuite)
	if reason, ok := weakCiphers[connState.CipherSuite]; ok {
		msg := msges.GetMessage("WEAK_CIPHER_SUITE")
		findings = append(findings, report.Finding{
			ID:       "WEAK_CIPHER_SUITE",
			Category: string(checks.CategoryNetwork),
			Severity: report.SeverityHigh,
			Title:    msg.Title,
			Message:  fmt.Sprintf(msg.Message, cipherName, reason),
			Fix:      msg.Fix,
		})
	} else if connState.Version == tls.VersionTLS12 && !isForwardSecret(connState.CipherSuite) {
		msg := msges.GetMessage("NO_FORWARD_SECRECY_TLS12")
		findings = append(findings, report.Finding{
			ID:       "NO_FORWARD_SECRECY_TLS12",
			Category: string(checks.CategoryNetwork),
			Severity: report.SeverityMedium,
			Title:    msg.Title,
			Message:  fmt.Sprintf(msg.Message, cipherName),
			Fix:      msg.Fix,
		})
	}

	// --- Check Certificate ---
	if len(connState.PeerCertificates) > 0 {
		leafCert := connState.PeerCertificates[0]

		// Certificate Expiration
		if currentTime.After(leafCert.NotAfter) {
			msg := msges.GetMessage("CERTIFICATE_EXPIRED")
			findings = append(findings, report.Finding{
				ID:       "CERTIFICATE_EXPIRED",
				Category: string(checks.CategoryNetwork),
				Severity: report.SeverityHigh,
				Title:    msg.Title,
				Message:  fmt.Sprintf(msg.Message, leafCert.NotAfter.Format("2006-01-02")),
				Fix:      msg.Fix,
			})
		} else if currentTime.AddDate(0, 1, 0).After(leafCert.NotAfter) { // Expires within 1 month
			msg := msges.GetMessage("CERTIFICATE_EXPIRING_SOON")
			findings = append(findings, report.Finding{
				ID:       "CERTIFICATE_EXPIRING_SOON",
				Category: string(checks.CategoryNetwork),
				Severity: report.SeverityMedium,
				Title:    msg.Title,
				Message:  fmt.Sprintf(msg.Message, leafCert.NotAfter.Format("2006-01-02")),
				Fix:      msg.Fix,
			})
		}

		// CN / SAN Mismatch
		if err := leafCert.VerifyHostname(targetHost); err != nil {
			msg := msges.GetMessage("CERTIFICATE_HOSTNAME_MISMATCH")
			findings = append(findings, report.Finding{
				ID:       "CERTIFICATE_HOSTNAME_MISMATCH",
				Category: string(checks.CategoryNetwork),
				Severity: report.SeverityHigh,
				Title:    msg.Title,
				Message:  fmt.Sprintf(msg.Message, targetHost, err.Error()),
				Fix:      msg.Fix,
			})
		}

		// OCSP Stapling
		if len(connState.OCSPResponse) == 0 {
			msg := msges.GetMessage("OCSP_STAPLING_NOT_USED")
			findings = append(findings, report.Finding{
				ID:       "OCSP_STAPLING_NOT_USED",
				Category: string(checks.CategoryNetwork),
				Severity: report.SeverityLow,
				Title:    msg.Title,
				Message:  msg.Message,
				Fix:      msg.Fix,
			})
		}
	}

	return findings, nil
}

func tlsVersionToString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	default:
		return fmt.Sprintf("Unknown (%x)", version)
	}
}

func isForwardSecret(cipherSuite uint16) bool {
	switch cipherSuite {
	case tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256:
		return true
	default:

		if strings.Contains(tls.CipherSuiteName(cipherSuite), "DHE") || strings.Contains(tls.CipherSuiteName(cipherSuite), "ECDHE") {
			return true
		}
		return false
	}
}
