package messages

import (
	"fmt"
	"strings"
	"sync"
)

type Language int

const (
	LangKO Language = iota
	LangEN
)

var (
	CurrentLanguage = LangEN
	langMu          sync.RWMutex
)

func SetLanguage(l Language) {
	langMu.Lock()
	defer langMu.Unlock()
	CurrentLanguage = l
}

type MessageDetail struct {
	Title                      string
	Message                    string
	Fix                        string
	IsPotentiallyFalsePositive bool
}

type rawMessageDetail struct {
	TitleKO                    string
	TitleEN                    string
	MessageKO                  string
	MessageEN                  string
	FixKO                      string
	FixEN                      string
	IsPotentiallyFalsePositive bool
}

var findingMessages = map[string]rawMessageDetail{
	"CORS_WILDCARD_ORIGIN": {
		TitleKO:                    "CORS 와일드카드 Origin 허용",
		TitleEN:                    "CORS Wildcard Origin Allowed",
		MessageKO:                  "Access-Control-Allow-Origin 헤더가 '*'로 설정되어 있어 모든 도메인에서의 리소스 접근을 허용합니다. 민감한 정보가 노출될 위험이 있습니다.",
		MessageEN:                  "The Access-Control-Allow-Origin header is set to '*', allowing resource access from any domain. This risks exposing sensitive information.",
		FixKO:                      "Access-Control-Allow-Origin 헤더에 와일드카드('*') 대신 신뢰할 수 있는 특정 도메인을 명시하십시오. 여러 도메인을 지원해야 하는 경우, 서버 측에서 Origin 헤더를 검증한 후 화이트리스트에 있는 경우에만 해당 Origin을 반환하도록 구현해야 합니다.",
		FixEN:                      "Specify a trusted domain in the Access-Control-Allow-Origin header instead of a wildcard ('*'). If multiple domains must be supported, validate the Origin header on the server side and return the Origin only if it is whitelisted.",
		IsPotentiallyFalsePositive: false,
	},
	"CORS_ORIGIN_REFLECTION": {
		TitleKO:                    "CORS Origin Reflection 취약점",
		TitleEN:                    "CORS Origin Reflection Vulnerability",
		MessageKO:                  "요청의 Origin 헤더 '%s'가 Access-Control-Allow-Origin에 그대로 반영됩니다. 이는 임의의 도메인에서 리소스 접근을 허용할 수 있습니다.",
		MessageEN:                  "The request's Origin header '%s' is reflected in Access-Control-Allow-Origin. This may allow resource access from arbitrary domains.",
		FixKO:                      "Access-Control-Allow-Origin 헤더에 허용된 Origin(화이트리스트)만 명시적으로 지정하고, 요청 Origin을 그대로 반영하지 마십시오.",
		FixEN:                      "Explicitly specify only allowed Origins (whitelist) in the Access-Control-Allow-Origin header, and do not reflect the request Origin directly.",
		IsPotentiallyFalsePositive: false,
	},
	"HTTPS_NOT_USED": {
		TitleKO:                    "HTTPS 미사용",
		TitleEN:                    "HTTPS Not Used",
		MessageKO:                  "HTTPS가 사용되지 않아 전송 구간에서 데이터 노출 위험이 있습니다",
		MessageEN:                  "HTTPS is not used, posing a risk of data exposure during transmission.",
		FixKO:                      "Let's Encrypt와 같은 신뢰할 수 있는 인증 기관(CA)에서 유효한 TLS 인증서를 발급받아 웹 서버에 적용하십시오. 모든 프로덕션 트래픽은 암호화된 채널(HTTPS)을 통해서만 전송되어야 합니다.",
		FixEN:                      "Obtain a valid TLS certificate from a trusted CA (like Let's Encrypt) and apply it to the web server. All production traffic should be transmitted over encrypted channels (HTTPS).",
		IsPotentiallyFalsePositive: false,
	},
	"HTTP_TO_HTTPS_REDIRECT_MISSING": {
		TitleKO:                    "HTTP → HTTPS 강제 리다이렉트 미설정",
		TitleEN:                    "HTTP to HTTPS Redirect Missing",
		MessageKO:                  "HTTP 요청이 HTTPS로 강제 전환되지 않습니다",
		MessageEN:                  "HTTP requests are not forcibly redirected to HTTPS.",
		FixKO:                      "웹 서버 설정(Nginx, Apache 등)에서 80번 포트(HTTP)로 들어오는 모든 요청을 443번 포트(HTTPS)로 301(Moved Permanently) 리다이렉트하도록 구성하십시오.",
		FixEN:                      "Configure the web server (Nginx, Apache, etc.) to redirect all requests on port 80 (HTTP) to port 443 (HTTPS) with a 301 (Moved Permanently) status.",
		IsPotentiallyFalsePositive: false,
	},
	"HTTPS_DOWNGRADE": {
		TitleKO:                    "HTTPS 다운그레이드 감지",
		TitleEN:                    "HTTPS Downgrade Detected",
		MessageKO:                  "HTTPS 요청이 HTTP로 다운그레이드되었습니다",
		MessageEN:                  "An HTTPS request was downgraded to HTTP.",
		FixKO:                      "HTTPS에서 HTTP로 리다이렉트하지 않도록 구성하세요",
		FixEN:                      "Configure the server not to redirect from HTTPS to HTTP.",
		IsPotentiallyFalsePositive: false,
	},
	"TLS_VERSION_SUPPORTED_V": { // %s is not part of the ID, it's a format specifier
		TitleKO:                    "TLS %s 지원",
		TitleEN:                    "TLS %s Supported",
		MessageKO:                  "대상 서버가 더 이상 사용되지 않는 안전하지 않은 TLS %s 프로토콜을 지원합니다.",
		MessageEN:                  "The target server supports the insecure and deprecated TLS %s protocol.",
		FixKO:                      "웹 서버의 SSL/TLS 설정에서 SSLv3, TLS 1.0, TLS 1.1과 같은 구형 프로토콜을 비활성화하십시오. 보안을 위해 TLS 1.2 및 TLS 1.3 버전만 활성화하는 것을 권장합니다.",
		FixEN:                      "Disable legacy protocols like SSLv3, TLS 1.0, and TLS 1.1 in the web server's SSL/TLS settings. It is recommended to enable only TLS 1.2 and TLS 1.3 for security.",
		IsPotentiallyFalsePositive: false,
	},
	"TLS_VERSION_DETECTED_V": { // %s is not part of the ID, it's a format specifier
		TitleKO:                    "취약한 TLS %s 사용",
		TitleEN:                    "Vulnerable TLS %s Used",
		MessageKO:                  "대상 서버가 취약한 TLS %s 프로토콜을 사용하여 연결을 설정했습니다.",
		MessageEN:                  "The target server established a connection using the vulnerable TLS %s protocol.",
		FixKO:                      "웹 서버의 SSL/TLS 설정에서 SSLv3, TLS 1.0, TLS 1.1과 같은 구형 프로토콜을 비활성화하십시오. 보안을 위해 TLS 1.2 및 TLS 1.3 버전만 활성화하는 것을 권장합니다.",
		FixEN:                      "Disable legacy protocols like SSLv3, TLS 1.0, and TLS 1.1 in the web server's SSL/TLS settings. It is recommended to enable only TLS 1.2 and TLS 1.3 for security.",
		IsPotentiallyFalsePositive: false,
	},
	"WEAK_CIPHER_SUITE": {
		TitleKO:                    "약한 Cipher Suite 사용",
		TitleEN:                    "Weak Cipher Suite Used",
		MessageKO:                  "대상 서버가 약한 암호 스위트 '%s'를 사용합니다. 이유: %s",
		MessageEN:                  "The target server uses a weak cipher suite '%s'. Reason: %s",
		FixKO:                      "RC4, 3DES, CBC 모드 등 취약한 암호 알고리즘을 사용하는 Cipher Suite를 비활성화하십시오. 대신 Forward Secrecy를 지원하는 ECDHE 또는 DHE 키 교환 방식과 AES-GCM, ChaCha20-Poly1305와 같은 강력한 암호화 알고리즘을 우선순위로 설정하십시오.",
		FixEN:                      "Disable cipher suites using weak encryption algorithms like RC4, 3DES, or CBC mode. Prioritize strong encryption algorithms like AES-GCM or ChaCha20-Poly1305 with Forward Secrecy (ECDHE or DHE).",
		IsPotentiallyFalsePositive: false,
	},
	"NO_FORWARD_SECRECY_TLS12": {
		TitleKO:                    "Forward Secrecy 미적용 (TLS 1.2)",
		TitleEN:                    "Forward Secrecy Not Applied (TLS 1.2)",
		MessageKO:                  "TLS 1.2를 사용하지만, 현재 암호 스위트 '%s'는 Forward Secrecy를 제공하지 않을 수 있습니다.",
		MessageEN:                  "TLS 1.2 is used, but the current cipher suite '%s' may not provide Forward Secrecy.",
		FixKO:                      "서버에서 ECDHE 또는 DHE 기반의 강력한 Forward Secrecy를 제공하는 암호 스위트(예: AES-GCM, ChaCha20-Poly1305 기반)만 사용하도록 설정하십시오.",
		FixEN:                      "Configure the server to use only cipher suites that provide strong Forward Secrecy based on ECDHE or DHE (e.g., AES-GCM, ChaCha20-Poly1305).",
		IsPotentiallyFalsePositive: false,
	},
	"CERTIFICATE_EXPIRED": {
		TitleKO:                    "인증서 만료",
		TitleEN:                    "Certificate Expired",
		MessageKO:                  "TLS 인증서가 %s에 만료되었습니다.",
		MessageEN:                  "The TLS certificate expired on %s.",
		FixKO:                      "만료된 TLS 인증서를 갱신하십시오.",
		FixEN:                      "Renew the expired TLS certificate.",
		IsPotentiallyFalsePositive: false,
	},
	"CERTIFICATE_EXPIRING_SOON": {
		TitleKO:                    "인증서 만료 임박",
		TitleEN:                    "Certificate Expiring Soon",
		MessageKO:                  "TLS 인증서가 한 달 이내인 %s에 만료될 예정입니다.",
		MessageEN:                  "The TLS certificate is scheduled to expire within a month on %s.",
		FixKO:                      "TLS 인증서 갱신을 계획하십시오.",
		FixEN:                      "Plan to renew the TLS certificate.",
		IsPotentiallyFalsePositive: false,
	},
	"CERTIFICATE_HOSTNAME_MISMATCH": {
		TitleKO:                    "인증서 호스트네임 불일치",
		TitleEN:                    "Certificate Hostname Mismatch",
		MessageKO:                  "TLS 인증서의 CN/SAN 필드가 대상 호스트 '%s'와 일치하지 않습니다. 오류: %s",
		MessageEN:                  "The CN/SAN field of the TLS certificate does not match the target host '%s'. Error: %s",
		FixKO:                      "인증서의 Common Name (CN) 또는 Subject Alternative Name (SAN) 필드가 대상 도메인과 정확히 일치하는 유효한 TLS 인증서를 사용하십시오.",
		FixEN:                      "Use a valid TLS certificate where the Common Name (CN) or Subject Alternative Name (SAN) fields exactly match the target domain.",
		IsPotentiallyFalsePositive: false,
	},
	"OCSP_STAPLING_NOT_USED": {
		TitleKO:                    "OCSP Stapling 미사용",
		TitleEN:                    "OCSP Stapling Not Used",
		MessageKO:                  "OCSP Stapling이 활성화되지 않아 클라이언트가 인증서 해지 상태를 확인하는 데 추가 요청이 필요할 수 있습니다.",
		MessageEN:                  "OCSP Stapling is not enabled, which may require clients to make additional requests to check certificate revocation status.",
		FixKO:                      "서버에서 OCSP Stapling을 활성화하여 클라이언트의 TLS 핸드셰이크 성능을 향상시키고 개인 정보 보호를 강화하십시오.",
		FixEN:                      "Enable OCSP Stapling on the server to improve client TLS handshake performance and enhance privacy.",
		IsPotentiallyFalsePositive: false,
	},
	"INPUT_REFLECTION_DETECTED": {
		TitleKO:                    "입력값 Reflection 감지",
		TitleEN:                    "Input Reflection Detected",
		MessageKO:                  "URL 파라미터 '%s'의 입력값이 응답 본문에 반영되었습니다. 이는 XSS 공격으로 이어질 수 있습니다.",
		MessageEN:                  "Input from URL parameter '%s' is reflected in the response body. This can lead to XSS attacks.",
		FixKO:                      "사용자 입력값을 출력 시 적절한 인코딩(HTML 엔티티, URL 인코딩 등)을 적용하여 Reflection을 방지하십시오.",
		FixEN:                      "Apply appropriate encoding (HTML entities, URL encoding, etc.) when outputting user input to prevent reflection.",
		IsPotentiallyFalsePositive: false,
	},
	"IDOR_POSSIBLE": {
		TitleKO:                    "IDOR 가능성 감지",
		TitleEN:                    "Possible IDOR Detected",
		MessageKO:                  "숫자 ID 변경 (%s) 시 응답 내용이 변경되었습니다. 이는 다른 사용자의 리소스에 접근 가능함을 의미할 수 있습니다.",
		MessageEN:                  "Response content changed when modifying numeric ID (%s). This may indicate access to other users' resources.",
		FixKO:                      "숫자 ID를 사용하는 리소스 접근 시 서버 측에서 적절한 접근 제어 (예: 소유자 확인)를 구현하십시오.",
		FixEN:                      "Implement appropriate access control (e.g., owner verification) on the server side when accessing resources using numeric IDs.",
		IsPotentiallyFalsePositive: true,
	},
	"IDOR_RESOURCE_GUESSING": {
		TitleKO:                    "IDOR 기반 리소스 추정 가능성",
		TitleEN:                    "IDOR-based Resource Guessing",
		MessageKO:                  "존재하지 않는 ID에 접근 시도 후 ID 변경 (%s)으로 유효한 리소스에 접근했습니다. 이는 다른 사용자의 리소스에 접근 가능함을 의미할 수 있습니다.",
		MessageEN:                  "Accessed a valid resource by changing ID (%s) after attempting to access a non-existent ID. This may indicate access to other users' resources.",
		FixKO:                      "숫자 ID를 사용하는 리소스 접근 시 서버 측에서 적절한 접근 제어 (예: 소유자 확인)를 구현하십시오.",
		FixEN:                      "Implement appropriate access control (e.g., owner verification) on the server side when accessing resources using numeric IDs.",
		IsPotentiallyFalsePositive: true,
	},
	"CSRF_TOKEN_POSSIBLY_MISSING": {
		TitleKO:                    "CSRF 토큰 부재 가능성",
		TitleEN:                    "CSRF Token Possibly Missing",
		MessageKO:                  "HTML 폼에서 CSRF(Cross-Site Request Forgery) 공격 방어를 위한 토큰이 발견되지 않았을 수 있습니다.",
		MessageEN:                  "A token to prevent CSRF (Cross-Site Request Forgery) attacks may be missing from the HTML form.",
		FixKO:                      "모든 상태 변경 요청을 처리하는 폼에 CSRF 토큰을 포함하고, 토큰의 유효성을 검증하십시오.",
		FixEN:                      "Include a CSRF token in forms handling state-changing requests and validate the token's validity.",
		IsPotentiallyFalsePositive: true,
	},
	"GRAPHQL_INTROSPECTION_ENABLED": {
		TitleKO:                    "GraphQL Introspection 활성화",
		TitleEN:                    "GraphQL Introspection Enabled",
		MessageKO:                  "GraphQL Introspection 기능이 '%s' 경로에서 활성화되어 스키마 정보가 노출될 수 있습니다.",
		MessageEN:                  "GraphQL Introspection is enabled on path '%s', potentially exposing schema information.",
		FixKO:                      "운영 환경에서는 GraphQL Introspection 기능을 비활성화하여 API의 내부 구조 노출을 방지하십시오.",
		FixEN:                      "Disable GraphQL Introspection in production environments to prevent exposing the API's internal structure.",
		IsPotentiallyFalsePositive: false,
	},
	"SESSION_MANAGEMENT_MANUAL_REVIEW_NEEDED": {
		TitleKO:                    "세션 관리 점검 (수동 검증 필요)",
		TitleEN:                    "Session Management Review (Manual)",
		MessageKO:                  "세션 관리 취약점(로그인 후 세션 재발급 여부, 로그인 전후 쿠키 변경 등)은 자동화된 검증이 어렵습니다. 수동 검증이 필요합니다.",
		MessageEN:                  "Session management vulnerabilities (session regeneration after login, cookie changes, etc.) are difficult to verify automatically. Manual review is required.",
		FixKO:                      "로그인 시 세션 ID 재발급, 로그아웃 시 세션 무효화, 민감한 쿠키의 변경 여부 등을 수동으로 확인하고 적절한 세션 관리 정책을 구현하십시오.",
		FixEN:                      "Manually verify session ID regeneration on login, session invalidation on logout, and sensitive cookie changes, and implement appropriate session management policies.",
		IsPotentiallyFalsePositive: true, // Explicitly marked for manual review, so also potentially false positive for automation
	},
	"LOGIN_PAGE_HTTPS_MISSING": {
		TitleKO:                    "로그인 페이지 HTTPS 미사용",
		TitleEN:                    "HTTPS Missing on Login Page",
		MessageKO:                  "로그인 페이지 '%s'가 HTTPS를 사용하지 않아 인증 정보가 평문으로 전송될 위험이 있습니다.",
		MessageEN:                  "Login page '%s' does not use HTTPS, risking plaintext transmission of credentials.",
		FixKO:                      "로그인 페이지를 포함한 모든 인증 관련 페이지에 HTTPS를 강제 적용하십시오.",
		FixEN:                      "Enforce HTTPS on all authentication-related pages, including the login page.",
		IsPotentiallyFalsePositive: false,
	},
	"COOKIE_SECURE_FLAG_MISSING": {
		TitleKO:                    "쿠키 Secure 플래그 누락",
		TitleEN:                    "Cookie Secure Flag Missing",
		MessageKO:                  "HTTPS 페이지에서 '%s' 쿠키에 Secure 플래그가 설정되지 않아 HTTP 통신 시 노출될 위험이 있습니다.",
		MessageEN:                  "The Secure flag is missing for cookie '%s' on an HTTPS page, risking exposure during HTTP communication.",
		FixKO:                      "모든 민감한 쿠키에 Secure 플래그를 설정하십시오.",
		FixEN:                      "Set the Secure flag for all sensitive cookies.",
		IsPotentiallyFalsePositive: false,
	},
	"COOKIE_HTTPONLY_FLAG_MISSING": {
		TitleKO:                    "쿠키 HttpOnly 플래그 누락",
		TitleEN:                    "Cookie HttpOnly Flag Missing",
		MessageKO:                  "'%s' 쿠키에 HttpOnly 플래그가 설정되지 않아 클라이언트 측 스크립트에 의해 접근될 수 있습니다.",
		MessageEN:                  "The HttpOnly flag is missing for cookie '%s', allowing access by client-side scripts.",
		FixKO:                      "민감한 쿠키에 HttpOnly 플래그를 설정하여 XSS 공격으로부터 보호하십시오.",
		FixEN:                      "Set the HttpOnly flag for sensitive cookies to protect against XSS attacks.",
		IsPotentiallyFalsePositive: false,
	},
	"SAMESITE_NONE_SECURE_MISSING": {
		TitleKO:                    "SameSite=None 쿠키에 Secure 플래그 누락",
		TitleEN:                    "Secure Flag Missing for SameSite=None Cookie",
		MessageKO:                  "'%s' 쿠키(헤더 값)가 SameSite=None을 사용하지만 Secure 플래그가 없습니다.",
		MessageEN:                  "Cookie '%s' uses SameSite=None but is missing the Secure flag.",
		FixKO:                      "SameSite=None을 사용하는 모든 쿠키에 Secure 플래그를 함께 설정하십시오.",
		FixEN:                      "Set the Secure flag for all cookies using SameSite=None.",
		IsPotentiallyFalsePositive: false,
	},
	"SESSION_COOKIE_NO_EXPIRATION": {
		TitleKO:                    "세션 쿠키 만료 없음",
		TitleEN:                    "Session Cookie No Expiration",
		MessageKO:                  "세션 관련 쿠키 '%s'가 만료 시간을 설정하지 않아, 장기간 브라우저에 남아있을 수 있습니다.",
		MessageEN:                  "Session cookie '%s' has no expiration time set and may persist in the browser for a long time.",
		FixKO:                      "세션 관련 쿠키에 적절한 만료 시간(Expires 또는 Max-Age)을 설정하여 세션 하이재킹 위험을 줄이십시오.",
		FixEN:                      "Set an appropriate expiration time (Expires or Max-Age) for session cookies to reduce session hijacking risks.",
		IsPotentiallyFalsePositive: false,
	},
	"CONTENT_SECURITY_POLICY_MISSING": { // From missingHeader("Content-Security-Policy", ...)
		TitleKO:                    "Missing Content-Security-Policy",
		TitleEN:                    "Missing Content-Security-Policy",
		MessageKO:                  "XSS 공격 방어 불가",
		MessageEN:                  "Cannot defend against XSS attacks.",
		FixKO:                      "웹 서버 또는 애플리케이션 응답 헤더에 'Content-Security-Policy'를 추가하십시오. 예: \"default-src 'self';\". 이는 신뢰할 수 있는 소스에서만 스크립트, 스타일, 이미지 등을 로드하도록 제한하여 XSS 공격을 완화합니다.",
		FixEN:                      "Add 'Content-Security-Policy' to the response header. E.g., \"default-src 'self';\". This mitigates XSS by restricting resource loading to trusted sources.",
		IsPotentiallyFalsePositive: false,
	},
	"X_FRAME_OPTIONS_MISSING": { // From missingHeader("X-Frame-Options", ...)
		TitleKO:                    "Missing X-Frame-Options",
		TitleEN:                    "Missing X-Frame-Options",
		MessageKO:                  "Clickjacking 공격 가능",
		MessageEN:                  "Vulnerable to Clickjacking attacks.",
		FixKO:                      "응답 헤더에 'X-Frame-Options: DENY' (모든 프레임 차단) 또는 'X-Frame-Options: SAMEORIGIN' (동일 출처만 허용)을 추가하여 클릭재킹(Clickjacking) 공격을 방지하십시오.",
		FixEN:                      "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' to the response header to prevent Clickjacking.",
		IsPotentiallyFalsePositive: false,
	},
	"X_CONTENT_TYPE_OPTIONS_MISSING": { // From missingHeader("X-Content-Type-Options", ...)
		TitleKO:                    "Missing X-Content-Type-Options",
		TitleEN:                    "Missing X-Content-Type-Options",
		MessageKO:                  "MIME 타입 스니핑 방어 불가",
		MessageEN:                  "Cannot defend against MIME type sniffing.",
		FixKO:                      "응답 헤더에 'X-Content-Type-Options: nosniff'를 추가하십시오. 이는 브라우저가 선언된 Content-Type과 다른 MIME 타입으로 리소스를 해석(Sniffing)하는 것을 방지하여 XSS 등의 위험을 줄입니다.",
		FixEN:                      "Add 'X-Content-Type-Options: nosniff' to the response header. This prevents browsers from sniffing the MIME type, reducing risks like XSS.",
		IsPotentiallyFalsePositive: false,
	},
	"REFERRER_POLICY_MISSING": { // From missingHeader("Referrer-Policy", ...)
		TitleKO:                    "Missing Referrer-Policy",
		TitleEN:                    "Missing Referrer-Policy",
		MessageKO:                  "Referrer 정보 과다 노출 가능",
		MessageEN:                  "Referrer information may be over-exposed.",
		FixKO:                      "Referrer-Policy: strict-origin-when-cross-origin",
		FixEN:                      "Referrer-Policy: strict-origin-when-cross-origin",
		IsPotentiallyFalsePositive: false,
	},
	"PERMISSIONS_POLICY_MISSING": { // From missingHeader("Permissions-Policy", ...)
		TitleKO:                    "Missing Permissions-Policy",
		TitleEN:                    "Missing Permissions-Policy",
		MessageKO:                  "브라우저 기능 제어 미흡",
		MessageEN:                  "Insufficient control over browser features.",
		FixKO:                      "Permissions-Policy: geolocation=()",
		FixEN:                      "Permissions-Policy: geolocation=()",
		IsPotentiallyFalsePositive: false,
	},
	"CROSS_ORIGIN_OPENER_POLICY_MISSING": { // From missingHeader("Cross-Origin-Opener-Policy", ...)
		TitleKO:                    "Missing Cross-Origin-Opener-Policy",
		TitleEN:                    "Missing Cross-Origin-Opener-Policy",
		MessageKO:                  "탭 격리 보호 미흡",
		MessageEN:                  "Insufficient tab isolation protection.",
		FixKO:                      "Cross-Origin-Opener-Policy: same-origin",
		FixEN:                      "Cross-Origin-Opener-Policy: same-origin",
		IsPotentiallyFalsePositive: false,
	},
	"CROSS_ORIGIN_EMBEDDER_POLICY_MISSING": { // From missingHeader("Cross-Origin-Embedder-Policy", ...)
		TitleKO:                    "Missing Cross-Origin-Embedder-Policy",
		TitleEN:                    "Missing Cross-Origin-Embedder-Policy",
		MessageKO:                  "격리된 컨텍스트 보호 미흡",
		MessageEN:                  "Insufficient protection for isolated contexts.",
		FixKO:                      "Cross-Origin-Embedder-Policy: require-corp",
		FixEN:                      "Cross-Origin-Embedder-Policy: require-corp",
		IsPotentiallyFalsePositive: false,
	},
	"CROSS_ORIGIN_RESOURCE_POLICY_MISSING": { // From missingHeader("Cross-Origin-Resource-Policy", ...)
		TitleKO:                    "Missing Cross-Origin-Resource-Policy",
		TitleEN:                    "Missing Cross-Origin-Resource-Policy",
		MessageKO:                  "리소스 공유 정책 미설정",
		MessageEN:                  "Resource sharing policy not set.",
		FixKO:                      "Cross-Origin-Resource-Policy: same-site",
		FixEN:                      "Cross-Origin-Resource-Policy: same-site",
		IsPotentiallyFalsePositive: false,
	},
	"HSTS_MISSING": {
		TitleKO:                    "Missing Strict-Transport-Security",
		TitleEN:                    "Missing Strict-Transport-Security",
		MessageKO:                  "HTTPS 연결 강제 및 다운그레이드 방어 미흡",
		MessageEN:                  "Insufficient enforcement of HTTPS and downgrade protection.",
		FixKO:                      "응답 헤더에 'Strict-Transport-Security'를 추가하십시오. 권장 값: \"max-age=31536000; includeSubDomains; preload\". 이는 브라우저가 해당 도메인에 대해 일정 기간 동안 HTTPS로만 접속하도록 강제합니다.",
		FixEN:                      "Add 'Strict-Transport-Security' to the response header. Recommended: \"max-age=31536000; includeSubDomains; preload\". This forces browsers to use HTTPS for the domain.",
		IsPotentiallyFalsePositive: false,
	},
	"HSTS_MAXAGE_LOW": {
		TitleKO:                    "HSTS max-age too low",
		TitleEN:                    "HSTS max-age too low",
		MessageKO:                  "HSTS max-age 값이 낮아 보호 기간이 부족합니다",
		MessageEN:                  "HSTS max-age value is too low, providing insufficient protection duration.",
		FixKO:                      "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
		FixEN:                      "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
		IsPotentiallyFalsePositive: false,
	},
	"SERVER_HEADER_EXPOSED": {
		TitleKO:                    "Server header exposed",
		TitleEN:                    "Server header exposed",
		MessageKO:                  "서버 정보 노출",
		MessageEN:                  "Server information exposed.",
		FixKO:                      "웹 서버 설정에서 'Server' 헤더를 제거하거나 일반적인 값(예: 'Server: WebServer')으로 변경하여 구체적인 서버 소프트웨어 및 버전 정보가 노출되지 않도록 하십시오.",
		FixEN:                      "Remove the 'Server' header or change it to a generic value (e.g., 'Server: WebServer') to prevent exposing specific software and version information.",
		IsPotentiallyFalsePositive: false,
	},
	"X_POWERED_BY_EXPOSED": {
		TitleKO:                    "X-Powered-By header exposed",
		TitleEN:                    "X-Powered-By header exposed",
		MessageKO:                  "프레임워크 또는 런타임 정보 노출",
		MessageEN:                  "Framework or runtime information exposed.",
		FixKO:                      "애플리케이션 서버 또는 프레임워크 설정에서 'X-Powered-By' 헤더 생성을 비활성화하십시오. (예: PHP의 expose_php = Off, Express.js의 app.disable('x-powered-by'))",
		FixEN:                      "Disable 'X-Powered-By' header generation in the application server or framework settings.",
		IsPotentiallyFalsePositive: false,
	},
	"TRACE_METHOD_ENABLED": {
		TitleKO:                    "TRACE 메서드 활성화",
		TitleEN:                    "TRACE Method Enabled",
		MessageKO:                  "HTTP TRACE 메서드가 활성화되어 XST (Cross-Site Tracing) 공격에 취약할 수 있습니다.",
		MessageEN:                  "HTTP TRACE method is enabled, making it vulnerable to XST (Cross-Site Tracing) attacks.",
		FixKO:                      "웹 서버 설정에서 TRACE 메서드를 비활성화하십시오.",
		FixEN:                      "Disable the TRACE method in the web server settings.",
		IsPotentiallyFalsePositive: false,
	},
	"OPTIONS_OVER_EXPOSED": {
		TitleKO:                    "OPTIONS 메서드 과다 노출",
		TitleEN:                    "OPTIONS Method Over-Exposed",
		MessageKO:                  "OPTIONS 메서드를 통해 허용되는 HTTP 메서드('%s')가 과도하게 노출되어 정보 유출 위험이 있습니다.",
		MessageEN:                  "Allowed HTTP methods ('%s') are over-exposed via OPTIONS, risking information leakage.",
		FixKO:                      "웹 서버 설정에서 불필요한 HTTP 메서드(PUT, DELETE, TRACE 등)를 비활성화하고, OPTIONS 요청에 대해 필요한 메서드만 응답하도록 구성하십시오.",
		FixEN:                      "Disable unnecessary HTTP methods (PUT, DELETE, TRACE, etc.) and configure OPTIONS to respond only with required methods.",
		IsPotentiallyFalsePositive: false,
	},
	"PUT_METHOD_ALLOWED": {
		TitleKO:                    "PUT 메서드 허용",
		TitleEN:                    "PUT Method Allowed",
		MessageKO:                  "웹 서버가 임의의 경로에 PUT 메서드를 허용하여 파일 생성/수정에 취약할 수 있습니다. 테스트 경로: %s",
		MessageEN:                  "The web server allows PUT method on arbitrary paths, vulnerable to file creation/modification. Test path: %s",
		FixKO:                      "REST API 등에서 꼭 필요한 경우가 아니라면 웹 서버 설정에서 PUT 메서드를 비활성화하십시오. 사용해야 한다면 해당 엔드포인트에 대해 강력한 인증 및 권한 검사를 적용해야 합니다.",
		FixEN:                      "Disable PUT method unless necessary. If used, apply strong authentication and authorization.",
		IsPotentiallyFalsePositive: false,
	},
	"DELETE_METHOD_ALLOWED": {
		TitleKO:                    "DELETE 메서드 허용",
		TitleEN:                    "DELETE Method Allowed",
		MessageKO:                  "웹 서버가 임의의 경로에 DELETE 메서드를 허용하여 파일 삭제에 취약할 수 있습니다. 테스트 경로: %s",
		MessageEN:                  "The web server allows DELETE method on arbitrary paths, vulnerable to file deletion. Test path: %s",
		FixKO:                      "REST API 등에서 꼭 필요한 경우가 아니라면 웹 서버 설정에서 DELETE 메서드를 비활성화하십시오. 사용해야 한다면 해당 엔드포인트에 대해 강력한 인증 및 권한 검사를 적용해야 합니다.",
		FixEN:                      "Disable DELETE method unless necessary. If used, apply strong authentication and authorization.",
		IsPotentiallyFalsePositive: false,
	},
	"ROBOTS_TXT_EXPOSED": {
		TitleKO:                    "robots.txt 파일 노출",
		TitleEN:                    "robots.txt Exposed",
		MessageKO:                  "민감할 수 있는 파일/디렉토리 '%s'가 외부에 노출되어 있습니다.",
		MessageEN:                  "Potentially sensitive file/directory '%s' is exposed.",
		FixKO:                      "해당 파일/디렉토리에 대한 외부 접근을 차단하거나 제거하십시오.",
		FixEN:                      "Block external access to the file/directory or remove it.",
		IsPotentiallyFalsePositive: false,
	},
	"SITEMAP_XML_EXPOSED": {
		TitleKO:                    "sitemap.xml 파일 노출",
		TitleEN:                    "sitemap.xml Exposed",
		MessageKO:                  "민감할 수 있는 파일/디렉토리 '%s'가 외부에 노출되어 있습니다.",
		MessageEN:                  "Potentially sensitive file/directory '%s' is exposed.",
		FixKO:                      "해당 파일/디렉토리에 대한 외부 접근을 차단하거나 제거하십시오.",
		FixEN:                      "Block external access to the file/directory or remove it.",
		IsPotentiallyFalsePositive: false,
	},
	"SECURITY_TXT_EXPOSED": {
		TitleKO:                    "security.txt 파일 노출",
		TitleEN:                    "security.txt Exposed",
		MessageKO:                  "민감할 수 있는 파일/디렉토리 '%s'가 외부에 노출되어 있습니다.",
		MessageEN:                  "Potentially sensitive file/directory '%s' is exposed.",
		FixKO:                      "해당 파일/디렉토리에 대한 외부 접근을 차단하거나 제거하십시오.",
		FixEN:                      "Block external access to the file/directory or remove it.",
		IsPotentiallyFalsePositive: false,
	},
	"WELL_KNOWN_EXPOSED": {
		TitleKO:                    ".well-known 디렉토리 노출",
		TitleEN:                    ".well-known Directory Exposed",
		MessageKO:                  "민감할 수 있는 파일/디렉토리 '%s'가 외부에 노출되어 있습니다.",
		MessageEN:                  "Potentially sensitive file/directory '%s' is exposed.",
		FixKO:                      "해당 파일/디렉토리에 대한 외부 접근을 차단하거나 제거하십시오.",
		FixEN:                      "Block external access to the file/directory or remove it.",
		IsPotentiallyFalsePositive: false,
	},
	"GIT_HEAD_EXPOSED": {
		TitleKO:                    ".git 디렉토리 노출 (HEAD 파일)",
		TitleEN:                    ".git Directory Exposed (HEAD file)",
		MessageKO:                  "민감할 수 있는 파일/디렉토리 '%s'가 외부에 노출되어 있습니다.",
		MessageEN:                  "Potentially sensitive file/directory '%s' is exposed.",
		FixKO:                      "해당 파일/디렉토리에 대한 외부 접근을 차단하거나 제거하십시오.",
		FixEN:                      "Block external access to the file/directory or remove it.",
		IsPotentiallyFalsePositive: false,
	},
	"GIT_CONFIG_EXPOSED": {
		TitleKO:                    ".git 디렉토리 노출 (config 파일)",
		TitleEN:                    ".git Directory Exposed (config file)",
		MessageKO:                  "민감할 수 있는 파일/디렉토리 '%s'가 외부에 노출되어 있습니다.",
		MessageEN:                  "Potentially sensitive file/directory '%s' is exposed.",
		FixKO:                      "해당 파일/디렉토리에 대한 외부 접근을 차단하거나 제거하십시오.",
		FixEN:                      "Block external access to the file/directory or remove it.",
		IsPotentiallyFalsePositive: false,
	},
	"ENV_EXPOSED": {
		TitleKO:                    ".env 파일 노출",
		TitleEN:                    ".env File Exposed",
		MessageKO:                  "민감할 수 있는 파일/디렉토리 '%s'가 외부에 노출되어 있습니다.",
		MessageEN:                  "Potentially sensitive file/directory '%s' is exposed.",
		FixKO:                      "해당 파일/디렉토리에 대한 외부 접근을 차단하거나 제거하십시오.",
		FixEN:                      "Block external access to the file/directory or remove it.",
		IsPotentiallyFalsePositive: false,
	},
	"TRAVIS_YML_EXPOSED": {
		TitleKO:                    ".travis.yml (CI/CD) 파일 노출",
		TitleEN:                    ".travis.yml (CI/CD) File Exposed",
		MessageKO:                  "민감할 수 있는 파일/디렉토리 '%s'가 외부에 노출되어 있습니다.",
		MessageEN:                  "Potentially sensitive file/directory '%s' is exposed.",
		FixKO:                      "해당 파일/디렉토리에 대한 외부 접근을 차단하거나 제거하십시오.",
		FixEN:                      "Block external access to the file/directory or remove it.",
		IsPotentiallyFalsePositive: false,
	},
	"GITLAB_CI_YML_EXPOSED": {
		TitleKO:                    ".gitlab-ci.yml (CI/CD) 파일 노출",
		TitleEN:                    ".gitlab-ci.yml (CI/CD) File Exposed",
		MessageKO:                  "민감할 수 있는 파일/디렉토리 '%s'가 외부에 노출되어 있습니다.",
		MessageEN:                  "Potentially sensitive file/directory '%s' is exposed.",
		FixKO:                      "해당 파일/디렉토리에 대한 외부 접근을 차단하거나 제거하십시오.",
		FixEN:                      "Block external access to the file/directory or remove it.",
		IsPotentiallyFalsePositive: false,
	},
	"JENKINSFILE_EXPOSED": {
		TitleKO:                    "Jenkinsfile (CI/CD) 파일 노출",
		TitleEN:                    "Jenkinsfile (CI/CD) File Exposed",
		MessageKO:                  "민감할 수 있는 파일/디렉토리 '%s'가 외부에 노출되어 있습니다.",
		MessageEN:                  "Potentially sensitive file/directory '%s' is exposed.",
		FixKO:                      "해당 파일/디렉토리에 대한 외부 접근을 차단하거나 제거하십시오.",
		FixEN:                      "Block external access to the file/directory or remove it.",
		IsPotentiallyFalsePositive: false,
	},
	"ACTUATOR_ENDPOINT_EXPOSED": {
		TitleKO:                    "/actuator 디버그 엔드포인트 노출",
		TitleEN:                    "/actuator Debug Endpoint Exposed",
		MessageKO:                  "민감할 수 있는 파일/디렉토리 '%s'가 외부에 노출되어 있습니다.",
		MessageEN:                  "Potentially sensitive file/directory '%s' is exposed.",
		FixKO:                      "해당 파일/디렉토리에 대한 외부 접근을 차단하거나 제거하십시오.",
		FixEN:                      "Block external access to the file/directory or remove it.",
		IsPotentiallyFalsePositive: false,
	},
	"DEBUG_ENDPOINT_EXPOSED": {
		TitleKO:                    "/debug 디버그 엔드포인트 노출",
		TitleEN:                    "/debug Debug Endpoint Exposed",
		MessageKO:                  "민감할 수 있는 파일/디렉토리 '%s'가 외부에 노출되어 있습니다.",
		MessageEN:                  "Potentially sensitive file/directory '%s' is exposed.",
		FixKO:                      "해당 파일/디렉토리에 대한 외부 접근을 차단하거나 제거하십시오.",
		FixEN:                      "Block external access to the file/directory or remove it.",
		IsPotentiallyFalsePositive: false,
	},
	"MIXED_CONTENT_DETECTED": {
		TitleKO:                    "Mixed Content 감지",
		TitleEN:                    "Mixed Content Detected",
		MessageKO:                  "HTTPS 페이지에서 안전하지 않은 HTTP 리소스 '%s'를 로드합니다.",
		MessageEN:                  "Insecure HTTP resource '%s' is loaded on an HTTPS page.",
		FixKO:                      "모든 리소스를 HTTPS로 로드하도록 변경하거나 상대 경로를 사용하십시오.",
		FixEN:                      "Change all resources to load via HTTPS or use relative paths.",
		IsPotentiallyFalsePositive: false,
	},
	"IFRAME_SANDBOX_MISSING": {
		TitleKO:                    "Iframe Sandbox 속성 미사용",
		TitleEN:                    "Iframe Sandbox Attribute Missing",
		MessageKO:                  "<iframe> 태그에 sandbox 속성이 없어 잠재적인 클릭재킹 또는 스크립트 실행 위험이 있습니다. (src: %s)",
		MessageEN:                  "<iframe> tag is missing the sandbox attribute, posing risks like clickjacking or script execution. (src: %s)",
		FixKO:                      "모든 <iframe> 태그에 sandbox 속성을 추가하여 포함된 콘텐츠의 권한을 제한하십시오.",
		FixEN:                      "Add the sandbox attribute to all <iframe> tags to restrict permissions of embedded content.",
		IsPotentiallyFalsePositive: false,
	},
	"INLINE_SCRIPT_DETECTED": {
		TitleKO:                    "인라인 스크립트 사용 감지",
		TitleEN:                    "Inline Script Detected",
		MessageKO:                  "Content-Security-Policy(CSP)가 없거나 약하여 인라인 스크립트가 허용됩니다. 이는 XSS 공격 위험을 증가시킬 수 있습니다.",
		MessageEN:                  "Inline scripts are allowed due to missing or weak Content-Security-Policy (CSP), increasing XSS risk.",
		FixKO:                      "가능한 모든 JavaScript 코드를 외부 .js 파일로 분리하십시오. 인라인 스크립트가 꼭 필요한 경우, CSP 헤더에 'nonce' 또는 'sha256' 해시를 사용하여 승인된 스크립트만 실행되도록 허용하고 'unsafe-inline' 사용을 지양하십시오.",
		FixEN:                      "Move JavaScript to external .js files. If inline scripts are necessary, use 'nonce' or 'sha256' hash in CSP to allow only approved scripts and avoid 'unsafe-inline'.",
		IsPotentiallyFalsePositive: true,
	},
	"JSON_API_TEXT_PLAIN_ALLOWED": {
		TitleKO:                    "JSON API에 text/plain Content-Type 허용",
		TitleEN:                    "JSON API Allows text/plain Content-Type",
		MessageKO:                  "JSON API 엔드포인트가 'Content-Type: text/plain' 요청을 JSON으로 처리하여 Content-Type 혼동 취약점에 노출될 수 있습니다.",
		MessageEN:                  "JSON API endpoint processes 'Content-Type: text/plain' as JSON, exposing it to Content-Type confusion vulnerabilities.",
		FixKO:                      "API 요청 처리 시 'Content-Type: application/json'만 허용하고, 다른 Content-Type은 거부하십시오.",
		FixEN:                      "Allow only 'Content-Type: application/json' for API requests and reject others.",
		IsPotentiallyFalsePositive: true,
	},
	"ACCEPT_HEADER_IGNORED": {
		TitleKO:                    "Accept 헤더 무시",
		TitleEN:                    "Accept Header Ignored",
		MessageKO:                  "클라이언트의 'Accept: text/html' 요청을 무시하고 JSON Content-Type을 반환했습니다. Content-Type Negotiation 취약점이 있을 수 있습니다.",
		MessageEN:                  "Ignored client's 'Accept: text/html' request and returned JSON Content-Type. Potential Content-Type Negotiation vulnerability.",
		FixKO:                      "클라이언트의 Accept 헤더를 존중하고, 요청된 Content-Type으로 응답하거나 적절한 오류를 반환하도록 구성하십시오.",
		FixEN:                      "Respect the client's Accept header and respond with the requested Content-Type or return an appropriate error.",
		IsPotentiallyFalsePositive: true,
	},
	"METHOD_OVERRIDE_ALLOWED": {
		TitleKO:                    "HTTP Method Override 허용",
		TitleEN:                    "HTTP Method Override Allowed",
		MessageKO:                  "X-HTTP-Method-Override 헤더를 사용하여 POST 요청을 '%s' 메서드로 오버라이드할 수 있습니다. 이는 예상치 못한 동작을 유발할 수 있습니다.",
		MessageEN:                  "X-HTTP-Method-Override header allows overriding POST requests to '%s' method. This may cause unexpected behavior.",
		FixKO:                      "불필요한 HTTP Method Override 기능을 비활성화하거나, 허용된 메서드만 엄격하게 처리하도록 구성하십시오.",
		FixEN:                      "Disable unnecessary HTTP Method Override features or strictly handle only allowed methods.",
		IsPotentiallyFalsePositive: true,
	},
	"RETRY_AFTER_HEADER_MISSING": {
		TitleKO:                    "Retry-After 헤더 부재",
		TitleEN:                    "Retry-After Header Missing",
		MessageKO:                  "응답에 'Retry-After' 헤더가 없어 클라이언트가 Rate Limit 초과 시 재시도 간격을 알 수 없습니다.",
		MessageEN:                  "Response is missing 'Retry-After' header, so clients cannot know the retry interval when Rate Limit is exceeded.",
		FixKO:                      "Rate Limit 적용 시 클라이언트에게 적절한 재시도 간격을 제공하기 위해 'Retry-After' 헤더를 포함하십시오.",
		FixEN:                      "Include 'Retry-After' header to provide appropriate retry intervals to clients when Rate Limit is applied.",
		IsPotentiallyFalsePositive: false,
	},
	"X_RATELIMIT_HEADERS_MISSING": {
		TitleKO:                    "X-RateLimit-* 헤더 부재",
		TitleEN:                    "X-RateLimit-* Headers Missing",
		MessageKO:                  "응답에 'X-RateLimit-*' 관련 헤더가 없어 클라이언트가 Rate Limit 정보를 알 수 없습니다.",
		MessageEN:                  "Response is missing 'X-RateLimit-*' headers, so clients cannot know Rate Limit information.",
		FixKO:                      "Rate Limit 정보를 클라이언트에게 명확히 전달하기 위해 'X-RateLimit-*' 헤더를 포함하십시오.",
		FixEN:                      "Include 'X-RateLimit-*' headers to clearly communicate Rate Limit information to clients.",
		IsPotentiallyFalsePositive: false,
	},
	"INFORMATION_LEAKAGE_STACK_TRACE": {
		TitleKO:                    "스택 트레이스 노출",
		TitleEN:                    "Stack Trace Exposed",
		MessageKO:                  "응답 본문에서 애플리케이션의 스택 트레이스가 발견되었습니다. 내부 시스템 정보가 노출될 위험이 있습니다.",
		MessageEN:                  "Application stack trace found in response body. Risk of exposing internal system information.",
		FixKO:                      "애플리케이션의 에러 처리 설정을 검토하여 운영(Production) 환경에서는 스택 트레이스가 클라이언트로 전송되지 않도록 하십시오. 대신 사용자 친화적인 일반 오류 페이지를 표시하고, 상세 로그는 서버 측에만 기록해야 합니다.",
		FixEN:                      "Review error handling settings to prevent sending stack traces to clients in production. Display user-friendly error pages and log details on the server side only.",
		IsPotentiallyFalsePositive: false,
	},
	"INFORMATION_LEAKAGE_DB_ERROR": {
		TitleKO:                    "데이터베이스 에러 문자열 노출",
		TitleEN:                    "Database Error String Exposed",
		MessageKO:                  "응답 본문에서 데이터베이스 에러 관련 문자열이 발견되었습니다. 데이터베이스 구조나 쿼리 방식 등 내부 시스템 정보가 노출될 위험이 있습니다.",
		MessageEN:                  "Database error strings found in response body. Risk of exposing internal system information like DB structure or queries.",
		FixKO:                      "SQL 예외나 데이터베이스 오류 메시지가 그대로 노출되지 않도록 예외 처리 로직을 강화하십시오. 사용자에게는 일반적인 오류 메시지만 반환해야 합니다.",
		FixEN:                      "Strengthen exception handling to prevent exposing SQL exceptions or DB error messages. Return only generic error messages to users.",
		IsPotentiallyFalsePositive: false,
	},
	"INFORMATION_LEAKAGE_X_POWERED_BY": {
		TitleKO:                    "X-Powered-By 헤더 노출",
		TitleEN:                    "X-Powered-By Header Exposed",
		MessageKO:                  "X-Powered-By 헤더를 통해 사용 중인 기술 스택('%s')이 노출되고 있습니다.",
		MessageEN:                  "Tech stack ('%s') is exposed via X-Powered-By header.",
		FixKO:                      "X-Powered-By 헤더를 제거하여 사용 중인 기술 스택 정보 노출을 최소화하십시오.",
		FixEN:                      "Remove X-Powered-By header to minimize tech stack information exposure.",
		IsPotentiallyFalsePositive: false,
	},
	"INFORMATION_LEAKAGE_SERVER_HEADER": {
		TitleKO:                    "Server 헤더 노출",
		TitleEN:                    "Server Header Exposed",
		MessageKO:                  "Server 헤더를 통해 웹 서버 정보('%s')가 노출되고 있습니다.",
		MessageEN:                  "Web server information ('%s') is exposed via Server header.",
		FixKO:                      "Server 헤더를 제거하거나 일반적인 값으로 변경하여 웹 서버 정보 노출을 최소화하십시오.",
		FixEN:                      "Remove Server header or change to a generic value to minimize web server information exposure.",
		IsPotentiallyFalsePositive: false,
	},
	"INFORMATION_LEAKAGE_FRAMEWORK_SIGNATURE": {
		TitleKO:                    "프레임워크/서버 시그니처 노출",
		TitleEN:                    "Framework/Server Signature Exposed",
		MessageKO:                  "응답 본문에서 사용 중인 웹 프레임워크나 서버의 버전 정보 등 시그니처가 발견되었습니다. 공격자가 특정 버전에 대한 취약점을 찾아 공격할 수 있습니다.",
		MessageEN:                  "Framework or server signature (version info) found in response body. Attackers may exploit specific version vulnerabilities.",
		FixKO:                      "불필요한 프레임워크/서버 시그니처 정보를 응답에서 제거하십시오.",
		FixEN:                      "Remove unnecessary framework/server signature information from the response.",
		IsPotentiallyFalsePositive: false,
	},
	"INFORMATION_LEAKAGE_DEBUG_META_ENDPOINT": {
		TitleKO:                    "디버그/메타 엔드포인트 노출",
		TitleEN:                    "Debug/Meta Endpoint Exposed",
		MessageKO:                  "민감한 정보가 포함될 수 있는 '%s' 엔드포인트가 노출되어 있습니다.",
		MessageEN:                  "Endpoint '%s' containing potentially sensitive information is exposed.",
		FixKO:                      "운영 환경에서 디버그 및 메타 엔드포인트에 대한 접근을 제한하거나 비활성화하십시오.",
		FixEN:                      "Restrict or disable access to debug and meta endpoints in production environments.",
		IsPotentiallyFalsePositive: false,
	},
	"JSON_UNEXPECTED_FIELD_INSERTION": {
		TitleKO:                    "JSON 예상 외 필드 삽입 점검",
		TitleEN:                    "JSON Unexpected Field Insertion Check",
		MessageKO:                  "JSON 요청에 예상되지 않은 필드를 삽입했을 때의 애플리케이션 처리 로직 검증이 필요합니다.",
		MessageEN:                  "Verification of application logic when unexpected fields are inserted into JSON requests is needed.",
		FixKO:                      "JSON 요청 처리 시 허용된 필드만 파싱하고, 예상되지 않은 필드는 무시하거나 오류를 반환하도록 구성하십시오.",
		FixEN:                      "Parse only allowed fields in JSON requests and ignore or return error for unexpected fields.",
		IsPotentiallyFalsePositive: true,
	},
	"JSONP_ENABLED": {
		TitleKO:   "JSONP 엔드포인트 활성화",
		TitleEN:   "JSONP Endpoint Enabled",
		MessageKO: "URL 파라미터('%s')를 통해 JSONP 응답이 활성화되어 있습니다. 이는 동일-출처 정책(SOP)을 우회하여 다른 도메인에서 데이터를 탈취하는 데 사용될 수 있습니다.",
		MessageEN: "JSONP response is enabled via the '%s' URL parameter. This can be used to bypass the Same-Origin Policy and steal data from other domains.",
		FixKO:     "JSONP 사용을 중단하고 CORS(Cross-Origin Resource Sharing)를 사용하여 API를 제공하십시오. JSONP가 반드시 필요한 경우, 콜백 함수 이름에 대한 엄격한 화이트리스트 검증을 구현하여 임의의 코드 실행을 방지해야 합니다.",
		FixEN:     "Discontinue using JSONP and use CORS (Cross-Origin Resource Sharing) to provide the API. If JSONP is essential, implement strict whitelist validation for callback function names to prevent arbitrary code execution.",
	},
	"XXE_DETECTED": {
		TitleKO:                    "XXE (XML External Entity) 취약점 감지",
		TitleEN:                    "XXE (XML External Entity) Vulnerability Detected",
		MessageKO:                  "XML 파서가 외부 엔티티를 처리하도록 설정되어 있습니다. 이는 로컬 파일 유출이나 SSRF 공격으로 이어질 수 있습니다. (반사된 값: %s)",
		MessageEN:                  "XML parser is configured to process external entities. This can lead to local file disclosure or SSRF attacks. (Reflected: %s)",
		FixKO:                      "XML 파서 설정에서 DTD(Document Type Definition) 및 외부 엔티티 처리를 비활성화하십시오.",
		FixEN:                      "Disable DTD (Document Type Definition) and external entity processing in the XML parser configuration.",
		IsPotentiallyFalsePositive: false,
	},
	"PARAMETER_POLLUTION_DETECTED": {
		TitleKO:                    "파라미터 오염 (Parameter Pollution) 감지",
		TitleEN:                    "Parameter Pollution Detected",
		MessageKO:                  "파라미터 '%s'에 중복 값을 전송했을 때 응답 내용이 크게 변경되었습니다. 이는 파라미터 오염 취약점의 가능성을 나타냅니다.",
		MessageEN:                  "Response changed significantly when sending duplicate values for parameter '%s'. This indicates potential Parameter Pollution vulnerability.",
		FixKO:                      "애플리케이션이 중복된 파라미터를 안전하게 처리하도록 구성하십시오 (예: 첫 번째 값만 사용, 모든 값 배열로 처리 등).",
		FixEN:                      "Configure the application to handle duplicate parameters safely (e.g., use only the first value, treat as array, etc.).",
		IsPotentiallyFalsePositive: true,
	},
	"PACKET_CONTENT_TYPE_MISMATCH": {
		TitleKO:                    "Content-Type 헤더와 본문 불일치",
		TitleEN:                    "Content-Type Header Mismatch",
		MessageKO:                  "응답 헤더의 Content-Type('%s')과 실제 본문 데이터의 형식('%s')이 일치하지 않습니다. 이는 MIME Sniffing 공격이나 파싱 오류를 유발할 수 있습니다.",
		MessageEN:                  "Content-Type header ('%s') does not match actual body format ('%s'). This may cause MIME Sniffing attacks or parsing errors.",
		FixKO:                      "서버에서 올바른 Content-Type 헤더를 설정하고, 'X-Content-Type-Options: nosniff' 헤더를 적용하십시오.",
		FixEN:                      "Set correct Content-Type header and apply 'X-Content-Type-Options: nosniff' header.",
		IsPotentiallyFalsePositive: false,
	},
	"PACKET_WWW_AUTHENTICATE_ON_200": {
		TitleKO:                    "200 OK 응답에 인증 요구 헤더 존재",
		TitleEN:                    "WWW-Authenticate Header on 200 OK",
		MessageKO:                  "요청이 성공(200 OK)했음에도 불구하고 'WWW-Authenticate' 헤더가 존재합니다. 이는 인증 로직의 구성 오류일 수 있습니다.",
		MessageEN:                  "'WWW-Authenticate' header exists despite 200 OK response. This may be a misconfiguration in authentication logic.",
		FixKO:                      "인증이 필요한 경우 401 Unauthorized 상태 코드를 사용하고, 그렇지 않은 경우 불필요한 인증 헤더를 제거하십시오.",
		FixEN:                      "Use 401 Unauthorized if authentication is required, otherwise remove unnecessary authentication headers.",
		IsPotentiallyFalsePositive: false,
	},
	"PACKET_CORS_BAD_COMBINATION": {
		TitleKO:                    "불안전한 CORS 헤더 조합",
		TitleEN:                    "Insecure CORS Header Combination",
		MessageKO:                  "Access-Control-Allow-Origin이 와일드카드('*')이면서 Access-Control-Allow-Credentials가 'true'로 설정되어 있습니다. (또는 허용되지 않는 다중 Origin)",
		MessageEN:                  "Access-Control-Allow-Origin is wildcard ('*') while Access-Control-Allow-Credentials is 'true'. (or disallowed multiple Origins)",
		FixKO:                      "Credentials를 허용할 경우 명시적인 Origin을 지정하고 와일드카드를 사용하지 마십시오.",
		FixEN:                      "Specify explicit Origin and avoid wildcard if Credentials are allowed.",
		IsPotentiallyFalsePositive: false,
	},
	"PACKET_ACCEPT_IGNORED": {
		TitleKO:                    "Accept 헤더 무시됨",
		TitleEN:                    "Accept Header Ignored",
		MessageKO:                  "클라이언트가 요청한 Accept 타입('%s')과 다른 Content-Type('%s')으로 응답했습니다. 콘텐츠 협상(Content Negotiation)이 제대로 동작하지 않을 수 있습니다.",
		MessageEN:                  "Responded with Content-Type ('%s') different from requested Accept type ('%s'). Content Negotiation may not be working properly.",
		FixKO:                      "서버가 클라이언트의 Accept 헤더를 존중하여 적절한 포맷으로 응답하거나, 지원하지 않는 경우 406 Not Acceptable을 반환하도록 구성하십시오.",
		FixEN:                      "Configure server to respect client's Accept header or return 406 Not Acceptable if unsupported.",
		IsPotentiallyFalsePositive: true,
	},
	"BLIND_SQLI_TIME_BASED": {
		TitleKO:                    "블라인드 SQL 인젝션 (시간 기반) 가능성",
		TitleEN:                    "Blind SQL Injection (Time-based) Possible",
		MessageKO:                  "파라미터 '%s'에 시간 지연 페이로드를 주입했을 때, 서버 응답이 약 %d초 지연되었습니다. 이는 시간 기반 블라인드 SQL 인젝션에 취약할 수 있음을 나타냅니다.",
		MessageEN:                  "Server response delayed by approx %d seconds when injecting time delay payload into parameter '%s'. Indicates potential Time-based Blind SQL Injection.",
		FixKO:                      "모든 데이터베이스 쿼리에 Prepared Statement(파라미터화된 쿼리)를 사용하고, 사용자 입력값을 검증하십시오. 특히 숫자 입력값도 문자열로 처리하여 쿼리에 직접 연결하지 마십시오.",
		FixEN:                      "Use Prepared Statements (parameterized queries) for all DB queries and validate user input. Do not concatenate input directly into queries.",
		IsPotentiallyFalsePositive: true,
	},
	"OS_COMMAND_INJECTION_TIME_BASED": {
		TitleKO:                    "OS 커맨드 인젝션 (시간 기반) 가능성",
		TitleEN:                    "OS Command Injection (Time-based) Possible",
		MessageKO:                  "파라미터 '%s'에 시간 지연 페이로드를 주입했을 때, 서버 응답이 약 %d초 지연되었습니다. 이는 OS 커맨드 인젝션에 취약할 수 있음을 나타냅니다.",
		MessageEN:                  "Server response delayed by approx %d seconds when injecting time delay payload into parameter '%s'. Indicates potential OS Command Injection.",
		FixKO:                      "외부 입력을 사용하여 시스템 명령어를 실행하지 마십시오. 반드시 필요한 경우, 허용된 명령어와 인자 목록(Whitelist)을 엄격하게 적용하고, 쉘 메타문자(;, |, &, ` 등)를 필터링하십시오.",
		FixEN:                      "Do not execute system commands using external input. If necessary, strictly whitelist allowed commands/arguments and filter shell metacharacters.",
		IsPotentiallyFalsePositive: true,
	},
	"SSRF_CALLBACK_DETECTED": {
		TitleKO:                    "SSRF (Server-Side Request Forgery) 취약점 가능성",
		TitleEN:                    "SSRF (Server-Side Request Forgery) Possible",
		MessageKO:                  "파라미터 '%s'에 외부 URL을 주입했을 때, 서버가 해당 URL의 콘텐츠를 가져오거나 응답이 변경되었습니다. 이는 서버가 사용자 입력 URL을 검증 없이 요청하고 있음을 나타냅니다.",
		MessageEN:                  "Server fetched content or response changed when injecting external URL into parameter '%s'. Indicates server requests user input URL without validation.",
		FixKO:                      "사용자가 입력한 URL에 대해 서버 측에서 요청을 보낼 때, 허용된 도메인/IP 목록(Whitelist)을 적용하고 내부 네트워크(Localhost, Private IP)로의 접근을 차단하십시오.",
		FixEN:                      "Apply whitelist of allowed domains/IPs and block access to internal networks (Localhost, Private IP) when server makes requests based on user input.",
		IsPotentiallyFalsePositive: true,
	},
	"SSRF_LOCAL_ACCESS_DETECTED": {
		TitleKO:                    "SSRF 내부망(Localhost) 접근 감지",
		TitleEN:                    "SSRF Localhost Access Detected",
		MessageKO:                  "파라미터 '%s'를 통해 로컬 호스트(127.0.0.1:%d)의 서비스에 접근할 수 있습니다. 응답에서 '%s' 서비스의 특징이 발견되었습니다.",
		MessageEN:                  "Access to localhost (127.0.0.1:%d) service possible via parameter '%s'. Service characteristic '%s' found in response.",
		FixKO:                      "서버에서 외부로 나가는 요청에 대해 내부 네트워크(127.0.0.0/8, 10.0.0.0/8 등)로의 접근을 차단(Deny List)하거나, 허용된 도메인만 접근 가능하도록(Allow List) 설정하십시오.",
		FixEN:                      "Block access to internal networks (127.0.0.0/8, 10.0.0.0/8, etc.) or allow only specific domains for outbound server requests.",
		IsPotentiallyFalsePositive: true,
	},
	"INSECURE_DESERIALIZATION_SUSPECTED": {
		TitleKO:                    "안전하지 않은 역직렬화 의심 (Serialized Data 감지)",
		TitleEN:                    "Insecure Deserialization Suspected",
		MessageKO:                  "파라미터 또는 쿠키 '%s'에서 직렬화된 데이터(Java, PHP, Python 등) 패턴이 감지되었습니다. 신뢰할 수 없는 데이터의 역직렬화는 RCE(원격 코드 실행)로 이어질 수 있습니다.",
		MessageEN:                  "Serialized data pattern (Java, PHP, Python, etc.) detected in parameter or cookie '%s'. Deserializing untrusted data can lead to RCE.",
		FixKO:                      "신뢰할 수 없는 소스에서 온 데이터를 역직렬화하지 마십시오. 가능하다면 JSON과 같은 안전한 데이터 포맷을 사용하고, 역직렬화 시 타입 제약이나 서명을 통해 무결성을 검증하십시오.",
		FixEN:                      "Do not deserialize data from untrusted sources. Use safe formats like JSON if possible, and verify integrity via type constraints or signatures during deserialization.",
		IsPotentiallyFalsePositive: true,
	},
	"COMPONENT_OUTDATED_DETECTED": {
		TitleKO:                    "오래되거나 취약한 컴포넌트 버전 감지",
		TitleEN:                    "Outdated/Vulnerable Component Detected",
		MessageKO:                  "서버 헤더 또는 HTML 주석에서 오래된 버전의 소프트웨어 정보('%s')가 발견되었습니다. 이는 알려진 취약점(CVE)에 노출될 위험이 있습니다.",
		MessageEN:                  "Outdated software version info ('%s') found in server header or HTML comments. Risk of exposure to known vulnerabilities (CVE).",
		FixKO:                      "사용 중인 소프트웨어 및 라이브러리를 최신 보안 패치가 적용된 버전으로 업데이트하고, 불필요한 버전 정보 노출을 설정에서 비활성화하십시오.",
		FixEN:                      "Update software and libraries to latest patched versions and disable unnecessary version info exposure in settings.",
		IsPotentiallyFalsePositive: false,
	},
	"SSTI_DETECTED": {
		TitleKO:                    "SSTI (Server-Side Template Injection) 감지",
		TitleEN:                    "SSTI (Server-Side Template Injection) Detected",
		MessageKO:                  "파라미터 '%s'에 템플릿 구문을 주입했을 때 서버에서 연산된 결과('49')가 반환되었습니다. 이는 원격 코드 실행(RCE)으로 이어질 수 있는 치명적인 취약점입니다.",
		MessageEN:                  "Server returned evaluated result ('49') when injecting template syntax into parameter '%s'. This is a critical vulnerability leading to RCE.",
		FixKO:                      "사용자 입력을 템플릿 엔진에 직접 연결하지 말고, 템플릿 엔진이 제공하는 파라미터 바인딩 기능을 사용하거나 입력을 엄격하게 검증하십시오.",
		FixEN:                      "Do not concatenate user input directly into templates. Use parameter binding provided by the template engine or strictly validate input.",
		IsPotentiallyFalsePositive: false,
	},
	"OPEN_REDIRECT_DETECTED": {
		TitleKO:                    "Open Redirect 취약점 감지",
		TitleEN:                    "Open Redirect Detected",
		MessageKO:                  "파라미터 '%s'를 통해 임의의 외부 도메인('%s')으로 리다이렉트가 가능합니다. 이는 피싱 공격에 악용될 수 있습니다.",
		MessageEN:                  "Redirect to arbitrary external domain ('%s') is possible via parameter '%s'. This can be abused for phishing attacks.",
		FixKO:                      "리다이렉트 대상 URL을 화이트리스트로 관리하거나, 사용자 입력값을 기반으로 리다이렉트하지 않도록 하십시오.",
		FixEN:                      "Whitelist redirect target URLs or avoid redirecting based on user input.",
		IsPotentiallyFalsePositive: false,
	},
	"BACKUP_FILE_EXPOSED": {
		TitleKO:                    "백업/임시 파일 노출",
		TitleEN:                    "Backup/Temporary File Exposed",
		MessageKO:                  "민감한 백업 또는 임시 파일 '%s'가 외부에 노출되어 소스코드나 설정 정보가 유출될 수 있습니다.",
		MessageEN:                  "Sensitive backup or temporary file '%s' is exposed, potentially leaking source code or configuration.",
		FixKO:                      "웹 서버 설정에서 .bak, .old, .swp 등의 확장자를 가진 파일에 대한 접근을 차단하고, 불필요한 파일은 삭제하십시오.",
		FixEN:                      "Configure web server to block access to files with extensions like .bak, .old, .swp, and remove unnecessary files.",
		IsPotentiallyFalsePositive: false,
	},
	"SENSITIVE_API_KEY_FOUND": {
		TitleKO:                    "민감한 API 키 또는 토큰 발견",
		TitleEN:                    "Sensitive API Key or Token Found",
		MessageKO:                  "자바스크립트 파일 또는 HTML 내에서 민감한 API 키/토큰 패턴이 발견되었습니다. (%s: %s)",
		MessageEN:                  "Sensitive API key/token pattern found in JavaScript or HTML. (%s: %s)",
		FixKO:                      "API 키가 클라이언트 측 코드에 노출되지 않도록 하십시오. 필요한 경우 환경 변수나 백엔드 프록시를 사용해야 합니다.",
		FixEN:                      "Ensure API keys are not exposed in client-side code. Use environment variables or backend proxies if necessary.",
		IsPotentiallyFalsePositive: true,
	},
	"CONSOLE_LOG_EXPOSED": {
		TitleKO:                    "디버깅 로그(console.log) 노출",
		TitleEN:                    "Debugging Log (console.log) Exposed",
		MessageKO:                  "소스코드에서 'console.log' 등 디버깅용 코드가 발견되었습니다. 중요 정보가 브라우저 콘솔에 노출될 수 있습니다. (패턴: %s)",
		MessageEN:                  "Debugging code like 'console.log' found. Sensitive info may be exposed in browser console. (Pattern: %s)",
		FixKO:                      "운영 배포 시에는 모든 'console.*' 코드를 제거하십시오.",
		FixEN:                      "Remove all 'console.*' codes in production.",
		IsPotentiallyFalsePositive: true,
	},
	"SQL_INJECTION_ERROR_BASED": {
		TitleKO:                    "SQL Injection (Error-based) 취약점",
		TitleEN:                    "SQL Injection (Error-based) Vulnerability",
		MessageKO:                  "파라미터 '%s'에 SQL 구문 삽입 시 데이터베이스 에러 메시지가 반환되었습니다. (Payload: %s) 이는 애플리케이션이 사용자 입력을 쿼리에 직접 연결하고 있음을 나타냅니다.",
		MessageEN:                  "Database error message returned when injecting SQL syntax into parameter '%s'. (Payload: %s) This indicates the application concatenates user input directly into queries.",
		FixKO:                      "1. Prepared Statement 사용: 모든 데이터베이스 쿼리에 파라미터화된 쿼리(Parameterized Query)를 사용하여 사용자 입력값이 SQL 코드로 해석되지 않도록 하십시오.\n2. 입력값 검증: 입력값의 타입, 길이, 형식을 엄격하게 검증하십시오.\n3. 에러 메시지 노출 금지: 데이터베이스 에러 메시지가 사용자에게 직접 노출되지 않도록 예외 처리를 설정하고, 일반적인 에러 페이지를 보여주도록 구성하십시오.",
		FixEN:                      "1. Use Prepared Statements: Use parameterized queries for all DB operations.\n2. Input Validation: Strictly validate input type, length, and format.\n3. Suppress Error Messages: Configure exception handling to prevent exposing DB errors to users.",
		IsPotentiallyFalsePositive: false,
	},
	"NETWORK_TRANSPORT_SECURITY": {
		TitleKO: "네트워크 전송 보안 기본 점검",
		TitleEN: "Network Transport Security Check",
	},
	"SECURITY_HEADERS": {
		TitleKO: "보안 헤더 점검",
		TitleEN: "Security Headers Check",
	},
	"TLS_CONFIGURATION": {
		TitleKO: "TLS 설정 점검",
		TitleEN: "TLS Configuration Check",
	},
	"HTTP_CONFIGURATION": {
		TitleKO: "HTTP 프로토콜 설정 점검",
		TitleEN: "HTTP Protocol Configuration Check",
	},
	"AUTH_SESSION_HARDENING": {
		TitleKO: "인증/세션 강화 점검 (쿠키 속성)",
		TitleEN: "Auth/Session Hardening Check (Cookie Attributes)",
	},
	"SESSION_MANAGEMENT": {
		TitleKO: "세션 관리 점검",
		TitleEN: "Session Management Check",
	},
	"PARAMETER_POLLUTION": {
		TitleKO: "파라미터 오염 (Parameter Pollution) 점검",
		TitleEN: "Parameter Pollution Check",
	},
	"CONTENT_TYPE_CONFUSION": {
		TitleKO: "Content-Type 혼동 점검",
		TitleEN: "Content-Type Confusion Check",
	},
	"CORS_CONFIGURATION": {
		TitleKO: "CORS 설정 오류 점검",
		TitleEN: "CORS Configuration Check",
	},
	"INFORMATION_LEAKAGE": {
		TitleKO: "정보 누출 점검",
		TitleEN: "Information Leakage Check",
	},
	"RATE_LIMIT_ABSENCE": {
		TitleKO: "Rate Limit 부재 점검",
		TitleEN: "Rate Limit Absence Check",
	},
	"APPLICATION_SECURITY": {
		TitleKO: "애플리케이션 보안 점검",
		TitleEN: "Application Security Check",
	},
	"PACKET_ANALYSIS": {
		TitleKO: "패킷 기반 이상 징후 분석",
		TitleEN: "Packet-based Anomaly Analysis",
	},
	"WEB_CONTENT_EXPOSURE": {
		TitleKO: "웹 콘텐츠 및 파일 노출 점검",
		TitleEN: "Web Content & File Exposure Check",
	},
	"SQL_INJECTION": {
		TitleKO: "SQL Injection 점검",
		TitleEN: "SQL Injection Check",
	},
	"REFLECTED_XSS": {
		TitleKO:                    "Reflected XSS (반사형 크로스 사이트 스크립팅) 취약점",
		TitleEN:                    "Reflected XSS Vulnerability",
		MessageKO:                  "파라미터 '%s'를 통해 주입된 스크립트 코드가 사용자 입력값 검증 없이 응답 페이지에 그대로 반사되어 실행됩니다. 공격자는 이를 통해 세션 탈취, 악성 사이트 리다이렉트 등을 수행할 수 있습니다.",
		MessageEN:                  "Script code injected via parameter '%s' is reflected and executed in the response page without validation. Attackers can use this to steal sessions or redirect users.",
		FixKO:                      "1. 입력값 검증 및 인코딩: 사용자로부터 입력받은 모든 데이터를 신뢰하지 말고, 출력 시 HTML 엔티티 인코딩(Escaping)을 적용해야 합니다. (예: < -> &lt;, > -> &gt;, & -> &amp;, \" -> &quot;, ' -> &#x27;)\n2. 보안 라이브러리 사용: 사용하는 프레임워크(React, Vue, Spring 등)에서 제공하는 XSS 방어 메커니즘을 활용하십시오.\n3. CSP(Content Security Policy) 적용: 응답 헤더에 CSP를 설정하여 승인되지 않은 스크립트의 실행을 차단하십시오.",
		FixEN:                      "1. Input/Output Encoding: Escape user input as HTML entities (e.g., < -> &lt;). \n2. Use Security Libraries: Utilize framework XSS protection features.\n3. Apply CSP: Set Content-Security-Policy headers to block unauthorized scripts.",
		IsPotentiallyFalsePositive: false,
	},
	"BLIND_SQL_INJECTION": {
		TitleKO: "블라인드 SQL Injection 점검 (시간 기반)",
		TitleEN: "Blind SQL Injection Check (Time-based)",
	},
	"OS_COMMAND_INJECTION": {
		TitleKO: "OS 커맨드 인젝션 점검 (시간 기반)",
		TitleEN: "OS Command Injection Check (Time-based)",
	},
	"SSTI_INJECTION": {
		TitleKO: "SSTI (Server-Side Template Injection) 점검",
		TitleEN: "SSTI (Server-Side Template Injection) Check",
	},
	"XXE_INJECTION": {
		TitleKO: "XXE (XML External Entity) 점검",
		TitleEN: "XXE (XML External Entity) Check",
	},
	"SSRF_DETECTION": {
		TitleKO: "SSRF (Server-Side Request Forgery) 탐지",
		TitleEN: "SSRF Detection",
	},
	"INSECURE_DESERIALIZATION": {
		TitleKO: "안전하지 않은 역직렬화 탐지",
		TitleEN: "Insecure Deserialization Detection",
	},
	"VULNERABLE_COMPONENTS": {
		TitleKO: "취약한 컴포넌트 버전 식별",
		TitleEN: "Vulnerable Component Identification",
	},
	"MISSING_SECURITY_HEADERS": {
		TitleKO:                    "보안 헤더 누락",
		TitleEN:                    "Missing Security Headers",
		MessageKO:                  "다음 보안 헤더가 응답에 포함되지 않았습니다: %s",
		MessageEN:                  "The following security headers are missing from the response: %s",
		FixKO:                      "웹 서버 설정 또는 애플리케이션 코드에서 누락된 보안 헤더를 추가하여 보안을 강화하십시오.",
		FixEN:                      "Add the missing security headers in the web server configuration or application code to enhance security.",
		IsPotentiallyFalsePositive: false,
	},
}

// uiMessages holds localized UI strings.
var uiMessages = map[string]map[Language]string{
	"CrawlerStart": {
		LangKO: "크롤링 시작: 최대 깊이 %d",
		LangEN: "Starting crawler: max depth %d",
	},
	"HTMLReportTitle": {
		LangKO: "보안 진단 리포트",
		LangEN: "Security Scan Report",
	},
	"HTMLTarget": {
		LangKO: "대상",
		LangEN: "Target",
	},
	"HTMLScanTime": {
		LangKO: "스캔 시간",
		LangEN: "Scan Time",
	},
	"HTMLDuration": {
		LangKO: "소요 시간",
		LangEN: "Duration",
	},
	"HTMLHigh": {
		LangKO: "위험 (High)",
		LangEN: "High",
	},
	"HTMLMedium": {
		LangKO: "경고 (Medium)",
		LangEN: "Medium",
	},
	"HTMLLow": {
		LangKO: "주의 (Low)",
		LangEN: "Low",
	},
	"HTMLInfo": {
		LangKO: "정보 (Info)",
		LangEN: "Info",
	},
	"HTMLCrawledScope": {
		LangKO: "크롤링된 범위",
		LangEN: "Crawled Scope",
	},
	"HTMLFindings": {
		LangKO: "발견된 취약점",
		LangEN: "Findings",
	},
	"HTMLRecommendation": {
		LangKO: "조치 방안",
		LangEN: "Recommendation",
	},
	"HTMLChartTitle": {
		LangKO: "취약점 심각도 분포",
		LangEN: "Vulnerability Severity Distribution",
	},
	"UIManualVerification": {
		LangKO: "[!] 이 항목은 오탐 가능성이 있으므로 수동 검증이 권장됩니다.",
		LangEN: "[!] Manual verification is recommended as this may be a false positive.",
	},
	"UINoVulns": {
		LangKO: "[OK] 발견된 취약점이 없습니다.",
		LangEN: "[OK] No vulnerabilities found.",
	},
	"JSONReportSaved": {
		LangKO: "JSON 리포트가 저장되었습니다: %s",
		LangEN: "JSON Report saved: %s",
	},
	"ScanSummaryTitle": {
		LangKO: "스캔 요약",
		LangEN: "Scan Summary",
	},
	"CheckStatusFound": {
		LangKO: "발견됨",
		LangEN: "Found",
	},
	"CheckStatusNotFound": {
		LangKO: "미발견",
		LangEN: "Not Found",
	},
	"ConsoleFindingsTitle": {
		LangKO: "--- 발견된 취약점 ---",
		LangEN: "--- Findings ---",
	},
	"ConsoleFixLabel": {
		LangKO: "조치방안",
		LangEN: "Fix",
	},
	"ConsoleConfidenceLabel": {
		LangKO: "신뢰도",
		LangEN: "Confidence",
	},
	"ConsoleEvidenceLabel": {
		LangKO: "증거",
		LangEN: "Evidence",
	},
	"ConsoleScanSummaryTitle": {
		LangKO: "--- 스캔 요약 ---",
		LangEN: "--- Scan Summary ---",
	},
	"ConsoleSkipped": {
		LangKO: "건너뜀",
		LangEN: "Skipped",
	},
	"ConsoleActiveModeRequired": {
		LangKO: "Active 모드 필요",
		LangEN: "Active Mode Required",
	},
	"ConsoleNoIssues": {
		LangKO: "[OK] 발견된 취약점이 없습니다.",
		LangEN: "[OK] No issues found",
	},
	"ScanningCheck": {
		LangKO: "점검 중: %s",
		LangEN: "Checking: %s",
	},
	"ScanCompleteMsg": {
		LangKO: "스캔 완료",
		LangEN: "Scan Complete",
	},
	"SummaryReportTitle": {
		LangKO: "스캔 요약 리포트",
		LangEN: "Scan Summary Report",
	},
	"SummarySeverity": {
		LangKO: "심각도",
		LangEN: "Severity",
	},
	"SummaryCount": {
		LangKO: "개수",
		LangEN: "Count",
	},
	"SummaryTotal": {
		LangKO: "총 발견된 취약점",
		LangEN: "Total Issues",
	},
	"ScanCancelled": {
		LangKO: "스캔이 취소되었습니다.",
		LangEN: "Scan cancelled.",
	},
	"ActiveScanWarning": {
		LangKO: "[!] 경고: Active Scan 모드는 대상 서버에 실제 공격 페이로드를 전송합니다.",
		LangEN: "[!] WARNING: Active Scan mode sends actual attack payloads to the target server.",
	},
	"ActiveScanPermission": {
		LangKO: "이 도구를 사용함으로써 귀하는 대상 시스템에 대한 테스트 권한이 있음을 확인하는 것입니다.",
		LangEN: "By using this tool, you confirm that you have permission to test the target system.",
	},
	"ActiveScanPrompt": {
		LangKO: "계속하시겠습니까?",
		LangEN: "Do you want to continue?",
	},
	"ActiveScanAborted": {
		LangKO: "사용자에 의해 스캔이 중단되었습니다.",
		LangEN: "Scan aborted by user.",
	},
	"Target": {
		LangKO: "대상: %s",
		LangEN: "Target: %s",
	},
	"ModeActive": {
		LangKO: "모드: Active Scan (침투 테스트)",
		LangEN: "Mode: Active Scan (Penetration Test)",
	},
	"ModePassive": {
		LangKO: "모드: Passive Scan (비침투)",
		LangEN: "Mode: Passive Scan (Non-intrusive)",
	},
	"StatusReady": {
		LangKO: "상태: 준비됨",
		LangEN: "Status: Ready",
	},
	"CrawlingComplete": {
		LangKO: "크롤링 완료: %d 개의 URL 발견",
		LangEN: "Crawling complete: %d URLs found",
	},
	"CrawledScope": {
		LangKO: "크롤링된 범위:",
		LangEN: "Crawled Scope:",
	},
	"ScanningProgress": {
		LangKO: "스캔 진행 중 [%d/%d]: %s",
		LangEN: "Scanning [%d/%d]: %s",
	},
	"ScannerInitFailed": {
		LangKO: "스캐너 초기화 실패 (%s): %v",
		LangEN: "Scanner init failed (%s): %v",
	},
	"ScanFailed": {
		LangKO: "스캔 실패 (%s): %v",
		LangEN: "Scan failed (%s): %v",
	},
	"AllScansCompleted": {
		LangKO: "모든 스캔이 완료되었습니다.",
		LangEN: "All scans completed.",
	},
	"JSONReportFailed": {
		LangKO: "JSON 리포트 저장 실패: %v",
		LangEN: "Failed to save JSON report: %v",
	},
	"HTMLReportFailed": {
		LangKO: "HTML 리포트 저장 실패: %v",
		LangEN: "Failed to save HTML report: %v",
	},
	"InteractiveWelcome": {
		LangKO: "PRS에 오신 것을 환영합니다. 'help'를 입력하여 명령어를 확인하세요.",
		LangEN: "Welcome to PRS Interactive Mode. Type 'help' for commands.",
	},
	"InteractiveExit": {
		LangKO: "프로그램을 종료합니다.",
		LangEN: "Exiting program.",
	},
	"InteractiveHelp": {
		LangKO: "사용 가능한 명령어:",
		LangEN: "Available commands:",
	},
	"InteractiveErrorTarget": {
		LangKO: "오류: 대상 URL이 필요합니다. 사용법: %s <url> ...",
		LangEN: "Error: Target URL required. Usage: %s <url> ...",
	},
	"InteractiveScanFailed": {
		LangKO: "스캔 실행 중 오류 발생: %v",
		LangEN: "Error running scan: %v",
	},
	"ScanProgress": {
		LangKO: "\r[진행률] %d/%d (%s) - %s\x1b[K", // \x1b[K는 줄의 나머지 부분을 지움
		LangEN: "\r[Progress] %d/%d (%s) - %s\x1b[K",
	},
	"InteractiveErrorUnknown": {
		LangKO: "알 수 없는 명령어: %s",
		LangEN: "Unknown command: %s",
	},
	"InteractiveErrorUnknownFlag": {
		LangKO: "알 수 없는 명령어: %s",
		LangEN: "Unknown flag: %s",
	},
	"AskSaveHTML": {
		LangKO: "스캔이 종료된 후 HTML 리포트를 저장하시겠습니까?",
		LangEN: "Do you want to save the HTML report?",
	},
}

// 기본값은 MessageDetail의 필드가 비어있는 상태
func GetMessage(id string) MessageDetail {
	langMu.RLock()
	lang := CurrentLanguage
	langMu.RUnlock()

	if msg, ok := findingMessages[id]; ok {
		if lang == LangEN {
			return MessageDetail{
				Title:                      msg.TitleEN,
				Message:                    msg.MessageEN,
				Fix:                        msg.FixEN,
				IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
			}
		}

		title := msg.TitleKO
		message := msg.MessageKO
		fix := msg.FixKO
		if shouldFallbackKorean(title) {
			title = msg.TitleEN
		}
		if shouldFallbackKorean(message) {
			message = msg.MessageEN
		}
		if shouldFallbackKorean(fix) {
			fix = msg.FixEN
		}

		return MessageDetail{
			Title:                      title,
			Message:                    message,
			Fix:                        fix,
			IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
		}
	}
	return MessageDetail{
		Title:                      "Message Not Found",
		Message:                    fmt.Sprintf("Message details for ID '%s' not found.", id),
		Fix:                        "Please check the message ID.",
		IsPotentiallyFalsePositive: true,
	}
}

func GetUIMessage(id string, args ...interface{}) string {
	langMu.RLock()
	lang := CurrentLanguage
	langMu.RUnlock()

	if msgs, ok := uiMessages[id]; ok {
		format, ok := msgs[lang]
		if !ok {
			format = msgs[LangEN]
		}
		if lang == LangKO && shouldFallbackKorean(format) {
			format = msgs[LangEN]
		}
		if format == "" {
			return id
		}
		if len(args) > 0 {
			return fmt.Sprintf(format, args...)
		}
		return format
	}
	return id
}

func shouldFallbackKorean(s string) bool {
	if s == "" {
		return true
	}
	return strings.Contains(s, "??") || strings.ContainsRune(s, '\uFFFD')
}
