package messages

import (
	"fmt"
)

// 그거 아시나요? 과거에는 한국어가 있었다는 사실
type MessageDetail struct {
	Title                      string
	Message                    string
	Fix                        string
	IsPotentiallyFalsePositive bool
}

type rawMessageDetail struct {
	TitleEN                    string
	MessageEN                  string
	FixEN                      string
	IsPotentiallyFalsePositive bool
}

var findingMessages = map[string]rawMessageDetail{
	"CORS_WILDCARD_ORIGIN": {
		TitleEN:                    "CORS Wildcard Origin Allowed",
		MessageEN:                  "The Access-Control-Allow-Origin header is set to '*', allowing resource access from any domain. This risks exposing sensitive information.",
		FixEN:                      "Specify a trusted domain in the Access-Control-Allow-Origin header instead of a wildcard ('*'). If multiple domains must be supported, validate the Origin header on the server side and return the Origin only if it is whitelisted.",
		IsPotentiallyFalsePositive: false,
	},
	"CORS_ORIGIN_REFLECTION": {
		MessageEN:                  "The request's Origin header '%s' is reflected in Access-Control-Allow-Origin. This may allow resource access from arbitrary domains.",
		FixEN:                      "Explicitly specify only allowed Origins (whitelist) in the Access-Control-Allow-Origin header, and do not reflect the request Origin directly.",
		IsPotentiallyFalsePositive: false,
	},
	"HTTPS_NOT_USED": {
		MessageEN:                  "HTTPS is not used, posing a risk of data exposure during transmission.",
		FixEN:                      "Obtain a valid TLS certificate from a trusted CA (like Let's Encrypt) and apply it to the web server. All production traffic should be transmitted over encrypted channels (HTTPS).",
		IsPotentiallyFalsePositive: false,
	},
	"HTTP_TO_HTTPS_REDIRECT_MISSING": {
		MessageEN:                  "HTTP requests are not forcibly redirected to HTTPS.",
		FixEN:                      "Configure the web server (Nginx, Apache, etc.) to redirect all requests on port 80 (HTTP) to port 443 (HTTPS) with a 301 (Moved Permanently) status.",
		IsPotentiallyFalsePositive: false,
	},
	"HTTPS_DOWNGRADE": {
		TitleEN:                    "HTTPS Downgrade Detected",
		IsPotentiallyFalsePositive: false,
	},
	"TLS_VERSION_SUPPORTED_V": { // %s is not part of the ID, it's a format specifier
		MessageEN:                  "The target server supports the insecure and deprecated TLS %s protocol.",
		FixEN:                      "Disable legacy protocols like SSLv3, TLS 1.0, and TLS 1.1 in the web server's SSL/TLS settings. It is recommended to enable only TLS 1.2 and TLS 1.3 for security.",
		IsPotentiallyFalsePositive: false,
	},
	"TLS_VERSION_DETECTED_V": { // %s is not part of the ID, it's a format specifier
		TitleEN:                    "Vulnerable TLS %s Used",
		MessageEN:                  "The target server established a connection using the vulnerable TLS %s protocol.",
		FixEN:                      "Disable legacy protocols like SSLv3, TLS 1.0, and TLS 1.1 in the web server's SSL/TLS settings. It is recommended to enable only TLS 1.2 and TLS 1.3 for security.",
		IsPotentiallyFalsePositive: false,
	},
	"WEAK_CIPHER_SUITE": {
		TitleEN:                    "Weak Cipher Suite Used",
		MessageEN:                  "The target server uses a weak cipher suite '%s'. Reason: %s",
		FixEN:                      "Disable cipher suites using weak encryption algorithms like RC4, 3DES, or CBC mode. Prioritize strong encryption algorithms like AES-GCM or ChaCha20-Poly1305 with Forward Secrecy (ECDHE or DHE).",
		IsPotentiallyFalsePositive: false,
	},
	"NO_FORWARD_SECRECY_TLS12": {
		TitleEN:                    "Forward Secrecy Not Applied (TLS 1.2)",
		MessageEN:                  "TLS 1.2 is used, but the current cipher suite '%s' may not provide Forward Secrecy.",
		FixEN:                      "Configure the server to use only cipher suites that provide strong Forward Secrecy based on ECDHE or DHE (e.g., AES-GCM, ChaCha20-Poly1305).",
		IsPotentiallyFalsePositive: false,
	},
	"CERTIFICATE_EXPIRED": {
		TitleEN:                    "Certificate Expired",
		MessageEN:                  "The TLS certificate expired on %s.",
		FixEN:                      "Renew the expired TLS certificate.",
		IsPotentiallyFalsePositive: false,
	},
	"CERTIFICATE_EXPIRING_SOON": {
		TitleEN:                    "Certificate Expiring Soon",
		MessageEN:                  "The TLS certificate is scheduled to expire within a month on %s.",
		FixEN:                      "Plan to renew the TLS certificate.",
		IsPotentiallyFalsePositive: false,
	},
	"CERTIFICATE_HOSTNAME_MISMATCH": {
		MessageEN:                  "The CN/SAN field of the TLS certificate does not match the target host '%s'. Error: %s",
		FixEN:                      "Use a valid TLS certificate where the Common Name (CN) or Subject Alternative Name (SAN) fields exactly match the target domain.",
		IsPotentiallyFalsePositive: false,
	},
	"OCSP_STAPLING_NOT_USED": {
		MessageEN:                  "OCSP Stapling is not enabled, which may require clients to make additional requests to check certificate revocation status.",
		FixEN:                      "Enable OCSP Stapling on the server to improve client TLS handshake performance and enhance privacy.",
		IsPotentiallyFalsePositive: false,
	},
	"INPUT_REFLECTION_DETECTED": {
		TitleEN:                    "Input Reflection Detected",
		MessageEN:                  "Input from URL parameter '%s' is reflected in the response body. This can lead to XSS attacks.",
		FixEN:                      "Apply appropriate encoding (HTML entities, URL encoding, etc.) when outputting user input to prevent reflection.",
		IsPotentiallyFalsePositive: false,
	},
	"IDOR_POSSIBLE": {
		TitleEN:                    "Possible IDOR Detected",
		MessageEN:                  "Response content changed when modifying numeric ID (%s). This may indicate access to other users' resources.",
		FixEN:                      "Implement appropriate access control (e.g., owner verification) on the server side when accessing resources using numeric IDs.",
		IsPotentiallyFalsePositive: true,
	},
	"IDOR_RESOURCE_GUESSING": {
		TitleEN:                    "IDOR-based Resource Guessing",
		MessageEN:                  "Accessed a valid resource by changing ID (%s) after attempting to access a non-existent ID. This may indicate access to other users' resources.",
		FixEN:                      "Implement appropriate access control (e.g., owner verification) on the server side when accessing resources using numeric IDs.",
		IsPotentiallyFalsePositive: true,
	},
	"CSRF_TOKEN_POSSIBLY_MISSING": {
		TitleEN:                    "CSRF Token Possibly Missing",
		MessageEN:                  "A token to prevent CSRF (Cross-Site Request Forgery) attacks may be missing from the HTML form.",
		FixEN:                      "Include a CSRF token in forms handling state-changing requests and validate the token's validity.",
		IsPotentiallyFalsePositive: true,
	},
	"GRAPHQL_INTROSPECTION_ENABLED": {
		MessageEN:                  "GraphQL Introspection is enabled on path '%s', potentially exposing schema information.",
		FixEN:                      "Disable GraphQL Introspection in production environments to prevent exposing the API's internal structure.",
		IsPotentiallyFalsePositive: false,
	},
	"SESSION_MANAGEMENT_MANUAL_REVIEW_NEEDED": {
		TitleEN:                    "Session Management Review (Manual)",
		MessageEN:                  "Session management vulnerabilities (session regeneration after login, cookie changes, etc.) are difficult to verify automatically. Manual review is required.",
		FixEN:                      "Manually verify session ID regeneration on login, session invalidation on logout, and sensitive cookie changes, and implement appropriate session management policies.",
		IsPotentiallyFalsePositive: true, // Explicitly marked for manual review, so also potentially false positive for automation
	},
	"LOGIN_PAGE_HTTPS_MISSING": {
		MessageEN:                  "Login page '%s' does not use HTTPS, risking plaintext transmission of credentials.",
		FixEN:                      "Enforce HTTPS on all authentication-related pages, including the login page.",
		IsPotentiallyFalsePositive: false,
	},
	"COOKIE_SECURE_FLAG_MISSING": {
		TitleEN:                    "Cookie Secure Flag Missing",
		MessageEN:                  "The Secure flag is missing for cookie '%s' on an HTTPS page, risking exposure during HTTP communication.",
		FixEN:                      "Set the Secure flag for all sensitive cookies.",
		IsPotentiallyFalsePositive: false,
	},
	"COOKIE_HTTPONLY_FLAG_MISSING": {
		TitleEN:                    "Cookie HttpOnly Flag Missing",
		MessageEN:                  "The HttpOnly flag is missing for cookie '%s', allowing access by client-side scripts.",
		FixEN:                      "Set the HttpOnly flag for sensitive cookies to protect against XSS attacks.",
		IsPotentiallyFalsePositive: false,
	},
	"SAMESITE_NONE_SECURE_MISSING": {
		TitleEN:                    "Secure Flag Missing for SameSite=None Cookie",
		MessageEN:                  "Cookie '%s' uses SameSite=None but is missing the Secure flag.",
		FixEN:                      "Set the Secure flag for all cookies using SameSite=None.",
		IsPotentiallyFalsePositive: false,
	},
	"SESSION_COOKIE_NO_EXPIRATION": {
		TitleEN:                    "Session Cookie No Expiration",
		MessageEN:                  "Session cookie '%s' has no expiration time set and may persist in the browser for a long time.",
		FixEN:                      "Set an appropriate expiration time (Expires or Max-Age) for session cookies to reduce session hijacking risks.",
		IsPotentiallyFalsePositive: false,
	},
	"CONTENT_SECURITY_POLICY_MISSING": { // From missingHeader("Content-Security-Policy", ...)
		TitleEN:                    "Missing Content-Security-Policy",
		MessageEN:                  "Cannot defend against XSS attacks.",
		FixEN:                      "Add 'Content-Security-Policy' to the response header. E.g., \"default-src 'self';\". This mitigates XSS by restricting resource loading to trusted sources.",
		IsPotentiallyFalsePositive: false,
	},
	"X_FRAME_OPTIONS_MISSING": { // From missingHeader("X-Frame-Options", ...)
		TitleEN:                    "Missing X-Frame-Options",
		FixEN:                      "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' to the response header to prevent Clickjacking.",
		IsPotentiallyFalsePositive: false,
	},
	"X_CONTENT_TYPE_OPTIONS_MISSING": { // From missingHeader("X-Content-Type-Options", ...)
		TitleEN:                    "Missing X-Content-Type-Options",
		MessageEN:                  "Cannot defend against MIME type sniffing.",
		FixEN:                      "Add 'X-Content-Type-Options: nosniff' to the response header. This prevents browsers from sniffing the MIME type, reducing risks like XSS.",
		IsPotentiallyFalsePositive: false,
	},
	"REFERRER_POLICY_MISSING": { // From missingHeader("Referrer-Policy", ...)
		TitleEN:                    "Missing Referrer-Policy",
		FixEN:                      "Referrer-Policy: strict-origin-when-cross-origin",
		IsPotentiallyFalsePositive: false,
	},
	"PERMISSIONS_POLICY_MISSING": { // From missingHeader("Permissions-Policy", ...)
		TitleEN:                    "Missing Permissions-Policy",
		MessageEN:                  "Insufficient control over browser features.",
		FixEN:                      "Permissions-Policy: geolocation=()",
		IsPotentiallyFalsePositive: false,
	},
	"CROSS_ORIGIN_OPENER_POLICY_MISSING": { // From missingHeader("Cross-Origin-Opener-Policy", ...)
		TitleEN:                    "Missing Cross-Origin-Opener-Policy",
		MessageEN:                  "Insufficient tab isolation protection.",
		FixEN:                      "Cross-Origin-Opener-Policy: same-origin",
		IsPotentiallyFalsePositive: false,
	},
	"CROSS_ORIGIN_EMBEDDER_POLICY_MISSING": { // From missingHeader("Cross-Origin-Embedder-Policy", ...)
		TitleEN:                    "Missing Cross-Origin-Embedder-Policy",
		MessageEN:                  "Insufficient protection for isolated contexts.",
		FixEN:                      "Cross-Origin-Embedder-Policy: require-corp",
		IsPotentiallyFalsePositive: false,
	},
	"CROSS_ORIGIN_RESOURCE_POLICY_MISSING": { // From missingHeader("Cross-Origin-Resource-Policy", ...)
		TitleEN:                    "Missing Cross-Origin-Resource-Policy",
		FixEN:                      "Cross-Origin-Resource-Policy: same-site",
		IsPotentiallyFalsePositive: false,
	},
	"HSTS_MISSING": {
		TitleEN:                    "Missing Strict-Transport-Security",
		MessageEN:                  "Insufficient enforcement of HTTPS and downgrade protection.",
		FixEN:                      "Add 'Strict-Transport-Security' to the response header. Recommended: \"max-age=31536000; includeSubDomains; preload\". This forces browsers to use HTTPS for the domain.",
		IsPotentiallyFalsePositive: false,
	},
	"HSTS_MAXAGE_LOW": {
		TitleEN:                    "HSTS max-age too low",
		MessageEN:                  "HSTS max-age value is too low, providing insufficient protection duration.",
		FixEN:                      "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
		IsPotentiallyFalsePositive: false,
	},
	"SERVER_HEADER_EXPOSED": {
		TitleEN:                    "Server header exposed",
		MessageEN:                  "Server information exposed.",
		FixEN:                      "Remove the 'Server' header or change it to a generic value (e.g., 'Server: WebServer') to prevent exposing specific software and version information.",
		IsPotentiallyFalsePositive: false,
	},
	"X_POWERED_BY_EXPOSED": {
		TitleEN:                    "X-Powered-By header exposed",
		MessageEN:                  "Framework or runtime information exposed.",
		FixEN:                      "Disable 'X-Powered-By' header generation in the application server or framework settings.",
		IsPotentiallyFalsePositive: false,
	},
	"TRACE_METHOD_ENABLED": {
		MessageEN:                  "HTTP TRACE method is enabled, making it vulnerable to XST (Cross-Site Tracing) attacks.",
		FixEN:                      "Disable the TRACE method in the web server settings.",
		IsPotentiallyFalsePositive: false,
	},
	"OPTIONS_OVER_EXPOSED": {
		TitleEN:                    "OPTIONS Method Over-Exposed",
		MessageEN:                  "Allowed HTTP methods ('%s') are over-exposed via OPTIONS, risking information leakage.",
		FixEN:                      "Disable unnecessary HTTP methods (PUT, DELETE, TRACE, etc.) and configure OPTIONS to respond only with required methods.",
		IsPotentiallyFalsePositive: false,
	},
	"PUT_METHOD_ALLOWED": {
		TitleEN:                    "PUT Method Allowed",
		MessageEN:                  "The web server allows PUT method on arbitrary paths, vulnerable to file creation/modification. Test path: %s",
		FixEN:                      "Disable PUT method unless necessary. If used, apply strong authentication and authorization.",
		IsPotentiallyFalsePositive: false,
	},
	"DELETE_METHOD_ALLOWED": {
		TitleEN:                    "DELETE Method Allowed",
		MessageEN:                  "The web server allows DELETE method on arbitrary paths, vulnerable to file deletion. Test path: %s",
		FixEN:                      "Disable DELETE method unless necessary. If used, apply strong authentication and authorization.",
		IsPotentiallyFalsePositive: false,
	},
	"ROBOTS_TXT_EXPOSED": {
		TitleEN:                    "robots.txt Exposed",
		MessageEN:                  "Potentially sensitive file/directory '%s' is exposed.",
		FixEN:                      "Block external access to the file/directory or remove it.",
		IsPotentiallyFalsePositive: false,
	},
	"SITEMAP_XML_EXPOSED": {
		TitleEN:                    "sitemap.xml Exposed",
		MessageEN:                  "Potentially sensitive file/directory '%s' is exposed.",
		FixEN:                      "Block external access to the file/directory or remove it.",
		IsPotentiallyFalsePositive: false,
	},
	"SECURITY_TXT_EXPOSED": {
		TitleEN:                    "security.txt Exposed",
		MessageEN:                  "Potentially sensitive file/directory '%s' is exposed.",
		FixEN:                      "Block external access to the file/directory or remove it.",
		IsPotentiallyFalsePositive: false,
	},
	"WELL_KNOWN_EXPOSED": {
		TitleEN:                    ".well-known Directory Exposed",
		MessageEN:                  "Potentially sensitive file/directory '%s' is exposed.",
		FixEN:                      "Block external access to the file/directory or remove it.",
		IsPotentiallyFalsePositive: false,
	},
	"GIT_HEAD_EXPOSED": {
		TitleEN:                    ".git Directory Exposed (HEAD file)",
		MessageEN:                  "Potentially sensitive file/directory '%s' is exposed.",
		FixEN:                      "Block external access to the file/directory or remove it.",
		IsPotentiallyFalsePositive: false,
	},
	"GIT_CONFIG_EXPOSED": {
		TitleEN:                    ".git Directory Exposed (config file)",
		MessageEN:                  "Potentially sensitive file/directory '%s' is exposed.",
		FixEN:                      "Block external access to the file/directory or remove it.",
		IsPotentiallyFalsePositive: false,
	},
	"ENV_EXPOSED": {
		TitleEN:                    ".env File Exposed",
		MessageEN:                  "Potentially sensitive file/directory '%s' is exposed.",
		FixEN:                      "Block external access to the file/directory or remove it.",
		IsPotentiallyFalsePositive: false,
	},
	"TRAVIS_YML_EXPOSED": {
		TitleEN:                    ".travis.yml (CI/CD) File Exposed",
		MessageEN:                  "Potentially sensitive file/directory '%s' is exposed.",
		FixEN:                      "Block external access to the file/directory or remove it.",
		IsPotentiallyFalsePositive: false,
	},
	"GITLAB_CI_YML_EXPOSED": {
		TitleEN:                    ".gitlab-ci.yml (CI/CD) File Exposed",
		MessageEN:                  "Potentially sensitive file/directory '%s' is exposed.",
		FixEN:                      "Block external access to the file/directory or remove it.",
		IsPotentiallyFalsePositive: false,
	},
	"JENKINSFILE_EXPOSED": {
		TitleEN:                    "Jenkinsfile (CI/CD) File Exposed",
		MessageEN:                  "Potentially sensitive file/directory '%s' is exposed.",
		FixEN:                      "Block external access to the file/directory or remove it.",
		IsPotentiallyFalsePositive: false,
	},
	"ACTUATOR_ENDPOINT_EXPOSED": {
		TitleEN:                    "/actuator Debug Endpoint Exposed",
		MessageEN:                  "Potentially sensitive file/directory '%s' is exposed.",
		FixEN:                      "Block external access to the file/directory or remove it.",
		IsPotentiallyFalsePositive: false,
	},
	"DEBUG_ENDPOINT_EXPOSED": {
		TitleEN:                    "/debug Debug Endpoint Exposed",
		MessageEN:                  "Potentially sensitive file/directory '%s' is exposed.",
		FixEN:                      "Block external access to the file/directory or remove it.",
		IsPotentiallyFalsePositive: false,
	},
	"MIXED_CONTENT_DETECTED": {
		TitleEN:                    "Mixed Content Detected",
		MessageEN:                  "Insecure HTTP resource '%s' is loaded on an HTTPS page.",
		FixEN:                      "Change all resources to load via HTTPS or use relative paths.",
		IsPotentiallyFalsePositive: false,
	},
	"IFRAME_SANDBOX_MISSING": {
		MessageEN:                  "<iframe> tag is missing the sandbox attribute, posing risks like clickjacking or script execution. (src: %s)",
		FixEN:                      "Add the sandbox attribute to all <iframe> tags to restrict permissions of embedded content.",
		IsPotentiallyFalsePositive: false,
	},
	"INLINE_SCRIPT_DETECTED": {
		TitleEN:                    "Inline Script Detected",
		MessageEN:                  "Inline scripts are allowed due to missing or weak Content-Security-Policy (CSP), increasing XSS risk.",
		FixEN:                      "Move JavaScript to external .js files. If inline scripts are necessary, use 'nonce' or 'sha256' hash in CSP to allow only approved scripts and avoid 'unsafe-inline'.",
		IsPotentiallyFalsePositive: true,
	},
	"JSON_API_TEXT_PLAIN_ALLOWED": {
		TitleEN:                    "JSON API Allows text/plain Content-Type",
		MessageEN:                  "JSON API endpoint processes 'Content-Type: text/plain' as JSON, exposing it to Content-Type confusion vulnerabilities.",
		FixEN:                      "Allow only 'Content-Type: application/json' for API requests and reject others.",
		IsPotentiallyFalsePositive: true,
	},
	"ACCEPT_HEADER_IGNORED": {
		TitleEN:                    "Accept Header Ignored",
		MessageEN:                  "Ignored client's 'Accept: text/html' request and returned JSON Content-Type. Potential Content-Type Negotiation vulnerability.",
		FixEN:                      "Respect the client's Accept header and respond with the requested Content-Type or return an appropriate error.",
		IsPotentiallyFalsePositive: true,
	},
	"METHOD_OVERRIDE_ALLOWED": {
		TitleEN:                    "HTTP Method Override Allowed",
		MessageEN:                  "X-HTTP-Method-Override header allows overriding POST requests to '%s' method. This may cause unexpected behavior.",
		FixEN:                      "Disable unnecessary HTTP Method Override features or strictly handle only allowed methods.",
		IsPotentiallyFalsePositive: true,
	},
	"RETRY_AFTER_HEADER_MISSING": {
		MessageEN:                  "Response is missing 'Retry-After' header, so clients cannot know the retry interval when Rate Limit is exceeded.",
		FixEN:                      "Include 'Retry-After' header to provide appropriate retry intervals to clients when Rate Limit is applied.",
		IsPotentiallyFalsePositive: false,
	},
	"X_RATELIMIT_HEADERS_MISSING": {
		MessageEN:                  "Response is missing 'X-RateLimit-*' headers, so clients cannot know Rate Limit information.",
		FixEN:                      "Include 'X-RateLimit-*' headers to clearly communicate Rate Limit information to clients.",
		IsPotentiallyFalsePositive: false,
	},
	"INFORMATION_LEAKAGE_STACK_TRACE": {
		TitleEN:                    "Stack Trace Exposed",
		MessageEN:                  "Application stack trace found in response body. Risk of exposing internal system information.",
		FixEN:                      "Review error handling settings to prevent sending stack traces to clients in production. Display user-friendly error pages and log details on the server side only.",
		IsPotentiallyFalsePositive: false,
	},
	"INFORMATION_LEAKAGE_DB_ERROR": {
		TitleEN:                    "Database Error String Exposed",
		MessageEN:                  "Database error strings found in response body. Risk of exposing internal system information like DB structure or queries.",
		FixEN:                      "Strengthen exception handling to prevent exposing SQL exceptions or DB error messages. Return only generic error messages to users.",
		IsPotentiallyFalsePositive: false,
	},
	"INFORMATION_LEAKAGE_X_POWERED_BY": {
		TitleEN:                    "X-Powered-By Header Exposed",
		MessageEN:                  "Tech stack ('%s') is exposed via X-Powered-By header.",
		FixEN:                      "Remove X-Powered-By header to minimize tech stack information exposure.",
		IsPotentiallyFalsePositive: false,
	},
	"INFORMATION_LEAKAGE_SERVER_HEADER": {
		TitleEN:                    "Server Header Exposed",
		MessageEN:                  "Web server information ('%s') is exposed via Server header.",
		FixEN:                      "Remove Server header or change to a generic value to minimize web server information exposure.",
		IsPotentiallyFalsePositive: false,
	},
	"INFORMATION_LEAKAGE_FRAMEWORK_SIGNATURE": {
		TitleEN:                    "Framework/Server Signature Exposed",
		MessageEN:                  "Framework or server signature (version info) found in response body. Attackers may exploit specific version vulnerabilities.",
		FixEN:                      "Remove unnecessary framework/server signature information from the response.",
		IsPotentiallyFalsePositive: false,
	},
	"INFORMATION_LEAKAGE_DEBUG_META_ENDPOINT": {
		TitleEN:                    "Debug/Meta Endpoint Exposed",
		MessageEN:                  "Endpoint '%s' containing potentially sensitive information is exposed.",
		FixEN:                      "Restrict or disable access to debug and meta endpoints in production environments.",
		IsPotentiallyFalsePositive: false,
	},
	"JSON_UNEXPECTED_FIELD_INSERTION": {
		TitleEN:                    "JSON Unexpected Field Insertion Check",
		MessageEN:                  "Verification of application logic when unexpected fields are inserted into JSON requests is needed.",
		FixEN:                      "Parse only allowed fields in JSON requests and ignore or return error for unexpected fields.",
		IsPotentiallyFalsePositive: true,
	},
	"JSONP_ENABLED": {
		MessageEN: "JSONP response is enabled via the '%s' URL parameter. This can be used to bypass the Same-Origin Policy and steal data from other domains.",
		FixEN:     "Discontinue using JSONP and use CORS (Cross-Origin Resource Sharing) to provide the API. If JSONP is essential, implement strict whitelist validation for callback function names to prevent arbitrary code execution.",
	},
	"XXE_DETECTED": {
		TitleEN:                    "XXE (XML External Entity) Vulnerability Detected",
		MessageEN:                  "XML parser is configured to process external entities. This can lead to local file disclosure or SSRF attacks. (Reflected: %s)",
		FixEN:                      "Disable DTD (Document Type Definition) and external entity processing in the XML parser configuration.",
		IsPotentiallyFalsePositive: false,
	},
	"PARAMETER_POLLUTION_DETECTED": {
		TitleEN:                    "Parameter Pollution Detected",
		MessageEN:                  "Response changed significantly when sending duplicate values for parameter '%s'. This indicates potential Parameter Pollution vulnerability.",
		FixEN:                      "Configure the application to handle duplicate parameters safely (e.g., use only the first value, treat as array, etc.).",
		IsPotentiallyFalsePositive: true,
	},
	"PACKET_CONTENT_TYPE_MISMATCH": {
		MessageEN:                  "Content-Type header ('%s') does not match actual body format ('%s'). This may cause MIME Sniffing attacks or parsing errors.",
		FixEN:                      "Set correct Content-Type header and apply 'X-Content-Type-Options: nosniff' header.",
		IsPotentiallyFalsePositive: false,
	},
	"PACKET_WWW_AUTHENTICATE_ON_200": {
		TitleEN:                    "WWW-Authenticate Header on 200 OK",
		MessageEN:                  "'WWW-Authenticate' header exists despite 200 OK response. This may be a misconfiguration in authentication logic.",
		FixEN:                      "Use 401 Unauthorized if authentication is required, otherwise remove unnecessary authentication headers.",
		IsPotentiallyFalsePositive: false,
	},
	"PACKET_CORS_BAD_COMBINATION": {
		TitleEN:                    "Insecure CORS Header Combination",
		MessageEN:                  "Access-Control-Allow-Origin is wildcard ('*') while Access-Control-Allow-Credentials is 'true'. (or disallowed multiple Origins)",
		FixEN:                      "Specify explicit Origin and avoid wildcard if Credentials are allowed.",
		IsPotentiallyFalsePositive: false,
	},
	"PACKET_ACCEPT_IGNORED": {
		MessageEN:                  "Responded with Content-Type ('%s') different from requested Accept type ('%s'). Content Negotiation may not be working properly.",
		FixEN:                      "Configure server to respect client's Accept header or return 406 Not Acceptable if unsupported.",
		IsPotentiallyFalsePositive: true,
	},
	"BLIND_SQLI_TIME_BASED": {
		TitleEN:                    "Blind SQL Injection (Time-based) Possible",
		MessageEN:                  "Server response delayed by approx %d seconds when injecting time delay payload into parameter '%s'. Indicates potential Time-based Blind SQL Injection.",
		FixEN:                      "Use Prepared Statements (parameterized queries) for all DB queries and validate user input. Do not concatenate input directly into queries.",
		IsPotentiallyFalsePositive: true,
	},
	"OS_COMMAND_INJECTION_TIME_BASED": {
		TitleEN:                    "OS Command Injection (Time-based) Possible",
		MessageEN:                  "Server response delayed by approx %d seconds when injecting time delay payload into parameter '%s'. Indicates potential OS Command Injection.",
		FixEN:                      "Do not execute system commands using external input. If necessary, strictly whitelist allowed commands/arguments and filter shell metacharacters.",
		IsPotentiallyFalsePositive: true,
	},
	"SSRF_CALLBACK_DETECTED": {
		TitleEN:                    "SSRF (Server-Side Request Forgery) Possible",
		MessageEN:                  "Server fetched content or response changed when injecting external URL into parameter '%s'. Indicates server requests user input URL without validation.",
		FixEN:                      "Apply whitelist of allowed domains/IPs and block access to internal networks (Localhost, Private IP) when server makes requests based on user input.",
		IsPotentiallyFalsePositive: true,
	},
	"SSRF_LOCAL_ACCESS_DETECTED": {
		TitleEN:                    "SSRF Localhost Access Detected",
		MessageEN:                  "Access to localhost (127.0.0.1:%d) service possible via parameter '%s'. Service characteristic '%s' found in response.",
		FixEN:                      "Block access to internal networks (127.0.0.0/8, 10.0.0.0/8, etc.) or allow only specific domains for outbound server requests.",
		IsPotentiallyFalsePositive: true,
	},
	"INSECURE_DESERIALIZATION_SUSPECTED": {
		TitleEN:                    "Insecure Deserialization Suspected",
		MessageEN:                  "Serialized data pattern (Java, PHP, Python, etc.) detected in parameter or cookie '%s'. Deserializing untrusted data can lead to RCE.",
		FixEN:                      "Do not deserialize data from untrusted sources. Use safe formats like JSON if possible, and verify integrity via type constraints or signatures during deserialization.",
		IsPotentiallyFalsePositive: true,
	},
	"COMPONENT_OUTDATED_DETECTED": {
		TitleEN:                    "Outdated/Vulnerable Component Detected",
		MessageEN:                  "Outdated software version info ('%s') found in server header or HTML comments. Risk of exposure to known vulnerabilities (CVE).",
		FixEN:                      "Update software and libraries to latest patched versions and disable unnecessary version info exposure in settings.",
		IsPotentiallyFalsePositive: false,
	},
	"SSTI_DETECTED": {
		TitleEN:                    "SSTI (Server-Side Template Injection) Detected",
		MessageEN:                  "Server returned evaluated result ('49') when injecting template syntax into parameter '%s'. This is a critical vulnerability leading to RCE.",
		FixEN:                      "Do not concatenate user input directly into templates. Use parameter binding provided by the template engine or strictly validate input.",
		IsPotentiallyFalsePositive: false,
	},
	"OPEN_REDIRECT_DETECTED": {
		TitleEN:                    "Open Redirect Detected",
		MessageEN:                  "Redirect to arbitrary external domain ('%s') is possible via parameter '%s'. This can be abused for phishing attacks.",
		FixEN:                      "Whitelist redirect target URLs or avoid redirecting based on user input.",
		IsPotentiallyFalsePositive: false,
	},
	"BACKUP_FILE_EXPOSED": {
		TitleEN:                    "Backup/Temporary File Exposed",
		MessageEN:                  "Sensitive backup or temporary file '%s' is exposed, potentially leaking source code or configuration.",
		FixEN:                      "Configure web server to block access to files with extensions like .bak, .old, .swp, and remove unnecessary files.",
		IsPotentiallyFalsePositive: false,
	},
	"SENSITIVE_API_KEY_FOUND": {
		TitleEN:                    "Sensitive API Key or Token Found",
		MessageEN:                  "Sensitive API key/token pattern found in JavaScript or HTML. (%s: %s)",
		FixEN:                      "Ensure API keys are not exposed in client-side code. Use environment variables or backend proxies if necessary.",
		IsPotentiallyFalsePositive: true,
	},
	"CONSOLE_LOG_EXPOSED": {
		TitleEN:                    "Debugging Log (console.log) Exposed",
		MessageEN:                  "Debugging code like 'console.log' found. Sensitive info may be exposed in browser console. (Pattern: %s)",
		FixEN:                      "Remove all 'console.*' codes in production.",
		IsPotentiallyFalsePositive: true,
	},
	"SQL_INJECTION_ERROR_BASED": {
		MessageEN:                  "Database error message returned when injecting SQL syntax into parameter '%s'. (Payload: %s) This indicates the application concatenates user input directly into queries.",
		FixEN:                      "1. Use Prepared Statements: Use parameterized queries for all DB operations.\n2. Input Validation: Strictly validate input type, length, and format.\n3. Suppress Error Messages: Configure exception handling to prevent exposing DB errors to users.",
		IsPotentiallyFalsePositive: false,
	},
	"NETWORK_TRANSPORT_SECURITY": {
		TitleEN: "Network Transport Security Check",
	},
	"SECURITY_HEADERS": {
		TitleEN: "Security Headers Check",
	},
	"TLS_CONFIGURATION": {
		TitleEN: "TLS Configuration Check",
	},
	"HTTP_CONFIGURATION": {
		TitleEN: "HTTP Protocol Configuration Check",
	},
	"AUTH_SESSION_HARDENING": {
		TitleEN: "Auth/Session Hardening Check (Cookie Attributes)",
	},
	"SESSION_MANAGEMENT": {
		TitleEN: "Session Management Check",
	},
	"PARAMETER_POLLUTION": {
		TitleEN: "Parameter Pollution Check",
	},
	"CONTENT_TYPE_CONFUSION": {
		TitleEN: "Content-Type Confusion Check",
	},
	"CORS_CONFIGURATION": {
		TitleEN: "CORS Configuration Check",
	},
	"INFORMATION_LEAKAGE": {
		TitleEN: "Information Leakage Check",
	},
	"RATE_LIMIT_ABSENCE": {
		TitleEN: "Rate Limit Absence Check",
	},
	"APPLICATION_SECURITY": {
		TitleEN: "Application Security Check",
	},
	"PACKET_ANALYSIS": {
		TitleEN: "Packet-based Anomaly Analysis",
	},
	"WEB_CONTENT_EXPOSURE": {
		TitleEN: "Web Content & File Exposure Check",
	},
	"SQL_INJECTION": {
		TitleEN: "SQL Injection Check",
	},
	"REFLECTED_XSS": {
		MessageEN:                  "Script code injected via parameter '%s' is reflected and executed in the response page without validation. Attackers can use this to steal sessions or redirect users.",
		FixEN:                      "1. Input/Output Encoding: Escape user input as HTML entities (e.g., < -> &lt;). \n2. Use Security Libraries: Utilize framework XSS protection features.\n3. Apply CSP: Set Content-Security-Policy headers to block unauthorized scripts.",
		IsPotentiallyFalsePositive: false,
	},
	"BLIND_SQL_INJECTION": {
		TitleEN: "Blind SQL Injection Check (Time-based)",
	},
	"OS_COMMAND_INJECTION": {
		TitleEN: "OS Command Injection Check (Time-based)",
	},
	"SSTI_INJECTION": {
		TitleEN: "SSTI (Server-Side Template Injection) Check",
	},
	"XXE_INJECTION": {
		TitleEN: "XXE (XML External Entity) Check",
	},
	"SSRF_DETECTION": {
		TitleEN: "SSRF Detection",
	},
	"INSECURE_DESERIALIZATION": {
		TitleEN: "Insecure Deserialization Detection",
	},
	"VULNERABLE_COMPONENTS": {
		TitleEN: "Vulnerable Component Identification",
	},
	"MISSING_SECURITY_HEADERS": {
		TitleEN:                    "Missing Security Headers",
		MessageEN:                  "The following security headers are missing from the response: %s",
		FixEN:                      "Add the missing security headers in the web server configuration or application code to enhance security.",
		IsPotentiallyFalsePositive: false,
	},
}

// uiMessages holds localized UI strings.
var uiMessages = map[string]string{
	"CrawlerStart":                "Starting crawler: max depth %d",
	"HTMLReportTitle":             "Security Scan Report",
	"HTMLTarget":                  "Target",
	"HTMLScanTime":                "Scan Time",
	"HTMLDuration":                "Duration",
	"HTMLHigh":                    "High",
	"HTMLMedium":                  "Medium",
	"HTMLLow":                     "Low",
	"HTMLInfo":                    "Info",
	"HTMLCrawledScope":            "Crawled Scope",
	"HTMLFindings":                "Findings",
	"HTMLRecommendation":          "Recommendation",
	"HTMLChartTitle":              "Vulnerability Severity Distribution",
	"UIManualVerification":        "[!] Manual verification is recommended as this may be a false positive.",
	"UINoVulns":                   "[OK] No vulnerabilities found.",
	"JSONReportSaved":             "JSON Report saved: %s",
	"ScanSummaryTitle":            "Scan Summary",
	"CheckStatusFound":            "Found",
	"CheckStatusNotFound":         "Not Found",
	"ConsoleFindingsTitle":        "--- Findings ---",
	"ConsoleFixLabel":             "Fix",
	"ConsoleConfidenceLabel":      "Confidence",
	"ConsoleValidationLabel":      "Validation",
	"ConsoleEvidenceLabel":        "Evidence",
	"ConsoleScanSummaryTitle":     "--- Scan Summary ---",
	"ConsoleSkipped":              "Skipped",
	"ConsoleActiveModeRequired":   "Active Mode Required",
	"ConsoleNoIssues":             "[OK] No issues found",
	"ScanningCheck":               "Checking: %s",
	"ScanCompleteMsg":             "Scan Complete",
	"SummaryReportTitle":          "Scan Summary Report",
	"SummarySeverity":             "Severity",
	"SummaryCount":                "Count",
	"SummaryTotal":                "Total Issues",
	"ScanCancelled":               "Scan cancelled.",
	"ActiveScanWarning":           "[!] WARNING: Active Scan mode sends actual attack payloads to the target server.",
	"ActiveScanPermission":        "By using this tool, you confirm that you have permission to test the target system.",
	"ActiveScanPrompt":            "Do you want to continue?",
	"ActiveScanAborted":           "Scan aborted by user.",
	"Target":                      "Target: %s",
	"ModeActive":                  "Mode: Active Scan (Penetration Test)",
	"ModePassive":                 "Mode: Passive Scan (Non-intrusive)",
	"StatusReady":                 "Status: Ready",
	"CrawlingComplete":            "Crawling complete: %d URLs found",
	"CrawledScope":                "Crawled Scope:",
	"ScanningProgress":            "Scanning [%d/%d]: %s",
	"ScannerInitFailed":           "Scanner init failed (%s): %v",
	"ScanFailed":                  "Scan failed (%s): %v",
	"AllScansCompleted":           "All scans completed.",
	"JSONReportFailed":            "Failed to save JSON report: %v",
	"HTMLReportFailed":            "Failed to save HTML report: %v",
	"InteractiveWelcome":          "Welcome to PRS Interactive Mode. Type 'help' for commands.",
	"InteractiveExit":             "Exiting program.",
	"InteractiveHelp":             "Available commands:",
	"InteractiveErrorTarget":      "Error: Target URL required. Usage: %s <url> ...",
	"InteractiveScanFailed":       "Error running scan: %v",
	"ScanProgress":                "\r[Progress] %d/%d (%s) - %s\x1b[K",
	"InteractiveErrorUnknown":     "Unknown command: %s",
	"InteractiveErrorUnknownFlag": "Unknown flag: %s",
	"AskSaveHTML":                 "Do you want to save the HTML report?",
}

func GetMessage(id string) MessageDetail {
	if msg, ok := findingMessages[id]; ok {
		title := msg.TitleEN
		if title == "" {
			title = id
		}
		return MessageDetail{
			Title:                      title,
			Message:                    msg.MessageEN,
			Fix:                        msg.FixEN,
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
	format, ok := uiMessages[id]
	if !ok || format == "" {
		return id
	}
	if len(args) > 0 {
		return fmt.Sprintf(format, args...)
	}
	return format
}
