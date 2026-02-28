package checks

import (
	context "github.com/MOYARU/prs/internal/checks/context"
	"github.com/MOYARU/prs/internal/report"
)

type Category string

const (
	CategoryNetwork              Category = "CAT_NETWORK"
	CategoryHTTPProtocol         Category = "CAT_HTTP_PROTOCOL"
	CategorySecurityHeaders      Category = "CAT_SECURITY_HEADERS"
	CategoryAuthSession          Category = "CAT_AUTH_SESSION"
	CategoryInputHandling        Category = "CAT_INPUT_HANDLING"
	CategoryAccessControl        Category = "CAT_ACCESS_CONTROL"
	CategoryFileExposure         Category = "CAT_FILE_EXPOSURE"
	CategoryInfrastructure       Category = "CAT_INFRASTRUCTURE"
	CategoryAppLogic             Category = "CAT_APP_LOGIC"
	CategoryAPI                  Category = "CAT_API"
	CategoryClientSecurity       Category = "CAT_CLIENT_SECURITY"
	CategoryOps                  Category = "CAT_OPS"
	CategoryInformationLeakage   Category = "CAT_INFO_LEAKAGE"
	CategoryAPISecurity          Category = "CAT_API_SECURITY"
	CategoryVulnerableComponents Category = "CAT_VULN_COMPONENTS"
	CategoryIntegrityFailures    Category = "CAT_INTEGRITY"
	CategorySSRF                 Category = "CAT_SSRF"
)

type Check struct {
	ID          string
	Category    Category
	Title       string
	Description string
	Mode        context.ScanMode
	Run         func(*context.Context) ([]report.Finding, error)
}
