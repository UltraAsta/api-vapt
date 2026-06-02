package attacks

import (
	"apivapt/schema"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Path fragments that signal a privileged / administrative function. An
// endpoint matching one of these should normally require an elevated role.
var privilegedPathHints = []string{
	"admin", "manage", "internal", "config", "setting",
	"role", "permission", "system", "debug", "superuser", "root",
}

func (b *BFLA) Run(endpoint schema.Endpoint, baseURL string) []schema.Findings {
	// We can only judge "function-level" authorization on functions that look
	// privileged; testing every endpoint would just flag normal public reads.
	if !looksPrivileged(endpoint.Path) {
		return nil
	}

	var findings []schema.Findings
	url := baseURL + endpoint.Path

	for _, method := range endpoint.Methods {
		// By default only probe with safe methods; destructive ones are sent
		// only when explicitly opted in via the Mutating field.
		if !b.Mutating && mutatingMethods[strings.ToUpper(method)] {
			continue
		}

		// Send the request with no credentials at all.
		result := fetch(method, url)
		if result == nil {
			continue
		}

		// A privileged function answering an unauthenticated caller with
		// success (rather than 401/403) is reachable without authorization.
		if result.status >= 200 && result.status < 300 {
			findings = append(findings, schema.Findings{
				Endpoint: endpoint.Path,
				Method:   method,
				Attack:   "Broken Function Level Authorization",
				Severity: "high",
				Evidence: fmt.Sprintf("privileged endpoint returned HTTP %d to an unauthenticated request (expected 401/403)", result.status),
				Request:  fmt.Sprintf("%s %s  (no auth header)", method, url),
				Response: result.body,
			})
		}
	}

	return findings
}

func looksPrivileged(path string) bool {
	lower := strings.ToLower(path)
	for _, hint := range privilegedPathHints {
		if strings.Contains(lower, hint) {
			return true
		}
	}
	return false
}

// fetch performs a simple bodyless request and returns status + body. Shared
// by the read-only probes in this package (BFLA, ExcessiveDataExposure).
func fetch(method, url string) *response {
	req, err := http.NewRequest(strings.ToUpper(method), url, nil)
	if err != nil {
		return nil
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4000))
	resp.Body.Close()
	return &response{status: resp.StatusCode, bodyLen: len(body), body: string(body)}
}
