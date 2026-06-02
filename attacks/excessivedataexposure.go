package attacks

import (
	"apivapt/schema"
	"encoding/json"
	"fmt"
	"strings"
)

// Field names that should (almost) never be returned to a client. Matched as
// substrings (case-insensitive) so "user_password" and "passwordHash" both hit.
var sensitiveFieldNames = []string{
	"password", "passwd", "pwd", "passwordhash",
	"secret", "client_secret", "access_token", "refresh_token", "token",
	"api_key", "apikey", "private_key", "privatekey",
	"ssn", "social_security", "credit_card", "card_number", "cvv",
	"salt", "session_id", "sessionid",
}

func (e *ExcessiveDataExposure) Run(endpoint schema.Endpoint, baseURL string) []schema.Findings {
	var findings []schema.Findings
	url := baseURL + endpoint.Path

	for _, method := range endpoint.Methods {
		// Only read operations return data worth inspecting.
		if strings.ToUpper(method) != "GET" {
			continue
		}

		result := fetch(method, url)
		if result == nil || result.status < 200 || result.status >= 300 {
			continue
		}

		var data any
		if err := json.Unmarshal([]byte(result.body), &data); err != nil {
			continue // not JSON — nothing structured to inspect
		}

		leaked := findSensitiveKeys(data)
		if len(leaked) > 0 {
			findings = append(findings, schema.Findings{
				Endpoint: endpoint.Path,
				Method:   method,
				Attack:   "Excessive Data Exposure",
				Severity: "medium",
				Evidence: fmt.Sprintf("response exposes sensitive field(s): %s", strings.Join(leaked, ", ")),
				Request:  fmt.Sprintf("%s %s", method, url),
				Response: result.body,
			})
		}
	}

	return findings
}

// findSensitiveKeys walks an arbitrary decoded JSON value (objects nested in
// arrays nested in objects, any depth) and returns the distinct object keys
// that match a known-sensitive name.
func findSensitiveKeys(v any) []string {
	var found []string
	seen := map[string]bool{}

	var walk func(any)
	walk = func(node any) {
		switch t := node.(type) {
		case map[string]any:
			for key, val := range t {
				if !seen[key] && isSensitiveField(key) {
					seen[key] = true
					found = append(found, key)
				}
				walk(val)
			}
		case []any:
			for _, item := range t {
				walk(item)
			}
		}
	}
	walk(v)
	return found
}

func isSensitiveField(key string) bool {
	lower := strings.ToLower(key)
	for _, s := range sensitiveFieldNames {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}
