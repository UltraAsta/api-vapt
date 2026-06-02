package attacks

import (
	"apivapt/schema"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"strings"
)

// Methods that carry a body and can create/update records.
var mutatingMethods = map[string]bool{
	"POST":  true,
	"PUT":   true,
	"PATCH": true,
}

// Privileged / internal fields a client should never be able to set.
// If the server accepts and reflects one of these, it is likely binding
// the whole request body straight onto its model (mass assignment).
var massAssignmentPayloads = map[string]any{
	"is_admin":    true,
	"isAdmin":     true,
	"admin":       true,
	"role":        "admin",
	"roles":       []string{"admin"},
	"is_active":   true,
	"verified":    true,
	"email_verified": true,
	"account_balance": 999999,
	"balance":     999999,
	"credits":     999999,
	"permissions": []string{"*"},
	"id":          1,
	"user_id":     1,
	"status":      "approved",
}

func (m *MassAssignment) Run(endpoint schema.Endpoint, baseURL string) []schema.Findings {
	var findings []schema.Findings

	url := baseURL + endpoint.Path

	for _, method := range endpoint.Methods {
		if !mutatingMethods[strings.ToUpper(method)] {
			continue
		}

		// 1. Build a legitimate baseline body from the documented body args.
		baseBody := legitimateBody(endpoint.Args)

		baseline := sendJSON(method, url, baseBody)
		if baseline == nil {
			continue
		}

		// 2. Inject one privileged field at a time on top of the legit body.
		for field, value := range massAssignmentPayloads {
			// Skip fields the endpoint already documents — those aren't an
			// authorization boundary being crossed.
			if _, documented := endpoint.Args[field]; documented {
				continue
			}

			tampered := make(map[string]any, len(baseBody)+1)
			maps.Copy(tampered, baseBody)
			tampered[field] = value

			result := sendJSON(method, url, tampered)
			if result == nil {
				continue
			}

			// 3. Evidence: the request succeeded AND the injected field is
			// echoed back in the response while it was absent from baseline.
			// Reflection of a field we never legitimately sent is a strong
			// signal the server persisted it.
			injectedReflected := strings.Contains(result.body, fmt.Sprintf("%q", field))
			inBaseline := strings.Contains(baseline.body, fmt.Sprintf("%q", field))

			if result.status >= 200 && result.status < 300 && injectedReflected && !inBaseline {
				reqJSON, _ := json.Marshal(tampered)
				findings = append(findings, schema.Findings{
					Endpoint: endpoint.Path,
					Method:   method,
					Attack:   "Mass Assignment",
					Severity: "high",
					Evidence: fmt.Sprintf("injected field %q (%v) was accepted (HTTP %d) and reflected in the response; absent from baseline",
						field, value, result.status),
					Request:  fmt.Sprintf("%s %s\n%s", method, url, reqJSON),
					Response: result.body,
				})
			}
		}
	}

	return findings
}

// legitimateBody fills in dummy values for documented body args so the
// request is well-formed enough for the server to process it.
func legitimateBody(args map[string]schema.Arg) map[string]any {
	body := map[string]any{}
	for name, arg := range args {
		if arg.In != "body" {
			continue
		}
		if arg.Default != nil {
			body[name] = arg.Default
			continue
		}
		if len(arg.Enum) > 0 {
			body[name] = arg.Enum[0]
			continue
		}
		body[name] = dummyValue(arg.Type)
	}
	return body
}

func dummyValue(argType string) any {
	switch strings.ToLower(argType) {
	case "integer", "number":
		return 1
	case "boolean":
		return true
	case "array":
		return []any{}
	case "object":
		return map[string]any{}
	default:
		return "test"
	}
}

func sendJSON(method, url string, body map[string]any) *response {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil
	}

	req, err := http.NewRequest(strings.ToUpper(method), url, bytes.NewReader(payload))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4000))
	resp.Body.Close()

	return &response{status: resp.StatusCode, bodyLen: len(respBody), body: string(respBody)}
}
