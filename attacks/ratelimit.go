package attacks

import (
	"apivapt/schema"
	"fmt"
	"net/http"
)

func (r *RateLimit) Run(endpoint schema.Endpoint, baseURL string) []schema.Findings {
	var findings []schema.Findings
	url := baseURL + endpoint.Path

	for i := range 1_000 {
		for _, method := range endpoint.Methods {
			req, err := http.NewRequest(method, url, nil)
			if err != nil {
				fmt.Printf("Request [%v] %v failed: %v", method, url, err)
				continue
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				fmt.Printf("Failed to execute request [%v] %v with error: %v", method, url, err)
				continue
			}

			resp.Body.Close()

			if resp.StatusCode == http.StatusTooManyRequests {
				findings = append(findings, schema.Findings{
					Endpoint: url,
					Method:   method,
					Attack:   "RateLimit",
					Severity: "medium",
					Evidence: fmt.Sprintf("429 received after %d requests", i+1),
					Request:  fmt.Sprintf("%s %s", method, url),
					Response: fmt.Sprintf("HTTP %d", resp.StatusCode),
				})
				// rate limit hit. no need to continue
				return findings
			}
		}
	}

	// no rate limit hit
	return findings
}
