package attacks

import (
	"apivapt/schema"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
)

var numericID = regexp.MustCompile(`/(\d+)(/|$)`)

func (b *BOLA) Run(endpoint schema.Endpoint, baseURL string) []schema.Findings {
	match := numericID.FindStringSubmatchIndex(endpoint.Path)
	if match == nil {
		return nil
	}

	origIDStr := endpoint.Path[match[2]:match[3]]
	origID, _ := strconv.Atoi(origIDStr)

	candidates := []int{1, 2, 3, origID - 1, origID + 1}

	var findings []schema.Findings
	for _, id := range candidates {
		if id <= 0 || id == origID {
			continue
		}

		newPath := endpoint.Path[:match[2]] + strconv.Itoa(id) + endpoint.Path[match[3]:]
		url := baseURL + newPath

		for _, method := range endpoint.Methods {
			req, err := http.NewRequest(method, url, nil)
			if err != nil {
				continue
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 2000))
			resp.Body.Close()

			if resp.StatusCode == 200 && len(body) > 10 {
				snippet := string(body)
				if len(snippet) > 200 {
					snippet = snippet[:200]
				}
				findings = append(findings, schema.Findings{
					Endpoint: newPath,
					Method:   method,
					Attack:   "BOLA",
					Severity: "high",
					Evidence: fmt.Sprintf("ID %d returned %d — %s", id, resp.StatusCode, snippet),
					Request:  fmt.Sprintf("%s %s", method, url),
					Response: string(body),
				})
			}
		}
	}

	return findings
}
