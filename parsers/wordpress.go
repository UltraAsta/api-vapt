package parsers

import (
	s "apivapt/schema"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
)

var wordpressPaths = []string{
	"/wp-json",
	"/index.php?rest_route=/",
	"/?rest_route=/",
	"/wp/wp-json",
	"/wp/index.php?rest_route=/",
}

func (w *WordpressParser) Detect(baseURL string, header http.Header, body []byte) (bool, string) {
	link := header.Get("Link")
	if strings.Contains(link, "api.w.org") {
		re := regexp.MustCompile(`<([^>]+)>`)
		match := re.FindStringSubmatch(link)
		if len(match) > 1 {
			return true, match[1]
		}
	}

	bodyStr := string(body)
	var pathsToSearch = []string{
		"wp-login.php", "wp-json", "wp-content", "wp-admin", "wp-includes",
	}
	for _, path := range pathsToSearch {
		if strings.Contains(bodyStr, path) {
			return true, w.probeDocURL(baseURL)
		}
	}

	return false, ""
}

func (w *WordpressParser) probeDocURL(baseURL string) string {
	for _, path := range wordpressPaths {
		url := baseURL + path
		resp, err := http.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if w.HasRoutes(b) {
			return url
		}
	}
	return ""
}

func (w *WordpressParser) HasRoutes(data []byte) bool {
	var probe map[string]json.RawMessage
	json.Unmarshal(data, &probe)

	_, ok := probe["routes"]
	return ok
}

func (w *WordpressParser) Parse(data []byte) (*s.APISchema, error) {
	var raw struct {
		URL    string `json:"url"`
		Routes map[string]struct {
			Namespace string   `json:"namespace"`
			Methods   []string `json:"methods"`
			Endpoints []struct {
				Methods []string        `json:"methods"`
				Args    json.RawMessage `json:"args"`
			} `json:"endpoints"`
		} `json:"routes"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	schema := s.APISchema{
		Type:    "wordpress",
		BaseURL: raw.URL,
	}

	skipNamespaces := map[string]bool{
		"wordfence/v1": true, "fluent-smtp": true,
		"fluentform/v1": true, "two-factor": true,
	}

	for path, route := range raw.Routes {
		if skipNamespaces[route.Namespace] {
			continue
		}
		if strings.Contains(path, "(?P<") {
			continue
		}

		endpoint := s.Endpoint{
			Path:    path,
			Methods: route.Methods,
			Args:    make(map[string]s.Arg),
		}

		for _, ep := range route.Endpoints {
			var argMap map[string]struct {
				Type     string   `json:"type"`
				Required bool     `json:"required"`
				Enum     []string `json:"enum"`
				Default  any      `json:"default"`
			}
			if err := json.Unmarshal(ep.Args, &argMap); err != nil {
				continue // was an array (no args), skip
			}
			for name, arg := range argMap {
				endpoint.Args[name] = s.Arg{
					Type:     arg.Type,
					Required: arg.Required,
					Enum:     arg.Enum,
					Default:  arg.Default,
					In:       "body",
				}
			}
		}

		if len(endpoint.Args) == 0 {
			endpoint.Args = nil
		}

		schema.Endpoints = append(schema.Endpoints, endpoint)
	}

	return &schema, nil
}

