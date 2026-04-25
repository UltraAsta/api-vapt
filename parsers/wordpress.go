package parsers

import (
	s "apivapt/schema"
	"encoding/json"
	"fmt"
	"strings"
)

func (w *WordpressParser) Detect(data []byte) bool {
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

func (w *WordpressParser) Compress(schema *s.APISchema) ([]string, error) {
	var compressedEndpoints []string

	for _, endpoint := range schema.Endpoints {
		methods := strings.Join(endpoint.Methods, ",")
		path := endpoint.Path

		var argList []string
		for key, value := range endpoint.Args {
			enums := strings.Join(value.Enum, "|")
			requiredOrNot := ""
			if value.Required == true {
				requiredOrNot = "*"
			}

			defaultValue := ""
			if value.Default != nil {
				defaultValue = fmt.Sprintf("=%v", value.Default)
			}

			arg := fmt.Sprintf("%v%v:%v%v{%v}", requiredOrNot, key, value.Type, defaultValue, value.In)
			if len(enums) > 0 {
				arg += fmt.Sprintf("[%v]", enums)
			}

			argList = append(argList, arg)
		}

		args := strings.Join(argList, ";")

		compressedEndpoint := fmt.Sprintf("[%v] %v", methods, path)

		if len(args) > 0 {
			compressedEndpoint += fmt.Sprintf(" | %v", args)
		}

		compressedEndpoints = append(compressedEndpoints, compressedEndpoint)
	}

	result := strings.Join(compressedEndpoints, "\n")
	fmt.Println(result)
	return compressedEndpoints, nil
}
