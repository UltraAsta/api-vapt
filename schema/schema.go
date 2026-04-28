package schema

import (
	"fmt"
	"strings"
)

type APISchema struct {
	Type      string     `json:"type"` // "openapi", "wordpress", "graphql"
	BaseURL   string     `json:"base_url"`
	Endpoints []Endpoint `json:"endpoints"`
}

type Endpoint struct {
	Path        string            `json:"path"`
	Methods     []string          `json:"methods"`
	Description string            `json:"desciption,omitempty"`
	Args        map[string]Arg    `json:"args,omitempty"`
	Responses   map[string]string `json:"responses,omitempty"`
}

type Arg struct {
	Type     string   `json:"type,omitempty"`
	Required bool     `json:"required,omitempty"`
	In       string   `json:"in,omitempty"` // "query", "body", "path", "header"
	Enum     []string `json:"enum,omitempty"`
	Default  any      `json:"default,omitempty"`
}

func (s *APISchema) Compress() ([]string, error) {
	var compressedEndpoints []string

	for _, endpoint := range s.Endpoints {
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
