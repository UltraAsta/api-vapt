package schema

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
