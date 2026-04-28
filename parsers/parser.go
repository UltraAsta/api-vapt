package parsers

import (
	s "apivapt/schema"
	"net/http"
)

type Parser interface {
	Parse(data []byte) (*s.APISchema, error)
	Detect(baseURL string, header http.Header, body []byte) (bool, string)
	HasRoutes(data []byte) bool
}

type WordpressParser struct{}
type OpenAPIParser struct{}
type GraphQLParser struct{}
