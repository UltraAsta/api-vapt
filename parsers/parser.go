package parsers

import (
	s "apivapt/schema"
	"net/http"
)

type Parser interface {
	Parse(data []byte) (*s.APISchema, error)
	Detect(header http.Header, body []byte) bool
	// Compress(schema *s.APISchema) ([]string, error)
	HasRoutes(data []byte) bool
}

type WordpressParser struct{}
type OpenAPIParser struct{}
type GraphQLParser struct{}
