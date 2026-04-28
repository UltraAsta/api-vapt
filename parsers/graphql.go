package parsers

import (
	s "apivapt/schema"
	"net/http"
)

func (g *GraphQLParser) Detect(header http.Header, body []byte) bool {
	return false
}

func (g *GraphQLParser) HasRoutes(data []byte) bool {
	return false
}

func (g *GraphQLParser) Parse(data []byte) (*s.APISchema, error) {
	return nil, nil
}
