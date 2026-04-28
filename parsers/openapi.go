package parsers

import (
	s "apivapt/schema"
	"net/http"
)

func (o *OpenAPIParser) Detect(header http.Header, body []byte) bool {
	return false
}

func (o *OpenAPIParser) HasRoutes(data []byte) bool {
	return false
}

func (o *OpenAPIParser) Parse(data []byte) (*s.APISchema, error) {
	return nil, nil
}
