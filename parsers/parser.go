package parsers

import (
	s "apivapt/schema"
)

type Parser interface {
	Parse(data []byte) (*s.APISchema, error)
	Detect(data []byte) bool
}

type WordpressParser struct{}
type OpenAPIParser struct{}
type GraphQLParser struct{}
