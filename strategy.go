package main

import (
	p "apivapt/parsers"
	"apivapt/schema"
	"net/http"
)

type ParserContext struct {
	Parsers []p.Parser
}

func (c *ParserContext) Init() *ParserContext {
	c.Parsers = []p.Parser{
		&p.WordpressParser{},
		&p.OpenAPIParser{},
		&p.GraphQLParser{},
	}

	return c
}

func (c *ParserContext) Detect(header http.Header, body []byte) bool {
	for _, p := range c.Parsers {
		if p.Detect(header, body) {
			return true
		}
	}
	return false
}

func (c *ParserContext) Parse(data []byte) (*schema.APISchema, error) {
	for _, p := range c.Parsers {
		if p.HasRoutes(data) {
			return p.Parse(data)
		}
	}
	return nil, nil
}
