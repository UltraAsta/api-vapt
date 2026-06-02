package main

import (
	p "apivapt/parsers"
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

func (c *ParserContext) Detect(baseURL string, header http.Header, body []byte) (p.Parser, string) {
	for _, parser := range c.Parsers {
		if ok, docURL := parser.Detect(baseURL, header, body); ok {
			return parser, docURL
		}
	}
	return nil, ""
}
