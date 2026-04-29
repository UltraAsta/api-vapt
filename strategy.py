from typing import Optional

import httpx

from parser.parser import Parser
from parser.wordpress import WordpressParser
from parser.openapi import OpenAPIParser
from parser.graphql import GraphQLParser


class ParserContext:
    def __init__(self):
        self.parsers: list[Parser] = [
            WordpressParser(),
            OpenAPIParser(),
            GraphQLParser(),
        ]

    def Detect(self, base_url: str, header: httpx.Headers, body: str) -> tuple[Optional[Parser], str]:
        for parser in self.parsers:
            ok, doc_url = parser.Detect(base_url, header, body)
            if ok:
                return parser, doc_url
        return None, ""
