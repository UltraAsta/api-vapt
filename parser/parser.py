import httpx

from .base import BaseParser
from .wordpress import WordpressParser
from .openapi import OpenAPIParser
from .graphql import GraphQLParser


class Parser:
    parsers: list[BaseParser] = [WordpressParser(), OpenAPIParser(), GraphQLParser()]

    def Detect(
        self, base_url: str, header: httpx.Headers, body: str
    ) -> tuple[BaseParser | None, str]:
        for p in self.parsers:
            ok, doc_url = p.Detect(base_url, header, body)
            if ok:
                return p, doc_url
        return None, ""
