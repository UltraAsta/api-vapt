import httpx

from schema.schema import APISchema
from .base import BaseParser


class OpenAPIParser(BaseParser):
    def Detect(self, base_url: str, header: httpx.Headers, body: str) -> tuple[bool, str]:
        return False, ""

    def HasRoutes(self, data: str) -> bool:
        return False

    def Parse(self, data: str) -> APISchema:
        return APISchema()
