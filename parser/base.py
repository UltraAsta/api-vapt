from abc import ABC, abstractmethod

import httpx

from schema.schema import APISchema


class BaseParser(ABC):
    @abstractmethod
    def Detect(self, base_url: str, header: httpx.Headers, body: str) -> tuple[bool, str]:
        pass

    @abstractmethod
    def HasRoutes(self, data: str) -> bool:
        pass

    @abstractmethod
    def Parse(self, data: str) -> APISchema:
        pass
