import re
import json

import httpx

from schema.schema import APISchema, Endpoint, Arg
from .base import BaseParser


WORDPRESS_PATHS = [
    "/wp-json",
    "/index.php?rest_route=/",
    "/?rest_route=/",
    "/wp/wp-json",
    "/wp/index.php?rest_route=/",
]

SKIP_NAMESPACES = {
    "wordfence/v1", "fluent-smtp", "fluentform/v1", "two-factor",
}


class WordpressParser(BaseParser):
    def Detect(self, base_url: str, header: httpx.Headers, body: str) -> tuple[bool, str]:
        link = header.get("Link", "")
        if "api.w.org" in link:
            match = re.search(r"<([^>]+)>", link)
            if match:
                return True, match.group(1)

        wp_paths = ["wp-login.php", "wp-json", "wp-content", "wp-admin", "wp-includes"]
        for path in wp_paths:
            if path in body:
                return True, self._probeDocURL(base_url)

        return False, ""

    def _probeDocURL(self, base_url: str) -> str:
        for path in WORDPRESS_PATHS:
            url = base_url + path
            try:
                resp = httpx.get(url)
                if self.HasRoutes(resp.text):
                    return url
            except Exception:
                continue
        return ""

    def HasRoutes(self, data: str) -> bool:
        try:
            probe = json.loads(data)
            return "routes" in probe
        except Exception:
            return False

    def Parse(self, data: str) -> APISchema:
        raw = json.loads(data)

        schema = APISchema(
            type="wordpress",
            base_url=raw.get("url", ""),
        )

        for path, route in raw.get("routes", {}).items():
            namespace = route.get("namespace", "")
            if namespace in SKIP_NAMESPACES:
                continue
            if "(?P<" in path:
                continue

            endpoint = Endpoint(
                path=path,
                methods=route.get("methods", []),
                args={},
            )

            for ep in route.get("endpoints", []):
                args_raw = ep.get("args", {})
                if not isinstance(args_raw, dict):
                    continue
                for name, arg in args_raw.items():
                    if not isinstance(arg, dict):
                        continue
                    endpoint.args[name] = Arg(
                        type=arg.get("type", ""),
                        required=arg.get("required", False),
                        enum=arg.get("enum", []),
                        default=arg.get("default", None),
                        in_="body",
                    )

            schema.endpoints.append(endpoint)

        return schema
