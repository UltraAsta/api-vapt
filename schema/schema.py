from dataclasses import dataclass, field
from typing import Any


@dataclass
class Arg:
    type: str = ""
    required: bool = False
    in_: str = ""  # "query", "body", "path", "header"
    enum: list[str] = field(default_factory=list)
    default: Any = None


@dataclass
class Endpoint:
    path: str = ""
    methods: list[str] = field(default_factory=list)
    description: str = ""
    args: dict[str, Arg] = field(default_factory=dict)
    responses: dict[str, str] = field(default_factory=dict)


@dataclass
class APISchema:
    type: str = ""  # "openapi", "wordpress", "graphql"
    base_url: str = ""
    endpoints: list[Endpoint] = field(default_factory=list)

    def Compress(self) -> list[str]:
        compressed_endpoints = []

        for endpoint in self.endpoints:
            methods = ",".join(endpoint.methods)
            path = endpoint.path

            arg_list = []
            for key, value in endpoint.args.items():
                enums = "|".join(value.enum)
                required_or_not = "*" if value.required else ""
                default_value = f"={value.default}" if value.default is not None else ""

                arg = f"{required_or_not}{key}:{value.type}{default_value}{{{value.in_}}}"
                if enums:
                    arg += f"[{enums}]"

                arg_list.append(arg)

            args = ";".join(arg_list)

            compressed_endpoint = f"[{methods}] {path}"
            if args:
                compressed_endpoint += f" | {args}"

            compressed_endpoints.append(compressed_endpoint)

        return compressed_endpoints


@dataclass
class Findings:
    endpoint: str = ""
    method: str = ""
    attack: str = ""
    severity: str = ""
    evidence: str = ""
    request: str = ""
    response: str = ""
