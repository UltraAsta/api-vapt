import json
import os

import httpx
import anthropic

from schema.schema import APISchema, Findings


def _runHTTPRequest(input_data: dict) -> str:
    method = input_data.get("method", "GET")
    url = input_data.get("url", "")
    headers = input_data.get("headers", {})
    body = input_data.get("body", "")

    try:
        resp = httpx.request(
            method, url, headers=headers, content=body.encode() if body else None
        )
        return f"Status: {resp.status_code}\nBody: {resp.text[:2000]}"
    except Exception as e:
        return f"request failed: {e}"


class Agent:
    def __init__(self):
        self.client = anthropic.Anthropic()

    def Scan(self, api_schema: APISchema, compressed: list[str]) -> list[Findings]:
        tools = [
            {
                "name": "http_request",
                "description": "Make an HTTP request to test an API endpoint for vulnerabilities",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "method": {"type": "string", "description": "HTTP method"},
                        "url": {"type": "string", "description": "Full URL to request"},
                        "headers": {
                            "type": "object",
                            "description": "Optional request headers",
                        },
                        "body": {
                            "type": "string",
                            "description": "Optional request body",
                        },
                    },
                },
            },
            {
                "name": "report_finding",
                "description": "Report a confirmed security vulnerability",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "endpoint": {"type": "string"},
                        "method": {"type": "string"},
                        "attack": {
                            "type": "string",
                            "description": "e.g. BOLA, SQLi, Broken Auth",
                        },
                        "severity": {
                            "type": "string",
                            "enum": ["critical", "high", "medium", "low", "info"],
                        },
                        "evidence": {"type": "string"},
                        "request": {"type": "string"},
                        "response": {"type": "string"},
                    },
                },
            },
        ]

        system_prompt = (
            f"You are a penetration tester. You are given a list of API endpoints from {api_schema.type}.\n"
            f"Your job is to test each endpoint for common vulnerabilities. Use http_request to probe endpoints "
            f"and report_finding when you confirm a vulnerability.\n"
            f"Base URL: {api_schema.base_url}"
        )

        user_message = "Here are the API endpoints to test:\n\n" + "\n".join(compressed)

        messages = [{"role": "user", "content": user_message}]
        findings: list[Findings] = []

        while True:
            resp = self.client.messages.create(
                model="deepseek-v4-flash",
                max_tokens=4096,
                system=system_prompt,
                tools=tools,
                messages=messages,
            )

            print(resp.content[0])

            messages.append({"role": "assistant", "content": resp.content})  # type: ignore

            for block in resp.content:
                if hasattr(block, "text"):
                    print(block.text)

            if resp.stop_reason != "tool_use":
                break

            results = []
            for block in resp.content:
                if block.type != "tool_use":
                    continue

                result = ""
                if block.name == "http_request":
                    result = _runHTTPRequest(block.input)
                elif block.name == "report_finding":
                    findings.append(
                        Findings(
                            endpoint=block.input.get("endpoint", ""),
                            method=block.input.get("method", ""),
                            attack=block.input.get("attack", ""),
                            severity=block.input.get("severity", ""),
                            evidence=block.input.get("evidence", ""),
                            request=block.input.get("request", ""),
                            response=block.input.get("response", ""),
                        )
                    )
                    result = "finding recorded"

                print(result)
                results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result,
                    }
                )

            messages.append({"role": "user", "content": results})

        return findings


def New() -> Agent:
    return Agent()
