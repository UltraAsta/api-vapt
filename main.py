import sys
from dotenv import load_dotenv
import httpx

from parser.parser import Parser
from agent.agent import New

load_dotenv()


def main():
    base_url = "http://localhost:31337"

    header, body = ReadURLContent(base_url)

    ctx = Parser()
    parser, doc_url = ctx.Detect(base_url, header, body)

    if parser is not None and doc_url:
        header, body = ReadURLContent(doc_url)

        schema = parser.Parse(body)
        compressed = schema.Compress()

        print(compressed)

        a = New()
        findings = a.Scan(schema, compressed)
        for f in findings:
            print(f"[{f.severity}] {f.method} {f.endpoint} — {f.attack}")


def ReadURLContent(url: str) -> tuple[httpx.Headers, str]:
    resp = httpx.get(url)
    if resp.is_error:
        print(f"Error sending a get request to the target: {resp.text}")
        sys.exit(1)
    return resp.headers, resp.text


main()
