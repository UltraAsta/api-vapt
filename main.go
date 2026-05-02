package main

import (
	"apivapt/agent"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/joho/godotenv"
)

func main() {
	// setup
	godotenv.Load()

	baseUrl := "http://localhost:31337/"

	header, body := ReadURLContent(baseUrl)

	ctx := (&ParserContext{}).Init()

	parser, docURL := ctx.Detect(baseUrl, header, body)
	if parser != nil && docURL != "" {

		header, body = ReadURLContent(docURL)

		schema, err := parser.Parse(body)
		if err != nil {
			log.Fatalf("Something went wrong parsing wordpress body: %v", err)
		}

		compressed, _ := schema.Compress()

		fmt.Println(compressed)

		a := agent.New()
		findings := a.Scan(schema, compressed)
		for _, f := range findings {
			fmt.Printf("[%s] %s %s — %s\n", f.Severity, f.Method, f.Endpoint, f.Attack)
		}
	}
}

func ReadURLContent(url string) (http.Header, []byte) {
	resp, err := http.Get(url)
	if err != nil {
		log.Fatalf("Error sending a get request to the target: %v", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error reading the response body: %v", err)
	}

	return resp.Header, body
}
