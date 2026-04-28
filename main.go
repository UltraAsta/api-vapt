package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
)

func main() {
	baseUrl := "https://reboot01.com/"

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

		file, err := os.Create("output.txt")
		if err != nil {
			log.Fatalf("Something went wrong creating output file: %v", err)
		}

		defer file.Close()

		json.NewEncoder(file).Encode(&compressed)
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
