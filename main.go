package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

func main() {
	url := "http://localhost:31337/"
	resp, err := http.Get(url)
	if err != nil {
		log.Fatalf("Error sending a get request to the target: %v", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	fmt.Println(string(body))
	if err != nil {
		log.Fatalf("Error reading the response body: %v", err)
	}

	ctx := ParserContext{}
	detected := ctx.Detect(resp.Header, body)
	if detected {
		schema, err := ctx.Parse(body)
		if err != nil {
			log.Fatalf("Something went wrong parsing wordpress body: %v", err)
		}

		compressed, _ := schema.Compress()

		file, err := os.Create("output.json")
		if err != nil {
			log.Fatalf("Something went wrong creating output file: %v", err)
		}

		defer file.Close()

		json.NewEncoder(file).Encode(&compressed)
	}
}
