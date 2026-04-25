package main

import (
	p "apivapt/parsers"
	"fmt"
	"io"
	"log"
	"net/http"
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

	wp := p.WordpressParser{}
	detected := wp.HasRoutes(body)
	if detected {
		schema, err := wp.Parse(body)
		if err != nil {
			log.Fatalf("Something went wrong parsing wordpress body: %v", err)
		}

		wp.Compress(schema)

		// file, err := os.Create("output.json")
		// if err != nil {
		// 	log.Fatalf("Something went wrong creating output file: %v", err)
		// }

		// defer file.Close()

		// json.NewEncoder(file).Encode(&schema)
	}
}
