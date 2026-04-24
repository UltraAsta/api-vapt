package main

import (
	p "apivapt/parsers"
	"fmt"
	"io"
	"log"
	"net/http"
)

func main() {
	url := "https://reboot01.com/wp-json/"
	resp, err := http.Get(url)
	if err != nil {
		log.Fatalf("Error sending a get request to the target: %v", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error reading the response body: %v", err)
	}

	wp := p.WordpressParser{}
	detected := wp.Detect(body)
	if detected {
		schema, err := wp.Parse(body)
		if err != nil {
			log.Fatalf("Something went wrong parsing wordpress body: %v", err)
		}

		fmt.Printf("%v", schema)
	}
}
