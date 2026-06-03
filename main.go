package main

import (
	"apivapt/agent"
	"os"
	"path/filepath"

	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/joho/godotenv"
	flag "github.com/spf13/pflag"
)

const seclistsBase = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/"

var wordlists = map[string]string{
	"common":    "common.txt",
	"quickhits": "quickhits.txt",
	"api":       "api/api-endpoints.txt",
}

func checkIfFileExists(file string) (bool, string) {
	localPath := filepath.Join("wordlists", file)
	if _, err := os.Stat(localPath); err == nil {
		return true, localPath
	}

	return false, localPath
}

func wordListDownload(fileTypeArg *string) {

	fileType, ok := wordlists[*fileTypeArg]
	if !ok {
		log.Fatalf("Invalid argument value")
	}

	exists, localPath := checkIfFileExists(fileType)
	if !exists {
		log.Fatalf("file %s already exists", fileType)

	}

	if err := os.MkdirAll(filepath.Dir(localPath), 0o755); err != nil {
		log.Fatalf("Error creating wordlist dir: %v", err)
	}

	resp, err := http.Get(seclistsBase + fileType)
	if err != nil {
		log.Fatalf("Error getting wordlist: %v", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("status %d", resp.StatusCode)
	}

	f, err := os.Create(localPath)
	if err != nil {
		log.Fatalf("Error in file creation: %v", err)
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)

	if err != nil {
		log.Fatalf("Error in copying file content: %v", err)
	}
}

func main() {
	// setup
	godotenv.Load()

	fileTypeArg := flag.StringP("type", "t", "common", "choosing the type of file to install. options include 'common' & 'api'")

	flag.Parse()

	wordListDownload(fileTypeArg)

	baseUrl := "http://localhost:8888"

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

	// none of the parsers succeeded in finding the type, go with bruteforce
	Discovery(baseUrl, "api/api-endpoints.txt")
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
