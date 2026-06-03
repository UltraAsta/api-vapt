// TODO: implement brute-force discovery using fuff-like approach
package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
)

func Discovery(baseUrl string, fileName string) {
	pathsFound := readFile(fileName)
	fmt.Println(pathsFound)
}

// reading a file with the common terms for endpoints and will be collected into an array
func readFile(fileName string) []string {
	exists, localPath := checkIfFileExists(fileName)
	if !exists {
		log.Fatalf("Error Reading File %s", fileName)
	}

	// os.Open instead of os.ReadFile is cuz open has more control over larger files
	file, err := os.Open(localPath)
	if err != nil {
		log.Fatalf("Something went wrong reading file: %v", err)
	}

	defer file.Close()

	var paths []string

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		path := scanner.Text()
		paths = append(paths, path)
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading file: %v", err)
	}

	return paths
}
