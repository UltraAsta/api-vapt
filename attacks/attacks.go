package attacks

import (
	"apivapt/schema"
)

type Attack interface {
	Run(endpoint schema.Endpoint, baseURL string) []schema.Findings
}

type BOLA struct{}
type SSRF struct{}
type RateLimit struct{}
