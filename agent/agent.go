package agent

import (
	"apivapt/attacks"
	"apivapt/schema"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

type Agent struct {
	Client  anthropic.Client
	BaseURL string
}

func New() Agent {
	client := anthropic.NewClient(
		option.WithAPIKey(os.Getenv("ANTHROPIC_API_KEY")),
		option.WithBaseURL(os.Getenv("ANTHROPIC_BASE_URL")),
	)
	return Agent{Client: client}
}

func (a *Agent) Scan(apiSchema *schema.APISchema, compressed []string) []schema.Findings {
	a.BaseURL = apiSchema.BaseURL

	tools := []anthropic.ToolUnionParam{
		{OfTool: &anthropic.ToolParam{
			Name:        "bola",
			Description: anthropic.String("Test an endpoint for Broken Object Level Authorization by enumerating object IDs"),
			InputSchema: anthropic.ToolInputSchemaParam{
				Properties: map[string]any{
					"path":    map[string]any{"type": "string", "description": "Endpoint path, e.g. /wp/v2/users/1"},
					"methods": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "HTTP methods to test"},
				},
			},
		}},
		{OfTool: &anthropic.ToolParam{
			Name:        "mass_assignment",
			Description: anthropic.String("Test an endpoint for Mass Assignment by injecting privileged/internal fields (is_admin, role, balance, etc.) into the request body and checking if they're accepted and reflected"),
			InputSchema: anthropic.ToolInputSchemaParam{
				Properties: map[string]any{
					"path":    map[string]any{"type": "string", "description": "Endpoint path, e.g. /api/users"},
					"methods": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "HTTP methods to test (only POST/PUT/PATCH are exercised)"},
					"args":    map[string]any{"type": "object", "description": "Documented args and their schema, e.g. {\"email\": {\"type\": \"string\", \"in\": \"body\"}}"},
				},
			},
		}},
		{OfTool: &anthropic.ToolParam{
			Name:        "excessive_data_exposure",
			Description: anthropic.String("Test an endpoint for Excessive Data Exposure by reading its JSON response and flagging sensitive fields (password, token, secret, ssn, etc.) the client should not receive"),
			InputSchema: anthropic.ToolInputSchemaParam{
				Properties: map[string]any{
					"path":    map[string]any{"type": "string", "description": "Endpoint path, e.g. /api/users/1"},
					"methods": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "HTTP methods to test (only GET is exercised)"},
				},
			},
		}},
		{OfTool: &anthropic.ToolParam{
			Name:        "bfla",
			Description: anthropic.String("Test a privileged/admin endpoint for Broken Function Level Authorization by calling it without credentials and checking whether it succeeds (2xx) instead of returning 401/403"),
			InputSchema: anthropic.ToolInputSchemaParam{
				Properties: map[string]any{
					"path":     map[string]any{"type": "string", "description": "Endpoint path, e.g. /api/admin/users"},
					"methods":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "HTTP methods to test"},
					"mutating": map[string]any{"type": "boolean", "description": "Set true ONLY with authorization to send destructive methods (PUT/PATCH/DELETE). Defaults to false (read-only probes)."},
				},
			},
		}},
		{OfTool: &anthropic.ToolParam{
			Name:        "report_finding",
			Description: anthropic.String("Report a confirmed security vulnerability"),
			InputSchema: anthropic.ToolInputSchemaParam{
				Properties: map[string]any{
					"endpoint": map[string]any{"type": "string"},
					"method":   map[string]any{"type": "string"},
					"attack":   map[string]any{"type": "string", "description": "e.g. BOLA, SQLi, Broken Auth"},
					"severity": map[string]any{"type": "string", "enum": []string{"critical", "high", "medium", "low", "info"}},
					"evidence": map[string]any{"type": "string"},
					"request":  map[string]any{"type": "string"},
					"response": map[string]any{"type": "string"},
				},
			},
		}},
		{OfTool: &anthropic.ToolParam{
			Name:        "ssrf",
			Description: anthropic.String("Test an endpoint for Server-Side Request Forgery by injecting internal URLs into URL-like parameters"),
			InputSchema: anthropic.ToolInputSchemaParam{
				Properties: map[string]any{
					"path":    map[string]any{"type": "string", "description": "Endpoint path, e.g. /api/fetch"},
					"methods": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "HTTP methods to test"},
					"args":    map[string]any{"type": "object", "description": "Query parameter names and their types, e.g. {\"url\": {\"type\": \"string\"}}"},
				},
			},
		}},
		{OfTool: &anthropic.ToolParam{
			Name:        "ratelimit",
			Description: anthropic.String("Test an endpoint for missing rate limiting by sending repeated requests and checking for 429 responses"),
			InputSchema: anthropic.ToolInputSchemaParam{
				Properties: map[string]any{
					"path":    map[string]any{"type": "string", "description": "Endpoint path, e.g. /api/login"},
					"methods": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "HTTP methods to test"},
				},
			},
		}},
	}

	systemPrompt := fmt.Sprintf(`You are a penetration tester. You are given a list of API endpoints from %s.
Your job is to test each endpoint for common vulnerabilities. Use the available attack tools on relevant endpoints and report_finding when you confirm a vulnerability.
Base URL: %s`, apiSchema.Type, apiSchema.BaseURL)

	userMessage := "Here are the API endpoints to test:\n\n" + strings.Join(compressed, "\n")

	messages := []anthropic.MessageParam{
		anthropic.NewUserMessage(anthropic.NewTextBlock(userMessage)),
	}

	var findings []schema.Findings

	for {
		resp, err := a.Client.Messages.New(context.Background(), anthropic.MessageNewParams{
			Model:     anthropic.ModelClaudeSonnet4_6,
			MaxTokens: 4096,
			System:    []anthropic.TextBlockParam{{Text: systemPrompt}},
			Tools:     tools,
			Messages:  messages,
		})
		if err != nil {
			log.Fatalf("Agent error: %v", err)
		}

		messages = append(messages, resp.ToParam())

		if len(resp.Content) > 0 {
			fmt.Println(resp.Content[0].Text)
		}

		if resp.StopReason != anthropic.StopReasonToolUse {
			break
		}

		var results []anthropic.ContentBlockParamUnion
		for _, block := range resp.Content {
			tool, ok := block.AsAny().(anthropic.ToolUseBlock)
			if !ok {
				continue
			}

			var result string

			switch tool.Name {
			case "bola":
				var input struct {
					Path    string   `json:"path"`
					Methods []string `json:"methods"`
				}
				json.Unmarshal([]byte(tool.JSON.Input.Raw()), &input)
				found := (&attacks.BOLA{}).Run(schema.Endpoint{Path: input.Path, Methods: input.Methods}, a.BaseURL)
				findings = append(findings, found...)
				result = fmt.Sprintf("%d findings", len(found))

			case "mass_assignment":
				var input struct {
					Path    string                `json:"path"`
					Methods []string              `json:"methods"`
					Args    map[string]schema.Arg `json:"args"`
				}
				json.Unmarshal([]byte(tool.JSON.Input.Raw()), &input)
				found := (&attacks.MassAssignment{}).Run(schema.Endpoint{Path: input.Path, Methods: input.Methods, Args: input.Args}, a.BaseURL)
				findings = append(findings, found...)
				result = fmt.Sprintf("%d findings", len(found))

			case "excessive_data_exposure":
				var input struct {
					Path    string   `json:"path"`
					Methods []string `json:"methods"`
				}
				json.Unmarshal([]byte(tool.JSON.Input.Raw()), &input)
				found := (&attacks.ExcessiveDataExposure{}).Run(schema.Endpoint{Path: input.Path, Methods: input.Methods}, a.BaseURL)
				findings = append(findings, found...)
				result = fmt.Sprintf("%d findings", len(found))

			case "bfla":
				var input struct {
					Path     string   `json:"path"`
					Methods  []string `json:"methods"`
					Mutating bool     `json:"mutating"`
				}
				json.Unmarshal([]byte(tool.JSON.Input.Raw()), &input)
				found := (&attacks.BFLA{Mutating: input.Mutating}).Run(schema.Endpoint{Path: input.Path, Methods: input.Methods}, a.BaseURL)
				findings = append(findings, found...)
				result = fmt.Sprintf("%d findings", len(found))

			case "ssrf":
				var input struct {
					Path    string                 `json:"path"`
					Methods []string               `json:"methods"`
					Args    map[string]schema.Arg  `json:"args"`
				}
				json.Unmarshal([]byte(tool.JSON.Input.Raw()), &input)
				found := (&attacks.SSRF{}).Run(schema.Endpoint{Path: input.Path, Methods: input.Methods, Args: input.Args}, a.BaseURL)
				findings = append(findings, found...)
				result = fmt.Sprintf("%d findings", len(found))

			case "ratelimit":
				var input struct {
					Path    string   `json:"path"`
					Methods []string `json:"methods"`
				}
				json.Unmarshal([]byte(tool.JSON.Input.Raw()), &input)
				found := (&attacks.RateLimit{}).Run(schema.Endpoint{Path: input.Path, Methods: input.Methods}, a.BaseURL)
				findings = append(findings, found...)
				result = fmt.Sprintf("%d findings", len(found))

			case "report_finding":
				var input schema.Findings
				json.Unmarshal([]byte(tool.JSON.Input.Raw()), &input)
				findings = append(findings, input)
				result = "finding recorded"
			}

			fmt.Println(result)
			results = append(results, anthropic.NewToolResultBlock(tool.ID, result, false))
		}

		messages = append(messages, anthropic.NewUserMessage(results...))
	}

	return findings
}
