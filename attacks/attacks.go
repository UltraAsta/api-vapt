package attacks

import (
	"apivapt/schema"
)

type Attack interface {
	Run(endpoint schema.Endpoint, baseURL string) []schema.Findings
}

// Attack types are organized around the OWASP API Security Top 10 (2023),
// plus the classic injection/transport classes that apply to most APIs.
// Each type's Run implementation lives in its own file (e.g. bola.go).

// --- Authorization ---

// API1:2023 — Broken Object Level Authorization.
// Enumerate object IDs to access records belonging to other users.
type BOLA struct{} // implemented: bola.go

// API3:2023 — Broken Object Property Level Authorization.
// Send extra/internal fields in the body to see if they're persisted.
type MassAssignment struct{}

// API3:2023 — Excessive Data Exposure.
// Inspect responses for sensitive fields the client shouldn't receive.
type ExcessiveDataExposure struct{}

// API5:2023 — Broken Function Level Authorization.
// Reach privileged/admin functions as a lower-privilege (or no) role.
// Mutating gates whether destructive methods (PUT/PATCH/DELETE) are sent;
// it defaults to false (read-only) via the zero value.
type BFLA struct{ Mutating bool }

// --- Authentication ---

// API2:2023 — Broken Authentication.
// Hit protected endpoints with missing/blank/malformed credentials.
type BrokenAuth struct{}

// API2:2023 — JWT weaknesses: alg:none, weak secret, no signature check,
// expired-token acceptance, kid injection.
type JWTAttack struct{}

// --- Resource consumption ---

// API4:2023 — Unrestricted Resource Consumption (missing rate limiting).
type RateLimit struct{} // implemented: ratelimit.go

// API4:2023 — Unbounded pagination / large-payload amplification.
type ResourceExhaustion struct{}

// --- Injection ---

// SQL injection via query params, body, and path segments.
type SQLi struct{}

// NoSQL injection (Mongo-style operators, JSON body manipulation).
type NoSQLi struct{}

// OS command injection through shell-reachable parameters.
type CommandInjection struct{}

// Reflected cross-site scripting in JSON/HTML responses.
type XSS struct{}

// Path / directory traversal (../) into file-serving parameters.
type PathTraversal struct{}

// --- Server-side requests ---

// API7:2023 — Server-Side Request Forgery.
type SSRF struct{} // implemented: ssrf.go

// --- Misconfiguration & inventory ---

// API8:2023 — Security Misconfiguration: permissive CORS, missing security
// headers, verbose errors/stack traces, debug endpoints.
type SecurityMisconfig struct{}

// API8:2023 — HTTP verb tampering / method-based auth bypass.
type HTTPMethodTampering struct{}

// API9:2023 — Improper Inventory Management: undocumented, deprecated, or
// non-production (/v1, /old, /debug) endpoints reachable.
type ImproperInventory struct{}

// API6:2023 — Unrestricted access to sensitive business flows
// (e.g. replaying a purchase/signup flow without throttling).
type BusinessFlowAbuse struct{}
