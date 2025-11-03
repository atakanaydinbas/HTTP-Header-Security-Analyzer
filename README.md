# HTTP Header Security Analyzer

A lightweight REST API built with Go and Fiber that analyzes a website’s HTTP security response headers. It checks the presence of key headers, computes a weighted score (0–100), and returns a letter grade (A–F) with a human‑readable summary.

## Features

- Analyze a target URL’s response headers with a single POST call
- Weighted scoring for critical/important/recommended headers
- HTTPS usage bonus and tiered coverage bonuses
- Health endpoint for readiness checks

## Endpoints

### GET /health

- Response: `{"status":"ok"}`

### POST /analyze

- Request body (JSON):

```json
{
  "url": "https://example.com"
}
```

- Notes:
  - `url` may be provided without a scheme; `https://` will be prefixed automatically if missing.

- Success response (example):

```json
{
  "headers": {
    "Strict-Transport-Security": true,
    "X-Content-Type-Options": true,
    "X-Frame-Options": false,
    "Content-Security-Policy": false,
    "Referrer-Policy": true,
    "Permissions-Policy": false,
    "Cross-Origin-Opener-Policy": false,
    "Cross-Origin-Resource-Policy": false
  },
  "score": 72,
  "grade": "B",
  "summary": [
    {
      "name": "Strict-Transport-Security",
      "present": true,
      "description": "Forces HTTPS connections to protect against man-in-the-middle attacks.",
      "weight": 20
    }
  ],
  "url": "https://example.com"
}
```

- Error responses:
  - 400: `{"error":"Invalid request body"}` or `{"error":"URL is required"}`
  - 500: `{"error":"Failed to analyze URL: <details>"}`

## Scoring Model

- Header weights contribute 70% of the total score.
- HTTPS usage contributes a base of +30 points.
- Tiered bonuses:
  - Critical headers: up to +10 points total
  - Important headers: up to +5 points total
- Score is capped at 100.

Letter grades:

- A: ≥ 80
- B: ≥ 65
- C: ≥ 45
- D: ≥ 25
- F: < 25

## Headers Checked

- Critical
  - `Strict-Transport-Security` — forces HTTPS
  - `X-Content-Type-Options` — prevents MIME sniffing
  - `X-Frame-Options` — mitigates clickjacking

- Important
  - `Content-Security-Policy` (aliases: `Content-Security-Policy-Report-Only`) — mitigates XSS by restricting sources
  - `Referrer-Policy` — controls referrer information sharing

- Recommended
  - `Permissions-Policy` (aliases: `Feature-Policy`) — restricts browser features/APIs
  - `Cross-Origin-Opener-Policy` — isolates browsing context
  - `Cross-Origin-Resource-Policy` — restricts cross-origin resource loading

## Getting Started

### Prerequisites

- Go toolchain (see `go.mod` for version; recent Go is recommended)

### Install dependencies

```bash
go mod tidy
```

### Run in development

```bash
go run .
```

- The server listens on `PORT` if set, otherwise `8080`.

Examples:

```bash
curl http://localhost:8080/health

curl -X POST http://localhost:8080/analyze \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

### Build

```bash
go build -o header-analyzer
```

Run the binary:

```bash
./header-analyzer   # Linux/macOS
header-analyzer.exe # Windows
```

## Configuration

- `PORT`: HTTP port (default: `8080`).
- CORS is enabled for all origins by default (`*`).

## Security Notes

- The HTTP client uses `InsecureSkipVerify: true` to avoid TLS verification failures during analysis. This is convenient for scanning but should be used cautiously in production contexts.
- CORS allows all origins. Consider restricting allowed origins/methods/headers if exposing this service publicly.

## Project Structure

- `main.go` — HTTP server, routes (`/analyze`, `/health`), error handling, CORS
- `internal/analyzer.go` — header checks, scoring and grading logic
- `go.mod`, `go.sum` — dependencies
- `LICENSE` — license information

## License

See `LICENSE` for details.

