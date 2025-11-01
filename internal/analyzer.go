package internal

import (
	"crypto/tls"
	"net/http"
	"strings"
	"time"
)

type SecurityHeader struct {
	Name        string   `json:"name"`
	Present     bool     `json:"present"`
	Description string   `json:"description"`
	Weight      int      `json:"weight"`
	Aliases     []string `json:"aliases,omitempty"`
}

type AnalysisResult struct {
	Headers map[string]bool     `json:"headers"`
	Score   int                 `json:"score"`
	Grade   string              `json:"grade"`
	Summary []SecurityHeader    `json:"summary"`
	URL     string              `json:"url"`
}

// SecurityHeaderTier represents the importance tier of security headers
type SecurityHeaderTier int

const (
	Critical SecurityHeaderTier = iota // Must have for good security
	Important                          // Should have for good security  
	Recommended                        // Nice to have for excellent security
)

var securityHeaders = []SecurityHeader{
	// Critical headers (40% of total score)
	{
		Name:        "Strict-Transport-Security",
		Description: "Forces HTTPS connections to protect against man-in-the-middle attacks.",
		Weight:      20, // Most important for transport security
	},
	{
		Name:        "X-Content-Type-Options",
		Description: "Prevents MIME-sniffing attacks by enforcing declared content types.",
		Weight:      15, // Critical for preventing content-type confusion
	},
	{
		Name:        "X-Frame-Options",
		Description: "Protects against clickjacking by controlling iframe embedding.",
		Weight:      15, // Critical for preventing clickjacking
	},
	
	// Important headers (35% of total score)
	{
		Name:        "Content-Security-Policy",
		Description: "Helps prevent XSS attacks by defining allowed content sources.",
		Weight:      20, // Very important but complex to implement correctly
		Aliases:     []string{"Content-Security-Policy-Report-Only"},
	},
	{
		Name:        "Referrer-Policy",
		Description: "Controls how much referrer information is shared with requests.",
		Weight:      15, // Important for privacy
	},
	
	// Recommended headers (25% of total score)
	{
		Name:        "Permissions-Policy",
		Description: "Controls which browser features and APIs can be used.",
		Weight:      10, // Modern security feature
		Aliases:     []string{"Feature-Policy"},
	},
	{
		Name:        "Cross-Origin-Opener-Policy",
		Description: "Prevents cross-origin attacks by isolating browsing context.",
		Weight:      8, // Newer security feature
	},
	{
		Name:        "Cross-Origin-Resource-Policy",
		Description: "Protects resources from being loaded by other origins.",
		Weight:      7, // Newer security feature
	},
}

// isHeaderPresent checks if a security header is present in the response
// It checks both the main header name and any aliases
func isHeaderPresent(resp *http.Response, header SecurityHeader) bool {
	// Check main header name (case-insensitive)
	if resp.Header.Get(header.Name) != "" {
		return true
	}
	
	// Check aliases
	for _, alias := range header.Aliases {
		if resp.Header.Get(alias) != "" {
			return true
		}
	}
	
	return false
}

func AnalyzeURL(url string) (*AnalysisResult, error) {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	result := &AnalysisResult{
		Headers: make(map[string]bool),
		Summary: make([]SecurityHeader, 0),
		URL:     url,
	}

	totalWeight := 0
	achievedWeight := 0

	for _, header := range securityHeaders {
		present := isHeaderPresent(resp, header)
		result.Headers[header.Name] = present

		summaryItem := SecurityHeader{
			Name:        header.Name,
			Present:     present,
			Description: header.Description,
			Weight:      header.Weight,
			Aliases:     header.Aliases,
		}
		result.Summary = append(result.Summary, summaryItem)

		totalWeight += header.Weight
		if present {
			achievedWeight += header.Weight
		}
	}

	// Calculate base score from security headers (70% of total)
	headerScore := 0
	if totalWeight > 0 {
		headerScore = (achievedWeight * 70) / totalWeight
	}

	// HTTPS is fundamental (30 points base)
	httpsScore := 0
	if strings.HasPrefix(url, "https://") {
		httpsScore = 30
	}

	// Combine base scores
	result.Score = headerScore + httpsScore

	// Apply tiered bonuses for security coverage
	criticalCount := countCriticalHeaders(result.Summary)
	importantCount := countImportantHeaders(result.Summary) 
	
	// Bonus for having critical headers (up to 10 points)
	if criticalCount > 0 {
		criticalBonus := (criticalCount * 10) / 3 // Up to 10 points for all 3 critical headers
		if criticalBonus > 10 {
			criticalBonus = 10
		}
		result.Score += criticalBonus
	}
	
	// Bonus for having important headers (up to 5 points)
	if importantCount > 0 {
		importantBonus := (importantCount * 5) / 2 // Up to 5 points for both important headers
		if importantBonus > 5 {
			importantBonus = 5
		}
		result.Score += importantBonus
	}

	// Cap at 100
	if result.Score > 100 {
		result.Score = 100
	}

	result.Grade = calculateGrade(result.Score)

	return result, nil
}

// hasAnyCriticalHeader checks if the site has at least one critical security header
func hasAnyCriticalHeader(summary []SecurityHeader) bool {
	criticalHeaders := []string{"Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options"}
	
	for _, header := range summary {
		for _, critical := range criticalHeaders {
			if header.Name == critical && header.Present {
				return true
			}
		}
	}
	return false
}

// countCriticalHeaders counts how many critical headers are present
func countCriticalHeaders(summary []SecurityHeader) int {
	criticalHeaders := []string{"Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options"}
	count := 0
	
	for _, header := range summary {
		for _, critical := range criticalHeaders {
			if header.Name == critical && header.Present {
				count++
				break
			}
		}
	}
	return count
}

// countImportantHeaders counts how many important headers are present
func countImportantHeaders(summary []SecurityHeader) int {
	importantHeaders := []string{"Content-Security-Policy", "Referrer-Policy"}
	count := 0
	
	for _, header := range summary {
		for _, important := range importantHeaders {
			if header.Name == important && header.Present {
				count++
				break
			}
		}
	}
	return count
}

func calculateGrade(score int) string {
	switch {
	case score >= 80:
		return "A"
	case score >= 65:
		return "B"
	case score >= 45:
		return "C"
	case score >= 25:
		return "D"
	default:
		return "F"
	}
}
