package main

import (
	"log"
	"os"

	"github.com/atakanaydinbas/HTTP-Header-Security-Analyzer/internal"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
)

type AnalyzeRequest struct {
	URL string `json:"url"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

func analyzeHandler(c *fiber.Ctx) error {
	var req AnalyzeRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "Invalid request body",
		})
	}

	if req.URL == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "URL is required",
		})
	}

	result, err := internal.AnalyzeURL(req.URL)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "Failed to analyze URL: " + err.Error(),
		})
	}

	return c.JSON(result)
}

func healthHandler(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"status": "ok",
	})
}





func main() {
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(ErrorResponse{
				Error: err.Error(),
			})
		},
	})

	// CORS middleware
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowMethods: "GET,POST,OPTIONS",
		AllowHeaders: "Content-Type",
	}))

	// Routes
	app.Post("/analyze", analyzeHandler)
	app.Get("/health", healthHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server starting on port %s", port)
	if err := app.Listen(":" + port); err != nil {
		log.Fatal(err)
	}
}
