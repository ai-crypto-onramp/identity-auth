package main

import (
	"context"
	"log"
	"net/http"
	"os"
)

func main() {
	shutdown, err := initTracer()
	if err != nil {
		log.Printf("otel init: %v", err)
	} else if shutdown != nil {
		defer func() { _ = shutdown(context.Background()) }()
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	_ = http.ListenAndServe(":"+port, newAPI(ConfigFromEnv()).Handler())
}