// Command gorial is an LLM security gateway: a reverse proxy that sits
// between your application and any OpenAI-compatible endpoint and enforces
// guardrails (prompt-injection / jailbreak detection, PII and secret
// redaction) on the traffic flowing in both directions.
package main

import (
	"flag"
	"log"

	"github.com/panchao/gorial/internal/config"
	"github.com/panchao/gorial/internal/proxy"
)

func main() {
	cfgPath := flag.String("config", "config.yaml", "path to the YAML policy file")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("gorial: load config: %v", err)
	}

	srv, err := proxy.New(cfg)
	if err != nil {
		log.Fatalf("gorial: build proxy: %v", err)
	}

	log.Printf("gorial listening on %s -> %s (%d guards)",
		cfg.Listen, cfg.Target, len(cfg.Guards))
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("gorial: server stopped: %v", err)
	}
}
