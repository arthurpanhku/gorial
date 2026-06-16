// Command gorial is an LLM security gateway: a reverse proxy that sits
// between your application and any OpenAI-compatible endpoint and enforces
// guardrails (prompt-injection / jailbreak detection, PII and secret
// redaction) on the traffic flowing in both directions.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/arthurpanhku/gorial/internal/config"
	"github.com/arthurpanhku/gorial/internal/proxy"
)

func main() {
	args := os.Args[1:]
	if len(args) > 0 {
		switch args[0] {
		case "serve":
			runServe(args[1:])
			return
		case "check":
			runCheck(args[1:])
			return
		case "sample-config":
			fmt.Print(config.Sample())
			return
		case "-h", "--help", "help":
			usage()
			return
		default:
			if !strings.HasPrefix(args[0], "-") {
				fmt.Fprintf(os.Stderr, "gorial: unknown command %q\n\n", args[0])
				usage()
				os.Exit(2)
			}
		}
	}

	// Backward-compatible form: gorial -config config.yaml.
	runServe(args)
}

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("config", "config.yaml", "path to the YAML policy file")
	_ = fs.Parse(args)

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

func runCheck(args []string) {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	cfgPath := fs.String("config", "config.yaml", "path to the YAML policy file")
	_ = fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("gorial: config invalid: %v", err)
	}
	if _, err := proxy.New(cfg); err != nil {
		log.Fatalf("gorial: config invalid: %v", err)
	}
	fmt.Printf("gorial: config OK (%d guards, listen %s -> %s)\n", len(cfg.Guards), cfg.Listen, cfg.Target)
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage:
  gorial -config config.yaml
  gorial serve -config config.yaml
  gorial check -config config.yaml
  gorial sample-config

Commands:
  serve          start the LLM security gateway
  check          validate config and guard setup
  sample-config  write a complete v1 config to stdout
`)
}
