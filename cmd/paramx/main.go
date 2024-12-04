package main

import (
	"flag"
	"os"

	"github.com/cyinnove/logify"
	"github.com/cyinnove/paramx/internal/runner"
	"github.com/cyinnove/paramx/pkg/utils"
	"github.com/cyinnove/paramx/internal/config" // Import the config package
)

var opts = &runner.Options{}

func init() {
	flag.StringVar(&opts.TempletesPath, "tp", "", "Directory where YAML configuration files are located.")
	flag.StringVar(&opts.FileInput, "l", "", "Path to a file containing URLs (one per line).")
	flag.StringVar(&opts.Tag, "tag", "xss", "The type of bug to extract the URLs based on it (default: \"xss\"). Supported values: xss, sqli, lfi, rce, idor, ssrf, ssti, redirect.")
	flag.BoolVar(&opts.AllTags, "at", false, "Search for URLs matching all vulnerability tags (overrides -tag).")
	flag.BoolVar(&opts.AllParams, "ap", false, "Hunt for all kinds of parameterized URLs regardless of tag (overrides -tag).")
	flag.StringVar(&opts.ReplaceWith, "rw", "", "Replace the parameter value with a custom value.")
	flag.StringVar(&opts.CustomTemplete, "t", "", "Path to a custom template.")
	flag.StringVar(&opts.OutputFile, "o", "", "Path to a file where the results should be saved.")
}

func main() {
	// Display banner
	config.Banner()

	// Parse command-line flags
	flag.Parse()

	// Read URLs from file if provided
	if opts.FileInput != "" {
		urls, err := utils.ReadURLsFromFile(opts.FileInput)
		if err != nil {
			logify.Fatalf("Failed to read URLs from file: %v", err)
			os.Exit(1)
		}
		opts.URLs = urls
	} else {
		// If no file is provided, read URLs from stdin
		urls, err := utils.ReadURLsFromStdin()
		if err != nil {
			logify.Fatalf("Failed to read URLs from stdin or no provided input: %v", err)
			os.Exit(1)
		}
		opts.URLs = urls
	}

	// Run the tool
	runner.Run(opts)
}
