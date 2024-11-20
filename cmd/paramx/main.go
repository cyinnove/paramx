package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/cyinnove/logify"
	"github.com/cyinnove/paramx/internal/runner"
	"github.com/cyinnove/paramx/pkg/utils"
	"github.com/cyinnove/paramx/internal/config" 
)

var opts = &runner.Options{}

func init() {
	//  flags
	flag.StringVar(&opts.TempletesPath, "tp", "", "Directory where YAML configuration files are located.")
	flag.StringVar(&opts.FileInput, "l", "", "Path to a file containing URLs (one per line).")
	flag.StringVar(&opts.Tag, "tag", "xss", "The type of bug to extract the URLs based on it (default: \"xss\"). Supported values: xss, sqli, lfi, rce, idor, ssrf, ssti, redirect.")
	flag.StringVar(&opts.ReplaceWith, "rw", "", "Replace the parameter value with a custom value.")
	flag.StringVar(&opts.CustomTemplete, "t", "", "Path to a custom template.")
	flag.StringVar(&opts.OutputFile, "o", "", "Path to a file where the results should be saved.")

	// usage message
	flag.Usage = func() {
		config.Banner()
		fmt.Println("Usage:")
		flag.PrintDefaults()
		os.Exit(0)
	}
}

func main() {
	flag.Parse()
	if opts.FileInput == "" && opts.TempletesPath == "" {
		fmt.Println(`Error: Missing required flags.`)
		flag.Usage()
	}

	// Read URLs from file if provided
	if opts.FileInput != "" {
		urls, err := utils.ReadURLsFromFile(opts.FileInput)
		if err != nil {
			logify.Fatalf("Failed to read URLs from file: %v", err)
		}
		opts.URLs = urls
	} else {
		// If no file is provided, read URLs from stdin
		urls, err := utils.ReadURLsFromStdin()
		if err != nil {
			logify.Fatalf("Failed to read URLs from stdin or no provided input: %v", err)
		}
		opts.URLs = urls
	}

	// Run the tool
	runner.Run(opts)
}
