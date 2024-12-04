package runner

import (
	"fmt"
	"os"

	"github.com/cyinnove/logify"

	"github.com/cyinnove/paramx/internal/config"
	"github.com/cyinnove/paramx/pkg/grep"
	"github.com/cyinnove/paramx/pkg/utils"
)

// Run executes the main logic of the program.
// It downloads templates, loads configurations, and performs parameter replacement.
func Run(opts *Options) {

	if err := config.DownloadTempletes(); err != nil {
		logify.Errorf("Failed to clone repository: %s\n", err.Error())
		os.Exit(1)
	}

	if opts.TempletesPath == "" {
		opts.TempletesPath = config.TempletesPath
	}

	configs, err := config.LoadConfig(opts.TempletesPath)
	if err != nil {
		panic(err)
	}

	if opts.CustomTemplete != "" {
		date, err := config.ReadCustomTemplete(opts.CustomTemplete)
		if err != nil {
			logify.Errorf("Error reading custom templete the syntax is invalid : %s\n", err.Error())
			os.Exit(1)
		}
		configs = append(configs, date)

	}


	switch opts.Tag {
	case "isubs":
		logify.Infof("Starting getting intersting subdomains from %d subdomains", len(opts.URLs), opts.Tag)

		result := utils.RemoveDuplicates(grep.GrepSubdomains(opts.URLs, configs))
		for _, r := range result {
			fmt.Fprintln(os.Stdout, r)
		}
		
		logify.Infof("Found %d interesting subdomains", len(result))

		if opts.OutputFile != "" {
			if err := utils.OutputTextResult(result, opts.OutputFile ); err != nil {
				logify.Fatalf("Error writing to file: %s\n", err.Error())
			}
			logify.Infof("Subdomains saved to %s", opts.OutputFile)
		}

	default:
		var result []string
		tags := []string{"xss"}

		if opts.AllTags {
			// Define all supported tags
			tags = []string{"xss", "sqli", "lfi", "rce", "idor", "ssrf", "ssti", "redirect"}
			logify.Infof("Searching for parameters matching all vulnerability tags")
		} else if opts.AllParams {
			logify.Infof("Hunting for all parameterized URLs")
			result = utils.RemoveDuplicates(grep.GrepAllParameters(opts.URLs))
		} else {
			// Validate single tag when not in all-tags mode
			validTags := []string{"xss", "ssrf", "sqli", "lfi", "rce", "idor", "ssti", "redirect", "isubs"}
			isValid := false
			for _, validTag := range validTags {
				if validTag == opts.Tag {
					isValid = true
					break
				}
			}
			if !isValid {
				logify.Fatalf("Invalid tag, please add a valid tag like (xss, ssrf, sqli, lfi, rce, idor, ssti, redirect, isubs)")
			}
			logify.Infof("Starting getting parameters from %d urls for tag %s", len(opts.URLs), opts.Tag)
			tags = []string{opts.Tag}
		}

		if !opts.AllParams {
			for _, tag := range tags {
				// Skip validation in GrepParameters since we've already validated
				tagResults := grep.GrepParametersNoValidate(opts.URLs, configs, tag, opts.ReplaceWith)
				result = append(result, tagResults...)
			}
			result = utils.RemoveDuplicates(result)
		}

		for _, r := range result {
			fmt.Fprintln(os.Stdout, r)
		}

		if opts.AllTags {
			logify.Infof("Found %d parameters across all tags", len(result))
		} else if opts.AllParams {
			logify.Infof("Found %d parameterized URLs", len(result))
		} else {
			logify.Infof("Found %d parameter with tag %s", len(result), opts.Tag)
		}

		if opts.OutputFile != "" {
			if err := utils.OutputTextResult(result, opts.OutputFile); err != nil {
				logify.Fatalf("Error writing to file: %s\n", err.Error())
			}
			logify.Infof("URLs saved to %s", opts.OutputFile)
		}
	}

}
