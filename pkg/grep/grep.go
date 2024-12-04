package grep

import (
	"net/url"
	"strings"

	"github.com/cyinnove/logify"
	"github.com/cyinnove/paramx/internal/config"
	"github.com/cyinnove/paramx/pkg/types"
)


func isTypeExist(tag string, types []string) bool {
	for _, t := range types {
		if strings.EqualFold(t, tag) {
			return true
		}
	}

	return false
}

// GrepParameters searches for parameters in the given URLs based on the provided configurations and bug type.
// It replaces the found parameters with the specified replacement string.
func GrepParameters(urls []string, configs []*config.Data, tag, replaceWith string) []string {
	tags := []string{}

	for _, cfg := range configs {
		tags = append(tags, cfg.Tag)
	}

	if !isTypeExist(tag, tags) {
		logify.Fatalf("Invalid tag , please add a valid tag like (xss, ssrf, sqli, lfi, rce, idor, ssti, redirect, isubs)")
	}

	return GrepParametersNoValidate(urls, configs, tag, replaceWith)
}

// GrepParametersNoValidate is similar to GrepParameters but skips tag validation.
// This is used internally when we've already validated the tag elsewhere.
func GrepParametersNoValidate(urls []string, configs []*config.Data, tag, replaceWith string) []string {
	result := []string{}

	for _, rawURL := range urls {
		params, fullURL := extractParameters(rawURL, replaceWith)

		for _, cfg := range configs {
			if !(cfg.Part == types.Query.String()) {
				continue
			}

			if !(strings.EqualFold(cfg.Tag, tag)) {
				continue
			}

			for paramName := range params {
				for _, param := range cfg.List {
					if strings.EqualFold(paramName, param) {
						result = append(result, fullURL)
					}
				}
			}
		}
	}

	return result
}

func extractParameters(rawURL, replaceWith string) (map[string]string, string) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, ""
	}

	if parsedURL.RawQuery != "" {
		query := parsedURL.Query()
		for key := range query {
			query.Set(key, replaceWith)
		}

		parsedURL.RawQuery = query.Encode()
	}

	params := make(map[string]string)

	for key, values := range parsedURL.Query() {
		params[key] = values[0]
	}

	return params, parsedURL.String()
}

func GrepSubdomains(urls []string, configs []*config.Data) []string {
	result := []string{}
	for _, sub := range urls {

		for _, cfg := range configs {
			if cfg.Part == types.Subdomain.String() {
				for _, subName := range cfg.List {
					if strings.Contains(sub, subName) {
						result = append(result, sub)
					}
				}
			}
		}
	}

	return result
}

// GrepAllParameters finds all URLs that contain any parameters, regardless of tag.
// It returns a slice of strings containing all URLs with parameters.
func GrepAllParameters(urls []string) []string {
	result := []string{}

	for _, rawURL := range urls {
		parsedURL, err := url.Parse(rawURL)
		if err != nil {
			continue
		}

		// Check if URL has query parameters
		if parsedURL.RawQuery != "" {
			result = append(result, rawURL)
			continue
		}

		// Check if URL has path parameters
		if strings.Contains(parsedURL.Path, ";") {
			result = append(result, rawURL)
			continue
		}

		// Check for matrix parameters or other parameter formats
		if strings.Contains(rawURL, "=") {
			result = append(result, rawURL)
		}
	}

	return result
}
