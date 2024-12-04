<p align="center">
  <a href="https://pkg.go.dev/github.com/cyinnove/paramx/pkg/paramx"><img src="https://pkg.go.dev/badge/github.com/cyinnove/paramx.svg"></a>
  <a href="https://goreportcard.com/report/github.com/cyinnove/paramx"><img src="https://goreportcard.com/badge/github.com/cyinnove/paramx"></a> 
  <a href="https://twitter.com/intent/follow?screen_name=zomasec"><img src="https://img.shields.io/twitter/follow/zomasec?style=flat&logo=x"></a>
  <a href="https://twitter.com/intent/follow?screen_name=HunterXReda"><img src="https://img.shields.io/twitter/follow/HunterXReda?style=flat&logo=x"></a>
</p>

## Overview

ParamX is a tool designed to extract interesting subdomains and parameters from URLs. It can be handy for bug hunters and penetration testers looking for specific types of vulnerabilities such as XSS, SQLi, LFI, RCE, IDOR, SSRF, SSTI, and open redirects.

<p align="center">
    <img src="./static/paramx-logo.png" hight="100" width="300">
</p>


- inspired from [gf](https://github.com/tomnomnom/gf) by tomnomnom but edited with more clean code and easy configuration using YAML templates

## Features

- Extracts parameters based on specified bug types.
- Supports custom templates.
- Can update and download YAML configuration templates.
- Processes URLs from files or standard input.
- Custom parameter value replacement.
- Easy configuration using YAML templates not JSON like gf
- Supports all-tags mode to search across all vulnerability types
- Supports all-params mode to find any parameterized URLs

## Templates
- You can find our written templates here [paramx-tempalets](https://github.com/cyinnove/paramx-templates) or you can create your own, it's so easy to do
-the syntax is basic
```
tag: {{TAG_NAME}} // xss,sqli,ssrf, as you want you can create your own
part: {{PART_NAME}} // query,subdomain, ... will add new parts in z future

list:
  - param1
  - param2
  - param2
```

## Installation

To install ParamX:

```sh
go install github.com/cyinnove/paramx/cmd/paramx@latest

```

## Usage

ParamX is executed via command-line interface (CLI) with several options to customize its behavior. Below are the available flags:

- `-tp` : Directory where YAML configuration files are located.
- `-l` : Path to a file containing URLs (one per line).
- `-tag` : The type of bug to extract the URLs based on it (default: "xss"). Supported values: xss, sqli, lfi, rce, idor, ssrf, ssti, redirect.
- `-at` : Search for URLs matching all vulnerability tags.
- `-ap` : Hunt for all kinds of parameterized URLs regardless of tag.
- `-rw` : Replace the parameter value with a custom value.
- `-t` : Path to a custom template.
- `-o` : Path to a file where the results should be saved.

### Examples

#### Basic Usage

To extract XSS parameters from a list of URLs provided in a file:

```sh
cat urls.txt | paramx -tag xss
```

This will show output like :

![poc.png](/static/poc.png)

#### Search All Tags

To search for parameters matching any vulnerability type:

```sh
cat urls.txt | paramx -at
```

#### Find All Parameterized URLs

To find all URLs that contain parameters, regardless of type:

```sh
cat urls.txt | paramx -ap
```

#### Save Results to File

To save the results to a file:

```sh
cat urls.txt | paramx -tag xss -o results.txt
```

## Contributing

Contributions are welcome! Please fork the repository and submit pull requests.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Contact

For issues, questions, or suggestions, please open an issue on the [GitHub repository](https://github.com/cyinnove/paramx).

---

### Detailed Example

Here’s a more detailed example of how you might run ParamX with various options:

```sh
paramx -tp /path/to/templates -l urls.txt -tag sqli -rw "injected_value" -t /path/to/custom_template.yaml
```

In this example, ParamX will:

1. Use templates from `/path/to/templates`.
2. Read URLs from `urls.txt`.
3. Extract parameters that are prone to SQL injection.
4. Replace parameter values with `injected_value`.
5. Use a custom template located at `/path/to/custom_template.yaml`.

## Internal Structure

The main package imports necessary modules and handles command-line flag definitions and parsing. The core functionalities include:

1. **Template Handling**:
   - Updating and downloading YAML configuration templates.
2. **URL Reading**:
   - Reading URLs from a file or standard input.
3. **Parameter Grepping**:
   - Extracting parameters based on specified tags.
4. **Logging**:
   - Logging important information and errors.

The `runner` package contains the main logic for parameter extraction, while the `utils` package includes utility functions for reading URLs and handling I/O operations.

---
## TODO

- add more custmization to match any part of url
- add ability to match any part using regex

---

- We are inviting the cyber security community to contribute on our open source project to make it better

Thank you for using ParamX! We hope this tool aids you in your recon process. For more information, visit our [GitHub repository](https://github.com/cyinnove/paramx). 
