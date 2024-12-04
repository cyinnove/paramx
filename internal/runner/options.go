package runner

// Options represents the configuration options for the runner.
type Options struct {
	URLs         []string // URLs is a list of target URLs.
	TempletesPath string   // TempletesPath is the path to the templates directory.
	Tag      string   	  // Tag is the type of bug to be injected.
	AllTags     bool      // AllTags enables searching for all vulnerability tags.
	AllParams   bool      // AllParams enables hunting for all parameterized URLs.
	FileInput    string   // FileInput is the path to the input file.
	ReplaceWith  string   // ReplaceWith is the string to replace the bug with.
	CustomTemplete string // CustomTemplete is the path to the custom templete.
	UpdateTempletes bool   // UpdateTempletes is a flag to update the templetes.
	OutputFile  string   // OutputFile is the path to the output file.
}