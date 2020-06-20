package gips

const (
	ipsHeader = "PATCH"
	ipsEOF    = "EOF"
)

var verbose bool

// SetVerbose sets the verbosity for this module
func SetVerbose(b bool) {
	verbose = b
}

func init() {
	verbose = false
}
