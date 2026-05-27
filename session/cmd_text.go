package session

import "strconv"

func init() {
	register("awk", noopCmd{})
	register("grep", grepCmd{})
	register("wc", wcCmd{})
	register("head", headCmd{})
	register("tail", noopCmd{})
	register("sed", noopCmd{})
	register("sort", noopCmd{})
	register("uniq", noopCmd{})
	register("cut", noopCmd{})
	register("tr", noopCmd{})
	register("xargs", noopCmd{})
}

// grepCmd -- pipes not implemented, grep is called standalone.
// exit 1 (no match) is realistic when there's no input.
type grepCmd struct{}

func (grepCmd) Run(args []string) (string, uint32) {
	if len(args) == 0 {
		return "Usage: grep [OPTION]... PATTERN [FILE]...\n", 2
	}
	return "", 1
}

// wcCmd -- without pipes stdin is empty, so all counts are 0.
type wcCmd struct{}

func (wcCmd) Run(args []string) (string, uint32) {
	flags, _ := splitArgs(args)
	if containsFlag(flags, 'l') || containsFlag(flags, 'w') || containsFlag(flags, 'c') {
		return "0\n", 0
	}
	return "0 0 0\n", 0
}

// headCmd -- Diicot recon uses `head -c 1` to get GPU count as a single char.
// Without real pipes we're called standalone -- no content to return.
type headCmd struct{}

func (headCmd) Run(args []string) (string, uint32) {
	for i, a := range args {
		if a == "-c" && i+1 < len(args) {
			if _, err := strconv.Atoi(args[i+1]); err != nil {
				return "head: invalid number of bytes\n", 1
			}
		}
	}
	return "", 0
}
