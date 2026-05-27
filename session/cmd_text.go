package session

import (
	"fmt"
	"strconv"
	"strings"
)

func init() {
	register("awk", awkCmd{})
	register("egrep", grepCmd{}) // egrep is grep with extended regex -- same handler
	register("grep", grepCmd{})
	register("wc", wcCmd{})
	register("head", headCmd{})
	register("tail", tailCmd{})
	register("sed", noopCmd{})
	register("sort", sortCmd{})
	register("uniq", noopCmd{})
	register("cut", noopCmd{})
	register("tr", noopCmd{})
	register("xargs", noopCmd{})
}

// awkCmd handles simple field-extraction patterns from the Diicot recon scripts.
// Full awk would need an interpreter -- we just cover {print $N} and {printf $N}.
type awkCmd struct{}

func (awkCmd) Run(args []string, stdin string, _ *Session) (string, uint32) {
	if len(args) == 0 {
		// no script -- pass stdin through (awk with no args reads stdin line by line)
		return stdin, 0
	}
	script := args[0]
	if !strings.Contains(script, "$") {
		return stdin, 0
	}
	// only handle $1 (most common in recon scripts)
	if !strings.Contains(script, "$1") {
		return stdin, 0
	}
	printf := strings.Contains(script, "printf")
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimRight(stdin, "\n"), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if printf {
			b.WriteString(fields[0]) // printf has no implicit newline
		} else {
			fmt.Fprintln(&b, fields[0])
		}
	}
	return b.String(), 0
}

// grepCmd filters stdin lines that contain the pattern.
type grepCmd struct{}

func (grepCmd) Run(args []string, stdin string, _ *Session) (string, uint32) {
	if len(args) == 0 {
		return "Usage: grep [OPTION]... PATTERN [FILE]...\n", 2
	}
	// collect all non-flag args as the pattern -- Fields() splits "Product Name"
	// into two tokens so we rejoin them. strip surrounding quotes after joining.
	var parts []string
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			parts = append(parts, a)
		}
	}
	if len(parts) == 0 {
		return "", 1
	}
	pattern := strings.Trim(strings.Join(parts, " "), `"'`)
	if stdin == "" {
		return "", 1
	}
	var b strings.Builder
	matched := false
	for _, line := range strings.Split(stdin, "\n") {
		if strings.Contains(line, pattern) {
			b.WriteString(line + "\n")
			matched = true
		}
	}
	if !matched {
		return "", 1
	}
	return b.String(), 0
}

// wcCmd counts lines/words/bytes in stdin.
type wcCmd struct{}

func (wcCmd) Run(args []string, stdin string, _ *Session) (string, uint32) {
	flags, _ := splitArgs(args)
	lines := strings.Count(stdin, "\n")
	words := len(strings.Fields(stdin))
	bytes := len(stdin)
	switch {
	case containsFlag(flags, 'l'):
		return fmt.Sprintf("%d\n", lines), 0
	case containsFlag(flags, 'w'):
		return fmt.Sprintf("%d\n", words), 0
	case containsFlag(flags, 'c'):
		return fmt.Sprintf("%d\n", bytes), 0
	}
	return fmt.Sprintf("%d %d %d\n", lines, words, bytes), 0
}

// headCmd returns the first N lines or bytes of stdin.
// Diicot recon uses `head -c 1` to get GPU count as a single character.
type headCmd struct{}

func (headCmd) Run(args []string, stdin string, _ *Session) (string, uint32) {
	for i, a := range args {
		if a == "-c" && i+1 < len(args) {
			n, err := strconv.Atoi(args[i+1])
			if err != nil {
				return "head: invalid number of bytes\n", 1
			}
			if n < 0 {
				n = 0
			}
			if n > len(stdin) {
				n = len(stdin)
			}
			return stdin[:n], 0
		}
		if a == "-n" && i+1 < len(args) {
			n, err := strconv.Atoi(args[i+1])
			if err != nil {
				return "head: invalid number of lines\n", 1
			}
			lines := strings.SplitN(stdin, "\n", n+2)
			if len(lines) > n {
				lines = lines[:n]
			}
			return strings.Join(lines, "\n") + "\n", 0
		}
	}
	// default: first 10 lines
	lines := strings.SplitN(stdin, "\n", 12)
	if len(lines) > 10 {
		lines = lines[:10]
	}
	return strings.Join(lines, "\n") + "\n", 0
}

// tailCmd returns the last N lines of stdin.
type tailCmd struct{}

func (tailCmd) Run(args []string, stdin string, _ *Session) (string, uint32) {
	n := 10
	for i, a := range args {
		if a == "-n" && i+1 < len(args) {
			if v, err := strconv.Atoi(args[i+1]); err == nil {
				n = v
			}
		}
	}
	lines := strings.Split(strings.TrimRight(stdin, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n") + "\n", 0
}

// sortCmd sorts stdin lines alphabetically.
type sortCmd struct{}

func (sortCmd) Run(_ []string, stdin string, _ *Session) (string, uint32) {
	if stdin == "" {
		return "", 0
	}
	lines := strings.Split(strings.TrimRight(stdin, "\n"), "\n")
	// insertion sort -- fine for small outputs
	for i := 1; i < len(lines); i++ {
		for j := i; j > 0 && lines[j] < lines[j-1]; j-- {
			lines[j], lines[j-1] = lines[j-1], lines[j]
		}
	}
	return strings.Join(lines, "\n") + "\n", 0
}
