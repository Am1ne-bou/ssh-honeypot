package session

import (
	"fmt"
	"sort"
	"strings"
)

func init() {
	register("env", envCmd{})
	register("printenv", printenvCmd{})
	register("bash", bashCmd{})
	register("sh", bashCmd{})
	register("python3", pythonCmd{version: "Python 3.12.3"})
	register("python", pythonCmd{version: "Python 2.7.18"})
	register("python2", pythonCmd{version: "Python 2.7.18"})
}

type envCmd struct{}

func (envCmd) Run(_ []string) (string, uint32) {
	keys := make([]string, 0, len(fakeEnv))
	for k := range fakeEnv {
		if k != "?" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%s\n", k, fakeEnv[k])
	}
	return b.String(), 0
}

type printenvCmd struct{}

func (printenvCmd) Run(args []string) (string, uint32) {
	if len(args) == 0 {
		return envCmd{}.Run(nil)
	}
	out := ""
	for _, a := range args {
		if v, ok := fakeEnv[a]; ok {
			out += v + "\n"
		}
	}
	return out, 0
}

// bash -c "..." -> rerun the inner cmd through dispatch. interactive bash just exits.
type bashCmd struct{}

func (bashCmd) Run(args []string) (string, uint32) {
	if len(args) >= 2 && args[0] == "-c" {
		return dispatch(strings.Join(args[1:], " "))
	}
	return "", 0
}

type pythonCmd struct{ version string }

func (p pythonCmd) Run(args []string) (string, uint32) {
	if len(args) == 0 {
		return "", 0 // interactive python -- idle timer will kill it
	}
	if args[0] == "--version" || args[0] == "-V" {
		return p.version + "\n", 0
	}
	// python3 -c '...' = reverse shell payload territory. already logged upstream.
	return "", 0
}
