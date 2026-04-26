package logger

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

// Loggers groups the three per-stream loggers and the files backing them.
type Loggers struct {
	Auth    *slog.Logger
	Session *slog.Logger
	Server  *slog.Logger
	files   []*os.File
}

// New opens dir/{auth,session,server}.log and returns a Loggers writing JSON to each.
func New(dir string) (*Loggers, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", dir, err)
	}

	l := &Loggers{}
	for _, name := range []string{"auth", "session", "server"} {
		path := filepath.Join(dir, name+".log")
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			l.Close()
			return nil, fmt.Errorf("open %s: %w", path, err)
		}
		l.files = append(l.files, f)
		lg := slog.New(slog.NewJSONHandler(f, nil))
		switch name {
		case "auth":
			l.Auth = lg
		case "session":
			l.Session = lg
		case "server":
			l.Server = lg
		}
	}
	return l, nil
}

// Close flushes and closes all backing files.
func (l *Loggers) Close() error {
	var first error
	for _, f := range l.files {
		if err := f.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}
