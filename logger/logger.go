package logger

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

type Loggers struct {
	Auth    *slog.Logger
	Session *slog.Logger
	Server  *slog.Logger
	files   []*os.File
}

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

func (l *Loggers) Close() error {
	var first error
	for _, f := range l.files {
		// fsync before close so the last batch of logs hits disk on SIGTERM
		if e := f.Sync(); e != nil && first == nil {
			first = e
		}
		if e := f.Close(); e != nil && first == nil {
			first = e
		}
	}
	return first
}
