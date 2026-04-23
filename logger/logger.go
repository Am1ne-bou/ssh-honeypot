package logger

import (
	"io"
	"log/slog"
)

// New returns a JSON slog.Logger writing to w.
func New(w io.Writer) *slog.Logger {
	h := slog.NewJSONHandler(w, nil)
	return slog.New(h)
}
