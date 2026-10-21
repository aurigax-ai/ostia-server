package server

import (
	"io"
	"log/slog"
)

func captureLog(w io.Writer) func() {
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(w, nil)))
	return func() { slog.SetDefault(previous) }
}
