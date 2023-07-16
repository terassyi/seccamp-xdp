package logger

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/exp/slog"
)

func SetUpLogger(json bool, output io.Writer, level slog.Level) *slog.Logger {
	var handler slog.Handler
	opt := slog.HandlerOptions{
		AddSource: true,
		Level:     level,
	}
	if !json {
		handler = opt.NewTextHandler(output)
	} else {
		handler = opt.NewJSONHandler(output)
	}
	return slog.New(handler)
}

func Output(out string) (io.Writer, error) {
	switch out {
	case "stdout":
		return os.Stdout, nil
	case "stderr":
		return os.Stderr, nil
	default:
		return nil, fmt.Errorf("Invalid output target: %s", out)
	}
}

func ValidateLevel(level int) slog.Level {
	switch level {
	case int(slog.LevelDebug):
		return slog.LevelDebug
	case int(slog.LevelWarn):
		return slog.LevelWarn
	case int(slog.LevelError):
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
