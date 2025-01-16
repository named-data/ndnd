package log

import (
	"context"
	"io"
	"log/slog"
	"runtime"
	"strings"
)

type Logger struct {
	slog  *slog.Logger
	level Level
}

type Tag interface {
	String() string
}

func NewText(w io.Writer) *Logger {
	return &Logger{
		slog: slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{
			Level:       slog.Level(LevelTrace),
			ReplaceAttr: replaceAttr,
		})),
		level: LevelInfo,
	}
}

func NewJson(w io.Writer) *Logger {
	return &Logger{
		slog: slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
			Level:       slog.Level(LevelTrace),
			ReplaceAttr: replaceAttr,
		})),
		level: LevelInfo,
	}
}

// SetLevel sets the logging level and returns the previous level.
func (l *Logger) SetLevel(level Level) (prev Level) {
	prev = l.level
	l.level = level
	return
}

// Level returns the current logging level.
func (l *Logger) Level() Level {
	return l.level
}

// Generic level message.
func (l *Logger) log(t Tag, msg string, level Level, v ...any) {
	if l.level > level {
		return
	}

	// Get source information
	var source string
	if l.level <= LevelDebug || t == nil {
		if pc, _, _, ok := runtime.Caller(2); ok {
			if f := runtime.FuncForPC(pc); f != nil {
				source = f.Name()
			}
		}
	}

	// Keep source information if debug
	if l.level <= LevelDebug {
		v = append(v, slog.SourceKey, source)
	}

	// Get tag or use source as tag
	if t != nil {
		v = append([]any{"tag", t.String()}, v...)
	} else if source != "" {
		parts := strings.Split(source, "/")
		v = append([]any{"tag", parts[len(parts)-1]}, v...)
	}

	// Log the message
	l.slog.Log(context.Background(), slog.Level(level), msg, v...)
}

// Trace level message.
func (l *Logger) Trace(t Tag, msg string, v ...any) {
	l.log(t, msg, LevelTrace, v...)
}

// Debug level message.
func (l *Logger) Debug(t Tag, msg string, v ...any) {
	l.log(t, msg, LevelDebug, v...)
}

// Info level message.
func (l *Logger) Info(t Tag, msg string, v ...any) {
	l.log(t, msg, LevelInfo, v...)
}

// Warn level message.
func (l *Logger) Warn(t Tag, msg string, v ...any) {
	l.log(t, msg, LevelWarn, v...)
}

// Error level message.
func (l *Logger) Error(t Tag, msg string, v ...any) {
	l.log(t, msg, LevelError, v...)
}

// Fatal level message, followed by an exit.
func (l *Logger) Fatal(t Tag, msg string, v ...any) {
	l.log(t, msg, LevelFatal, v...)
}

func replaceAttr(groups []string, a slog.Attr) slog.Attr {
	if a.Key == slog.LevelKey {
		level := a.Value.Any().(slog.Level)
		a.Value = slog.StringValue(Level(level).String())
	}

	return a
}
