package log

import (
	"fmt"
	"log/slog"
	"sync/atomic"

	"github.com/mdobak/go-xerrors"
	"github.com/ringo-is-a-color/heteroglossia/util/osutil"
)

var verbose = atomic.Bool{}

func Debug(msg string, args ...any) {
	slog.Debug(msg, args...)
}

var Info = slog.Info

func InfoWithError(msg string, err error, args ...any) {
	slog.Info(msg, append(args, "err", err)...)
	if verbose.Load() == true {
		// skip first stack trace which used in 'github.com/ringo-is-a-color/heteroglossia/util/errors' package
		stacktrace := xerrors.StackTrace(err)
		if len(stacktrace) > 1 {
			fmt.Print(stacktrace[1:])
		} else {
			fmt.Print(stacktrace)
		}
	}
}

var Warn = slog.Warn

func WarnWithError(msg string, err error, args ...any) {
	slog.Warn(msg, append(args, "err", err)...)
	fmt.Print(xerrors.StackTrace(err)[1:])
}

var Error = slog.Error

func Fatal(msg string, err error, args ...any) {
	slog.Error(msg, append(args, "err", err)...)
	osutil.Exit(1)
}

func SetVerbose(b bool) {
	verbose.Store(b)
	slog.SetLogLoggerLevel(slog.LevelDebug)
}
