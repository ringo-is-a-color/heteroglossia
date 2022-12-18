package log

import (
	"fmt"
	"os"
	"sync/atomic"

	"github.com/mdobak/go-xerrors"
	"github.com/ringo-is-a-color/heteroglossia/util/osutil"
	"golang.org/x/exp/slog"
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
		fmt.Print(xerrors.StackTrace(err)[1:])
	}
}

func Fatal(msg string, err error, args ...any) {
	slog.Error(msg, err, args...)
	osutil.Exit(1)
}

func SetVerbose(b bool) {
	verbose.Store(b)
	handlerOptions := slog.HandlerOptions{
		Level: slog.LevelDebug,
	}
	slog.SetDefault(slog.New(handlerOptions.NewTextHandler(os.Stdout)))
}
