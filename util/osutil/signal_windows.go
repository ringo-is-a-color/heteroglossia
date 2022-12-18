package osutil

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/tebeka/atexit"
)

func listenEndSignalAndRunHandler() {
	end := make(chan os.Signal, 1)
	signal.Notify(end,
		// https://www.gnu.org/software/libc/manual/html_node/Termination-Signals.html
		syscall.SIGTERM,
		syscall.SIGINT,
		syscall.SIGQUIT,
		syscall.SIGKILL,
		syscall.SIGHUP,
	)

	<-end
	signal.Stop(end)
	// https://pkg.go.dev/os#Process.Signal
	// Sending Interrupt on Windows is not implemented.
	atexit.Exit(1)
}
