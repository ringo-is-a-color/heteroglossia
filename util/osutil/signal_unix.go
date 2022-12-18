//go:build unix

package osutil

import (
	"os"
	"os/signal"
	"syscall"
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

	sig := <-end
	signal.Stop(end)
	runHandlers()
	err := syscall.Kill(syscall.Getpid(), sig.(syscall.Signal))
	if err != nil {
		panic(err)
	}
}
