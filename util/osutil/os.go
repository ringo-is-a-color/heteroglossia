package osutil

import (
	"github.com/tebeka/atexit"
)

func init() {
	go listenEndSignalAndRunHandler()
}

func RegisterProgramTerminationHandler(f func()) {
	atexit.Register(f)
}

func Exit(code int) {
	atexit.Exit(code)
}
