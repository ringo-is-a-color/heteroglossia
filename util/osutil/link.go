package osutil

import (
	_ "unsafe"
)

//go:linkname runHandlers github.com/tebeka/atexit.runHandlers
func runHandlers()
