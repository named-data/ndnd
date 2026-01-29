package utils

import (
	"fmt"
	"os"
	"runtime"
)

// (AI GENERATED DESCRIPTION): Prints a stack trace of all goroutines to standard error.
func PrintStackTrace() {
	buf := make([]byte, 1<<20)
	stacklen := runtime.Stack(buf, true)
	fmt.Fprintf(os.Stderr, "*** goroutine dump...\n%s\n*** end\n", buf[:stacklen])
}
