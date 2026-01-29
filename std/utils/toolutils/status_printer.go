package toolutils

import (
	"fmt"
	"os"
	"strings"
)

type StatusPrinter struct {
	File    *os.File
	Padding int
}

// (AI GENERATED DESCRIPTION): Prints a key‑value pair to the printer’s file, left‑padding the key with spaces so the output lines align.
func (s StatusPrinter) Print(key string, value any) {
	fmt.Fprintf(s.File, "%s%s=%v\n", strings.Repeat(" ", s.Padding-len(key)), key, value)
}
