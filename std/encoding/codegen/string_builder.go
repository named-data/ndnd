package codegen

import (
	"fmt"
	"strings"
	"text/template"
)

type strErrBuf struct {
	b   strings.Builder
	err error
}

// (AI GENERATED DESCRIPTION): Writes a string to the internal buffer only if no previous error has been recorded, and stores the first error encountered (either from the write or passed in).
func (m *strErrBuf) printlne(str string, err error) {
	if m.err == nil {
		if err == nil {
			_, m.err = fmt.Fprintln(&m.b, str)
		} else {
			m.err = err
		}
	}
}

// (AI GENERATED DESCRIPTION): Writes a formatted string followed by a newline to an internal buffer, but only if no previous error has occurred, recording any error that arises.
func (m *strErrBuf) printlnf(format string, args ...any) {
	if m.err == nil {
		_, m.err = fmt.Fprintf(&m.b, format, args...)
		m.b.WriteRune('\n')
	}
}

// (AI GENERATED DESCRIPTION): Returns the trimmed string content of the buffer and any stored error.
func (m *strErrBuf) output() (string, error) {
	return strings.TrimSpace(m.b.String()), m.err
}

// (AI GENERATED DESCRIPTION): Executes a Go template with the given data, writing the output to the buffer and recording the first error that occurs (ignoring subsequent executions if an error is already set).
func (m *strErrBuf) executeTemplate(t *template.Template, data any) {
	if m.err == nil {
		m.err = t.Execute(&m.b, data)
	}
}

// (AI GENERATED DESCRIPTION): Parses the supplied template string into a Go template and executes it with the provided data, writing the rendered output into the `strErrBuf`.
func (m *strErrBuf) execTemplS(name string, templ string, data any) {
	t := template.Must(template.New(name).Parse(templ))
	m.executeTemplate(t, data)
}
