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

func (m *strErrBuf) printlne(str string, err error) {
	if m.err == nil {
		if err == nil {
			_, m.err = fmt.Fprintln(&m.b, str)
		} else {
			m.err = err
		}
	}
}

func (m *strErrBuf) printlnf(format string, args ...any) {
	if m.err == nil {
		_, m.err = fmt.Fprintf(&m.b, format, args...)
		m.b.WriteRune('\n')
	}
}

func (m *strErrBuf) printlnf_if(cond bool, format string, args ...any) {
	if cond {
		m.printlnf(format, args...)
	}
}

func (m *strErrBuf) output() (string, error) {
	return strings.TrimSpace(m.b.String()), m.err
}

func (m *strErrBuf) executeTemplate(t *template.Template, data any) {
	if m.err == nil {
		m.err = t.Execute(&m.b, data)
	}
}

func (m *strErrBuf) execTemplS(name string, templ string, data any) {
	t := template.Must(template.New(name).Parse(templ))
	m.executeTemplate(t, data)
}
