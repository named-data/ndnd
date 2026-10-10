package lvs

import (
	"bufio"
	"fmt"
	"io"
	"unicode"
)

type Token int

const (
	EOF = iota
	NEWLINE
	ILLEGAL
	UNCLOSED_STR
	STR
	RULE_IDENT
	TAG_IDENT
	FN_IDENT

	COLON
	SLASH
	CONSTRAINT
	COMMA
	OR
	OPEN_BRACKET
	CLOSE_BRACKET
	FN_OPEN
	FN_CLOSE
	SIGNER_ARROW
)

var tokens = []string{
	EOF:          "EOF",
	NEWLINE:      "NEWLINE",
	ILLEGAL:      "ILLEGAL",
	UNCLOSED_STR: "UNCLOSED_STR",
	STR:          "STR",
	RULE_IDENT:   "RULE_IDENT",
	TAG_IDENT:    "TAG_IDENT",
	FN_IDENT:     "FN_IDENT",

	COLON:         ":",
	SLASH:         "/",
	CONSTRAINT:    "&",
	COMMA:         ",",
	OR:            "|",
	OPEN_BRACKET:  "{",
	CLOSE_BRACKET: "}",
	FN_OPEN:       "(",
	FN_CLOSE:      ")",
	SIGNER_ARROW:  "<=",
}

func (t Token) String() string {
	return tokens[t]
}

type Position struct {
	line int
	col  int
}

func (p Position) String() string {
	return fmt.Sprintf("%v:%v", p.line, p.col)
}

type Lexer struct {
	pos        Position
	reader     *bufio.Reader
	peek       bool
	peekColBuf []int
}

func NewLexer(reader io.Reader) *Lexer {
	return &Lexer{
		pos:    Position{line: 1, col: 0},
		reader: bufio.NewReader(reader),
	}
}

func (l *Lexer) Next() (Position, Token, string) {
	for {
		r, _, err := l.reader.ReadRune()
		if err != nil {
			if err == io.EOF {
				return l.pos, EOF, ""
			}

			panic(err)
		}

		l.pos.col++

		switch r {
		case '\n':
			startPos := l.pos
			l.resetPosition()
			return startPos, NEWLINE, "\n"
		case ':':
			return l.pos, COLON, ":"
		case '/':
			if l.atComment() {
				l.SkipLine()
			} else {
				return l.pos, SLASH, "/"
			}
		case '&':
			return l.pos, CONSTRAINT, "&"
		case '{':
			return l.pos, OPEN_BRACKET, "{"
		case '}':
			return l.pos, CLOSE_BRACKET, "}"
		case ',':
			return l.pos, COMMA, ","
		case '|':
			return l.pos, OR, "|"
		case '<':
			next, err := l.reader.Peek(1)
			if err != nil {
				panic(err)
			}

			if next[0] != '=' {
				return l.pos, ILLEGAL, "<"
			}

			startPos := l.pos

			l.skipRune() // signer arrow is two characters
			return startPos, SIGNER_ARROW, "<="
		case '#':
			startPos := l.pos
			return startPos, RULE_IDENT, "#" + l.readIdent()
		case '$':
			startPos := l.pos
			return startPos, FN_IDENT, "$" + l.readIdent()
		case '"':
			startPos := l.pos
			str, err := l.readString()
			if err != nil {
				l.backup()
				return startPos, UNCLOSED_STR, str
			}
			return startPos, STR, str
		default:
			if unicode.IsSpace(r) {
				continue
			} else if unicode.IsLetter(r) || r == '_' {
				startPos := l.pos
				l.backup()
				return startPos, TAG_IDENT, l.readIdent()
			} else {
				return l.pos, ILLEGAL, string(r)
			}
		}
	}
}

func (l *Lexer) resetPosition() {
	if l.peek {
		l.peekColBuf = append(l.peekColBuf, l.pos.col)
	}

	l.pos.line++
	l.pos.col = 0
}

func (l *Lexer) backup() {
	if err := l.reader.UnreadRune(); err != nil {
		panic(err)
	}

	l.pos.col--
}

func (l *Lexer) skipRune() {
	if _, _, err := l.reader.ReadRune(); err != nil {
		panic(err)
	}

	l.pos.col++
}

func (l *Lexer) atComment() bool {
	next, _ := l.reader.Peek(1)
	return next[0] == '/'
}

func (l *Lexer) SkipLine() {
	for {
		r, _, err := l.reader.ReadRune()
		if err != nil {
			if err == io.EOF {
				return
			}

			panic(err)
		}
		l.pos.col++

		if r == '\n' {
			l.resetPosition()
			return
		}
	}
}

func (l *Lexer) readIdent() string {
	var lit string
	for {
		r, _, err := l.reader.ReadRune()
		if err != nil {
			if err == io.EOF {
				// at the end of the identifier
				return lit
			}

			panic(err)
		}

		l.pos.col++
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
			lit = lit + string(r)
		} else {
			// scanned something not in the identifier
			l.backup()
			return lit
		}
	}
}

func (l *Lexer) readString() (string, error) {
	var str string
	for {
		r, _, err := l.reader.ReadRune()
		if err != nil {
			panic(err)
		}
		l.pos.col++

		switch r {
		case '\\':
			n, _, err := l.reader.ReadRune()
			if err == io.EOF {
				panic(err)
			}
			l.pos.col++

			str = str + string(r) + string(n)
		case '"':
			return "\"" + str + "\"", nil
		case '\n':
			return "", fmt.Errorf("Unclosed string")
		default:
			str = str + string(r)
		}
	}
}
