package lvs

import (
	"errors"
	"fmt"
	"io"
	"strings"

	enc "github.com/named-data/ndnd/std/encoding"
)

type ComponentValue struct {
	c []byte
}

type RuleId struct {
	id string
}

type Pattern struct {
	id string
}

type NameComp struct {
	compVal ComponentValue
	ruleId  RuleId
	pat     Pattern
}

type NamePat struct {
	p []NameComp
}

func (n NamePat) String() string {
	var sb strings.Builder
	for _, comp := range n.p {
		if comp.compVal.c != nil {
			sb.WriteString("c: \"\"" + string(comp.compVal.c) + "\"")
		} else if comp.pat.id != "" {
			sb.WriteString(comp.pat.id)
		} else if comp.ruleId.id != "" {
			sb.WriteString(comp.ruleId.id)
		}
		sb.WriteString("/")
	}

	return sb.String()
}

type FnArg struct {
	compVal ComponentValue
	pat     Pattern
}

type FnCall struct {
	name string
	args []FnArg
}

type Constraint struct {
	compVal ComponentValue
	pat     Pattern
	fnCall  FnCall
}

type TagConstraint struct {
	pat     Pattern
	options []Constraint
}

type Rule struct {
	id   RuleId
	name NamePat
	// A list of component constraint sets.
	// In disjunctive normal form, e.g. (a^b^c)V(d^e)
	compCons [][]TagConstraint
	// A list of signing key names. Any of them can be used.
	signCons []RuleId
}

func (r *Rule) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s\t%s\t", r.id.id, r.name.String()))

	for _, cc := range r.compCons {
		sb.WriteString("{")
		for _, tc := range cc {
			sb.WriteString(tc.pat.id + ":")
			for _, co := range tc.options {
				sb.WriteString(fmt.Sprint(co) + ",")
			}
		}
		sb.WriteString("} | ")
	}

	sb.WriteString(fmt.Sprint("\t", r.signCons))

	return sb.String()
}

type LvsFile struct {
	rules []Rule
}

type SyntaxError struct {
	pos      Position
	expected Token
	gotToken Token
	gotLit   string
}

func (e SyntaxError) Error() string {
	return fmt.Sprintf("%v Expected %v, got %v %v", e.pos, e.expected, e.gotToken, e.gotLit)
}

func (l *LvsFile) String() string {
	var sb strings.Builder

	for _, rule := range l.rules {
		sb.WriteString(rule.String())
		sb.WriteString("\n")
	}

	return sb.String()
}

type Parser struct {
	pos   Position
	lexer Lexer
	tok   Token
	lit   string
}

func NewParser(reader io.Reader) *Parser {
	lexer := *NewLexer(reader)
	return &Parser{lexer: lexer}
}

func (p *Parser) Parse() (LvsFile, error) {
	var rules []Rule
	var err error // Collect all the syntax errors before outputting

	for {
		var rule Rule
		p.nextToken()

		if p.tok == NEWLINE {
			continue
		}

		if p.tok == EOF {
			return LvsFile{rules}, err
		}

		if p.tok != RULE_IDENT {
			err = errors.Join(err, SyntaxError{pos: p.pos, expected: RULE_IDENT, gotToken: p.tok, gotLit: p.lit})
			p.lexer.SkipLine()
			continue
		}

		rule.id.id = p.lit
		p.nextToken()
		if p.tok != COLON {
			err = errors.Join(err, SyntaxError{pos: p.pos, expected: COLON, gotToken: p.tok, gotLit: p.lit})
			p.lexer.SkipLine()
			continue
		}

		rn, pnErr := p.parseName()
		if pnErr != nil {
			err = errors.Join(err, pnErr)
			p.lexer.SkipLine()
			continue
		}
		rule.name = rn

		if p.tok == CONSTRAINT {
			cc, ccErr := p.parseCompCons()
			if ccErr != nil {
				err = errors.Join(err, ccErr)
				p.lexer.SkipLine()
				continue
			}
			rule.compCons = cc
		}

		if p.tok == SIGNER_ARROW {
			signCons, errSignCon := p.parseSignCons()
			rule.signCons = signCons
			if errSignCon != nil {
				err = errors.Join(err, errSignCon)
				p.lexer.SkipLine()
				continue
			}
		}

		if p.tok != NEWLINE && p.tok != EOF {
			err = errors.Join(err, fmt.Errorf("%v Expected NEWLINE or EOF, got %v", p.pos, p.tok))
			p.lexer.SkipLine()
			continue
		}

		rules = append(rules, rule)
	}
}

func (p *Parser) nextToken() {
	p.pos, p.tok, p.lit = p.lexer.Next()
}

func (p *Parser) parseName() (NamePat, error) {
	var pat []NameComp

	for {
		p.nextToken()
		switch p.tok {
		case SLASH:
			continue
		case STR:
			comp, err := enc.ComponentFromStr(p.lit[1 : len(p.lit)-1]) // remove quotes
			if err != nil {
				return NamePat{}, err
			}
			pat = append(pat, NameComp{compVal: ComponentValue{comp.Bytes()}})
		case TAG_IDENT:
			pat = append(pat, NameComp{pat: Pattern{id: p.lit}})
		case RULE_IDENT:
			pat = append(pat, NameComp{ruleId: RuleId{id: p.lit}})
		default:
			return NamePat{}, fmt.Errorf("%v Expected component value, tag, or rule identifier, got %v", p.pos, p.tok)
		}

		p.nextToken()
		if p.tok != SLASH {
			return NamePat{p: pat}, nil
		}
	}
}

func (p *Parser) parseCompCons() ([][]TagConstraint, error) {
	var conSets [][]TagConstraint

	for {
		p.nextToken()
		switch p.tok {
		case OPEN_BRACKET:
			cs, err := p.parseConSet()
			if err != nil {
				return nil, err
			}
			conSets = append(conSets, cs)
		case OR:
			continue
		default: // If there is unexpected symbol, it will be caught outside of this function
			return conSets, nil
		}
	}
}

func (p *Parser) parseConSet() ([]TagConstraint, error) {
	var conSet []TagConstraint

	for {
		p.nextToken()

		switch p.tok {
		case TAG_IDENT:
			constraint := TagConstraint{pat: Pattern{id: p.lit}}
			p.nextToken() // skip colon
			op, done, err := p.parseConOptions()
			if err != nil {
				return nil, err
			}
			constraint.options = op
			conSet = append(conSet, constraint)
			if done {
				return conSet, nil
			}
		case COMMA, OR:
			continue
		default:
			return conSet, nil
		}
	}
}

func (p *Parser) parseConOptions() (cons []Constraint, done bool, err error) {
	var options []Constraint

	for {
		p.nextToken()

		switch p.tok {
		case STR:
			comp, err := enc.ComponentFromStr(p.lit[1 : len(p.lit)-1])
			if err != nil {
				return nil, true, err
			}
			options = append(options, Constraint{compVal: ComponentValue{comp.Bytes()}})
		case TAG_IDENT:
			options = append(options, Constraint{pat: Pattern{p.lit}})
		case FN_IDENT:
			fnCall := FnCall{name: p.lit}
			args, err := p.parseFnArgs()
			if err != nil {
				return nil, true, err
			}
			fnCall.args = args
			options = append(options, Constraint{fnCall: fnCall})
		case CLOSE_BRACKET:
			return options, true, nil
		case OR:
			continue
		default: // comma
			return options, false, nil
		}
	}
}

func (p *Parser) parseFnArgs() ([]FnArg, error) {
	var args []FnArg

	for {
		p.nextToken() // TODO: check open or close parenthesis

		switch p.tok {
		case FN_OPEN, COMMA:
			continue
		case STR:
			comp, err := enc.ComponentFromStr(p.lit[1 : len(p.lit)-1])
			if err != nil {
				return nil, err
			}
			args = append(args, FnArg{compVal: ComponentValue{comp.Bytes()}})
		case TAG_IDENT:
			args = append(args, FnArg{pat: Pattern{p.lit}})
		default:
			return args, nil
		}
	}
}

func (p *Parser) parseSignCons() ([]RuleId, error) {
	var signers []RuleId

	for {
		p.nextToken()

		if p.tok != RULE_IDENT {
			errPos := p.pos
			p.lexer.SkipLine()
			return nil, SyntaxError{pos: errPos, expected: RULE_IDENT, gotToken: p.tok, gotLit: p.lit}
		}

		signers = append(signers, RuleId{p.lit})

		p.nextToken()
		if p.tok != OR {
			return signers, nil
		}
	}
}
