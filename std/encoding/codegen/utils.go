package codegen

import (
	"fmt"
	"strings"
	"text/template"
)

func GenTypeNumLen(typeNum uint64) (string, error) {
	var ret uint
	switch {
	case typeNum <= 0xfc:
		ret = 1
	case typeNum <= 0xffff:
		ret = 3
	case typeNum <= 0xffffffff:
		ret = 5
	default:
		ret = 9
	}
	return fmt.Sprintf("\tl += %d", ret), nil
}

func GenEncodeTypeNum(typeNum uint64) (string, error) {
	ret := ""
	switch {
	case typeNum <= 0xfc:
		ret += fmt.Sprintf("\tbuf[pos] = byte(%d)\n", typeNum)
		ret += fmt.Sprintf("\tpos += %d", 1)
	case typeNum <= 0xffff:
		ret += fmt.Sprintf("\tbuf[pos] = %d\n", 0xfd)
		ret += fmt.Sprintf("\tbinary.BigEndian.PutUint16(buf[pos+1:], uint16(%d))\n", typeNum)
		ret += fmt.Sprintf("\tpos += %d", 3)
	case typeNum <= 0xffffffff:
		ret += fmt.Sprintf("\tbuf[pos] = %d\n", 0xfe)
		ret += fmt.Sprintf("\tbinary.BigEndian.PutUint32(buf[pos+1:], uint32(%d))\n", typeNum)
		ret += fmt.Sprintf("\tpos += %d", 5)
	default:
		ret += fmt.Sprintf("\tbuf[pos] = %d\n", 0xff)
		ret += fmt.Sprintf("\tbinary.BigEndian.PutUint64(buf[pos+1:], uint64(%d))\n", typeNum)
		ret += fmt.Sprintf("\tpos += %d", 9)
	}
	return ret, nil
}

func GenNaturalNumberLen(code string, isTlv bool) (string, error) {
	var temp string
	if isTlv {
		temp = `l += uint(enc.TLNum({{.}}).EncodingLength())`
	} else {
		temp = `l += uint(1 + enc.Nat({{.}}).EncodingLength())`
	}
	t := template.Must(template.New("NaturalNumberLen").Parse(temp))
	b := strings.Builder{}
	err := t.Execute(&b, code)
	return b.String(), err
}

func GenNaturalNumberEncode(code string, isTlv bool) (string, error) {
	var temp string
	if isTlv {
		temp = `pos += uint(enc.TLNum({{.}}).EncodeInto(buf[pos:]))`
	} else {
		temp = `
			buf[pos] = byte(enc.Nat({{.}}).EncodeInto(buf[pos+1:]))
			pos += uint(1 + buf[pos])
		`
	}
	t := template.Must(template.New("NaturalNumberEncode").Parse(temp))
	b := strings.Builder{}
	err := t.Execute(&b, code)
	return b.String(), err
}

func GenTlvNumberDecode(code string) (string, error) {
	const Temp = `{{.}}, err = reader.ReadTLNum()
	if err != nil {
		return nil, enc.ErrFailToParse{TypeNum: 0, Err: err}
	}`
	t := template.Must(template.New("TlvNumberDecode").Parse(Temp))
	b := strings.Builder{}
	err := t.Execute(&b, code)
	return b.String(), err
}

func GenNaturalNumberDecode(code string) (string, error) {
	const Temp = `{{.}} = uint64(0)
	{
		for i := 0; i < int(l); i++ {
			x := byte(0)
			x, err = reader.ReadByte()
			if err != nil {
				if err == io.EOF {
					err = io.ErrUnexpectedEOF
				}
				break
			}
			{{.}} = uint64({{.}}<<8) | uint64(x)
		}
	}`
	t := template.Must(template.New("NaturalNumberDecode").Parse(Temp))
	b := strings.Builder{}
	err := t.Execute(&b, code)
	return b.String(), err
}

func GenSwitchWirePlan() (string, error) {
	return `wirePlan = append(wirePlan, l)
	l = 0`, nil
}

func GenSwitchWire() (string, error) {
	return `wireIdx ++
	pos = 0
	if wireIdx < len(wire) {
		buf = wire[wireIdx]
	} else {
		buf = nil
	}`, nil
}
