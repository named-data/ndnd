package encoding

import "io"

func (r *FastReader) ReadTLNum() (val TLNum, err error) {
	var x byte
	if x, err = r.ReadByte(); err != nil {
		return
	}
	l := 1
	switch {
	case x <= 0xfc:
		val = TLNum(x)
		return
	case x == 0xfd:
		l = 2
	case x == 0xfe:
		l = 4
	case x == 0xff:
		l = 8
	}
	val = 0
	for i := 0; i < l; i++ {
		if x, err = r.ReadByte(); err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return
		}
		val = TLNum(val<<8) | TLNum(x)
	}
	return
}

func (r *FastReader) ReadComponent() (Component, error) {
	typ, err := r.ReadTLNum()
	if err != nil {
		return Component{}, err
	}
	l, err := r.ReadTLNum()
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return Component{}, err
	}
	val, err := r.ReadBuf(int(l))
	if err != nil {
		return Component{}, err
	}
	return Component{
		Typ: typ,
		Val: val,
	}, nil
}

func (r *FastReader) ReadName() (Name, error) {
	var err error
	var c Component
	ret := make(Name, 0, 8)
	// Bad design of Go: it does not allow you use := to create a temp var c and write the error to err.
	for c, err = r.ReadComponent(); err == nil; c, err = r.ReadComponent() {
		ret = append(ret, c)
	}
	if err != io.EOF {
		return nil, err
	} else {
		return ret, nil
	}
}
