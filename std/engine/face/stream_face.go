package face

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"

	enc "github.com/named-data/ndnd/std/encoding"
	ndn_io "github.com/named-data/ndnd/std/utils/io"
)

// StreamFace is a face that uses a stream connection.
type StreamFace struct {
	baseFace
	network string
	addr    string
	conn    net.Conn
}

func NewStreamFace(network string, addr string, local bool) *StreamFace {
	s := &StreamFace{
		baseFace: newBaseFace(local),
		network:  network,
		addr:     addr,
	}

	// Quit app by default when stream face fails
	s.OnDown(func() { os.Exit(106) })

	return s
}

func (f *StreamFace) String() string {
	return fmt.Sprintf("stream-face (%s://%s)", f.network, f.addr)
}

func (f *StreamFace) Trait() Face {
	return f
}

func (f *StreamFace) Open() error {
	if f.IsRunning() {
		return errors.New("face is already running")
	}

	if f.onError == nil || f.onPkt == nil {
		return errors.New("face callbacks are not set")
	}

	c, err := net.Dial(f.network, f.addr)
	if err != nil {
		return err
	}

	f.conn = c
	f.setStateUp()
	go f.receive()

	return nil
}

func (f *StreamFace) Close() error {
	if f.setStateClosed() {
		if f.conn != nil {
			return f.conn.Close()
		}
	}

	return nil
}

func (f *StreamFace) Send(pkt enc.Wire) error {
	if !f.IsRunning() {
		return errors.New("face is not running")
	}

	f.sendMut.Lock()
	defer f.sendMut.Unlock()

	_, err := f.conn.Write(pkt.Join())
	if err != nil {
		return err
	}

	return nil
}

func (f *StreamFace) receive() {
	defer f.setStateDown()

	err := ndn_io.ReadTlvStream(f.conn, func(b ndn_io.BufT) bool {
		if err := f.onPkt(b.Buf); err != nil {
			f.Close()    // engine error
			return false // break
		}
		return f.IsRunning()
	}, nil)

	if f.IsRunning() {
		if err != nil {
			f.onError(err)
		} else {
			f.onError(io.EOF)
		}
	}
}
