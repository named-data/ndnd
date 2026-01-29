package face

import (
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

// (AI GENERATED DESCRIPTION): Creates a new StreamFace configured with the specified network type and address, marks it as local or remote, and registers a default handler that exits the process with status 106 when the face goes down.
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

// (AI GENERATED DESCRIPTION): Returns a string describing the stream face, formatted as “stream‑face (network://addr)”.
func (f *StreamFace) String() string {
	return fmt.Sprintf("stream-face (%s://%s)", f.network, f.addr)
}

// (AI GENERATED DESCRIPTION): Opens a stream-based Face by establishing a network connection, initializing its state, and launching a goroutine to receive packets.
func (f *StreamFace) Open() error {
	if f.IsRunning() {
		return fmt.Errorf("face is already running")
	}

	if f.onError == nil || f.onPkt == nil {
		return fmt.Errorf("face callbacks are not set")
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

// (AI GENERATED DESCRIPTION): Closes the StreamFace by marking its state as closed and shutting down the underlying connection if one exists.
func (f *StreamFace) Close() error {
	if f.setStateClosed() {
		if f.conn != nil {
			return f.conn.Close()
		}
	}

	return nil
}

// (AI GENERATED DESCRIPTION): Sends the provided packet over the StreamFace’s underlying connection, returning an error if the face is not running or if the write fails.
func (f *StreamFace) Send(pkt enc.Wire) error {
	if !f.IsRunning() {
		return fmt.Errorf("face is not running")
	}

	f.sendMut.Lock()
	defer f.sendMut.Unlock()

	_, err := f.conn.Write(pkt.Join())
	if err != nil {
		return err
	}

	return nil
}

// (AI GENERATED DESCRIPTION): Receives TLV packets from the underlying connection, dispatching each to the packet handler, and upon stream termination or an error, triggers an error callback and transitions the face to a down state.
func (f *StreamFace) receive() {
	defer f.setStateDown()

	err := ndn_io.ReadTlvStream(f.conn, func(b []byte) bool {
		f.onPkt(b)
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
