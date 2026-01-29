package face_test

import (
	"testing"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/engine/face"
	tu "github.com/named-data/ndnd/std/utils/testutils"
	"github.com/stretchr/testify/require"
)

// (AI GENERATED DESCRIPTION): Verifies the consume logic of a DummyFace, ensuring it opens correctly, accepts queued packets, returns them in order, and handles errors and closing as expected.
func TestBasicConsume(t *testing.T) {
	tu.SetT(t)

	testOnData := func([]byte) {
		t.Fatal("No data should be received in this test.")
	}
	// onError is not actually called by dummy face.
	testOnError := func(err error) {
		require.NoError(t, err)
	}

	face := face.NewDummyFace()
	tu.Err(face.Consume())
	require.Error(t, face.Open())
	face.OnPacket(testOnData)
	face.OnError(testOnError)
	require.NoError(t, face.Open())
	tu.Err(face.Consume())

	err := face.Send(enc.Wire{enc.Buffer{0x05, 0x03, 0x01, 0x02, 0x03}})
	require.NoError(t, err)
	data := tu.NoErr(face.Consume())
	require.Equal(t, enc.Buffer{0x05, 0x03, 0x01, 0x02, 0x03}, data)
	tu.Err(face.Consume())

	err = face.Send(enc.Wire{enc.Buffer{0x05, 0x01, 0x01}})
	require.NoError(t, err)
	err = face.Send(enc.Wire{enc.Buffer{0x05, 0x04, 0x01, 0x02, 0x03, 0x04}})
	require.NoError(t, err)
	data = tu.NoErr(face.Consume())
	require.Equal(t, enc.Buffer{0x05, 0x01, 0x01}, data)
	data = tu.NoErr(face.Consume())
	require.Equal(t, enc.Buffer{0x05, 0x04, 0x01, 0x02, 0x03, 0x04}, data)
	tu.Err(face.Consume())

	require.NoError(t, face.Close())
}

// (AI GENERATED DESCRIPTION): Tests that feeding packets into a DummyFace correctly invokes the OnPacket handler with the exact payloads in order and that no errors are generated.
func TestBasicFeed(t *testing.T) {
	tu.SetT(t)
	cnt := 0

	testOnData := func(frame []byte) {
		r := enc.NewBufferReader(frame)
		cnt++
		switch cnt {
		case 1:
			buf := tu.NoErr(r.ReadBuf(r.Length()))
			require.Equal(t, enc.Buffer{0x05, 0x03, 0x01, 0x02, 0x03}, buf)
			return
		case 2:
			buf := tu.NoErr(r.ReadBuf(r.Length()))
			require.Equal(t, enc.Buffer{0x05, 0x01, 0x01}, buf)
			return
		case 3:
			buf := tu.NoErr(r.ReadBuf(r.Length()))
			require.Equal(t, enc.Buffer{0x05, 0x04, 0x01, 0x02, 0x03, 0x04}, buf)
			return
		}
		t.Fatal("No data should be received now.")
	}
	testOnError := func(err error) {
		require.NoError(t, err)
	}

	face := face.NewDummyFace()
	face.OnPacket(testOnData)
	face.OnError(testOnError)
	require.NoError(t, face.Open())

	err := face.FeedPacket(enc.Buffer{0x05, 0x03, 0x01, 0x02, 0x03})
	require.NoError(t, err)
	err = face.FeedPacket(enc.Buffer{0x05, 0x01, 0x01})
	require.NoError(t, err)
	err = face.FeedPacket(enc.Buffer{0x05, 0x04, 0x01, 0x02, 0x03, 0x04})
	require.NoError(t, err)

	require.Equal(t, 3, cnt)
	require.NoError(t, face.Close())
}
