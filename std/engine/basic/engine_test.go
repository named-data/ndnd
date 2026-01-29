package basic_test

import (
	"testing"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	basic_engine "github.com/named-data/ndnd/std/engine/basic"
	"github.com/named-data/ndnd/std/engine/face"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/ndn/spec_2022"
	sig "github.com/named-data/ndnd/std/security/signer"
	"github.com/named-data/ndnd/std/types/optional"
	tu "github.com/named-data/ndnd/std/utils/testutils"
	"github.com/stretchr/testify/require"
)

// (AI GENERATED DESCRIPTION): Executes a test by creating a dummy face, engine, and timer, starting the engine, running the supplied test function, and then stopping the engine while ensuring no errors occur.
func executeTest(t *testing.T, main func(*face.DummyFace, *basic_engine.Engine, *basic_engine.DummyTimer)) {
	tu.SetT(t)

	face := face.NewDummyFace()
	timer := basic_engine.NewDummyTimer()
	engine := basic_engine.NewEngine(face, timer)
	require.NoError(t, engine.Start())

	main(face, engine, timer)

	require.NoError(t, engine.Stop())
}

// (AI GENERATED DESCRIPTION): Tests that the basic engine can start successfully when provided with a dummy face and timer, ensuring no errors occur during initialization.
func TestEngineStart(t *testing.T) {
	executeTest(t, func(face *face.DummyFace, engine *basic_engine.Engine, timer *basic_engine.DummyTimer) {
	})
}

// (AI GENERATED DESCRIPTION): Tests that an expressed Interest is correctly sent, a matching Data packet is received and processed, and the callback receives the expected Data packet with the correct name, freshness, and content.
func TestConsumerBasic(t *testing.T) {
	executeTest(t, func(face *face.DummyFace, engine *basic_engine.Engine, timer *basic_engine.DummyTimer) {
		hitCnt := 0

		spec := engine.Spec()
		name := tu.NoErr(enc.NameFromStr("/example/testApp/randomData/t=1570430517101"))
		config := &ndn.InterestConfig{
			MustBeFresh: true,
			CanBePrefix: false,
			Lifetime:    optional.Some(6 * time.Second),
		}
		interest, err := spec.MakeInterest(name, config, nil, nil)
		require.NoError(t, err)
		err = engine.Express(interest, func(args ndn.ExpressCallbackArgs) {
			hitCnt += 1
			require.Equal(t, ndn.InterestResultData, args.Result)
			require.True(t, args.Data.Name().Equal(name))
			require.Equal(t, 1*time.Second, args.Data.Freshness().Unwrap())
			require.Equal(t, []byte("Hello, world!"), args.Data.Content().Join())
		})
		require.NoError(t, err)
		buf := tu.NoErr(face.Consume())
		require.Equal(t, enc.Buffer(
			"\x050\x07(\x08\x07example\x08\x07testApp\x08\nrandomData"+
				"\x38\x08\x00\x00\x01m\xa4\xf3\xffm\x12\x00\x0c\x02\x17p"),
			buf)
		timer.MoveForward(500 * time.Millisecond)
		require.NoError(t, face.FeedPacket(enc.Buffer(
			"\x06B\x07(\x08\x07example\x08\x07testApp\x08\nrandomData"+
				"\x38\x08\x00\x00\x01m\xa4\xf3\xffm\x14\x07\x18\x01\x00\x19\x02\x03\xe8"+
				"\x15\rHello, world!",
		)))

		require.Equal(t, 1, hitCnt)
	})
}

// TODO: TestInterestCancel

// (AI GENERATED DESCRIPTION): Tests that an Interest expressed with specific parameters correctly triggers a NACK callback with the NoRoute reason, verifying that the outgoing Interest packet is properly encoded and that the engine processes the received NACK as an InterestResultNack.
func TestInterestNack(t *testing.T) {
	executeTest(t, func(face *face.DummyFace, engine *basic_engine.Engine, timer *basic_engine.DummyTimer) {
		hitCnt := 0

		spec := engine.Spec()
		name := tu.NoErr(enc.NameFromStr("/localhost/nfd/faces/events"))
		config := &ndn.InterestConfig{
			MustBeFresh: true,
			CanBePrefix: true,
			Lifetime:    optional.Some(1 * time.Second),
		}
		interest, err := spec.MakeInterest(name, config, nil, nil)
		require.NoError(t, err)
		err = engine.Express(interest, func(args ndn.ExpressCallbackArgs) {
			hitCnt += 1
			require.Equal(t, ndn.InterestResultNack, args.Result)
			require.Equal(t, spec_2022.NackReasonNoRoute, args.NackReason)
		})
		require.NoError(t, err)
		buf := tu.NoErr(face.Consume())
		require.Equal(t, enc.Buffer(
			"\x05)\x07\x1f\x08\tlocalhost\x08\x03nfd\x08\x05faces\x08\x06events"+
				"\x21\x00\x12\x00\x0c\x02\x03\xe8"),
			buf)
		timer.MoveForward(500 * time.Millisecond)
		require.NoError(t, face.FeedPacket(enc.Buffer(
			"\x64\x36\xfd\x03\x20\x05\xfd\x03\x21\x01\x96"+
				"\x50\x2b\x05)\x07\x1f\x08\tlocalhost\x08\x03nfd\x08\x05faces\x08\x06events"+
				"\x21\x00\x12\x00\x0c\x02\x03\xe8",
		)))

		require.Equal(t, 1, hitCnt)
	})
}

// (AI GENERATED DESCRIPTION): Verifies that an Interest with a 10 ms lifetime times out after the timer advances and the Express callback is invoked with `InterestResultTimeout`, even when a Data packet arrives afterward.
func TestInterestTimeout(t *testing.T) {
	executeTest(t, func(face *face.DummyFace, engine *basic_engine.Engine, timer *basic_engine.DummyTimer) {
		hitCnt := 0

		spec := engine.Spec()
		name := tu.NoErr(enc.NameFromStr("not important"))
		config := &ndn.InterestConfig{
			Lifetime: optional.Some(10 * time.Millisecond),
		}
		interest, err := spec.MakeInterest(name, config, nil, nil)
		require.NoError(t, err)
		err = engine.Express(interest, func(args ndn.ExpressCallbackArgs) {
			hitCnt += 1
			require.Equal(t, ndn.InterestResultTimeout, args.Result)
		})
		require.NoError(t, err)
		buf := tu.NoErr(face.Consume())
		require.Equal(t, enc.Buffer("\x05\x14\x07\x0f\x08\rnot important\x0c\x01\x0a"), buf)
		timer.MoveForward(50 * time.Millisecond)

		data, err := spec.MakeData(name, &ndn.DataConfig{}, enc.Wire{enc.Buffer("\x0a")}, sig.NewSha256Signer())
		require.NoError(t, err)
		require.NoError(t, face.FeedPacket(data.Wire.Join()))

		require.Equal(t, 1, hitCnt)
	})
}

// (AI GENERATED DESCRIPTION): Tests that an Interest with CanBePrefix=true can be satisfied by a Data packet with a longer name, while a non‑prefix Interest times out and that a longer Interest without CanBePrefix still matches the same Data packet.
func TestInterestCanBePrefix(t *testing.T) {
	executeTest(t, func(face *face.DummyFace, engine *basic_engine.Engine, timer *basic_engine.DummyTimer) {
		hitCnt := 0

		spec := engine.Spec()
		name1 := tu.NoErr(enc.NameFromStr("/not"))
		name2 := tu.NoErr(enc.NameFromStr("/not/important"))
		config1 := &ndn.InterestConfig{
			Lifetime:    optional.Some(5 * time.Millisecond),
			CanBePrefix: false,
		}
		config2 := &ndn.InterestConfig{
			Lifetime:    optional.Some(5 * time.Millisecond),
			CanBePrefix: true,
		}
		interest1, err := spec.MakeInterest(name1, config1, nil, nil)
		require.NoError(t, err)
		interest2, err := spec.MakeInterest(name1, config2, nil, nil)
		require.NoError(t, err)
		interest3, err := spec.MakeInterest(name2, config1, nil, nil)
		require.NoError(t, err)

		dataWire := []byte("\x06\x1d\x07\x10\x08\x03not\x08\timportant\x14\x03\x18\x01\x00\x15\x04test")

		err = engine.Express(interest1, func(args ndn.ExpressCallbackArgs) {
			hitCnt += 1
			require.Equal(t, ndn.InterestResultTimeout, args.Result)
		})
		require.NoError(t, err)

		err = engine.Express(interest2, func(args ndn.ExpressCallbackArgs) {
			hitCnt += 1
			require.Equal(t, ndn.InterestResultData, args.Result)
			require.True(t, args.Data.Name().Equal(name2))
			require.Equal(t, []byte("test"), args.Data.Content().Join())
			require.Equal(t, dataWire, args.RawData.Join())
		})
		require.NoError(t, err)

		err = engine.Express(interest3, func(args ndn.ExpressCallbackArgs) {
			hitCnt += 1
			require.Equal(t, ndn.InterestResultData, args.Result)
			require.True(t, args.Data.Name().Equal(name2))
			require.Equal(t, []byte("test"), args.Data.Content().Join())
			require.Equal(t, dataWire, args.RawData.Join())
		})
		require.NoError(t, err)

		buf := tu.NoErr(face.Consume())
		require.Equal(t, enc.Buffer("\x05\x0a\x07\x05\x08\x03not\x0c\x01\x05"), buf)
		buf = tu.NoErr(face.Consume())
		require.Equal(t, enc.Buffer("\x05\x0c\x07\x05\x08\x03not\x21\x00\x0c\x01\x05"), buf)
		buf = tu.NoErr(face.Consume())
		require.Equal(t, enc.Buffer("\x05\x15\x07\x10\x08\x03not\x08\timportant\x0c\x01\x05"), buf)

		timer.MoveForward(4 * time.Millisecond)
		require.NoError(t, face.FeedPacket(dataWire))
		require.Equal(t, 2, hitCnt)
		timer.MoveForward(1 * time.Second)
		require.Equal(t, 3, hitCnt)
	})
}

// (AI GENERATED DESCRIPTION): Tests that interests addressed by an implicit SHA‑256 digest name match the correct Data packet and return its content, while a non‑matching digest results in a timeout.
func TestImplicitSha256(t *testing.T) {
	executeTest(t, func(face *face.DummyFace, engine *basic_engine.Engine, timer *basic_engine.DummyTimer) {
		hitCnt := 0

		spec := engine.Spec()
		name1 := tu.NoErr(enc.NameFromStr(
			"/test/sha256digest=FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"))
		name2 := tu.NoErr(enc.NameFromStr(
			"/test/sha256digest=5488f2c11b566d49e9904fb52aa6f6f9e66a954168109ce156eea2c92c57e4c2"))
		config := &ndn.InterestConfig{
			Lifetime: optional.Some(5 * time.Millisecond),
		}
		interest1, err := spec.MakeInterest(name1, config, nil, nil)
		require.NoError(t, err)
		interest2, err := spec.MakeInterest(name2, config, nil, nil)
		require.NoError(t, err)

		err = engine.Express(interest1, func(args ndn.ExpressCallbackArgs) {
			hitCnt += 1
			require.Equal(t, ndn.InterestResultTimeout, args.Result)
		})
		require.NoError(t, err)
		err = engine.Express(interest2, func(args ndn.ExpressCallbackArgs) {
			hitCnt += 1
			require.Equal(t, ndn.InterestResultData, args.Result)
			require.True(t, args.Data.Name().Equal(tu.NoErr(enc.NameFromStr("/test"))))
			require.Equal(t, []byte("test"), args.Data.Content().Join())
		})
		require.NoError(t, err)

		buf := tu.NoErr(face.Consume())
		require.Equal(t, enc.Buffer(
			"\x05\x2d\x07\x28\x08\x04test\x01\x20"+
				"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"+
				"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"+
				"\x0c\x01\x05",
		), buf)
		buf = tu.NoErr(face.Consume())
		require.Equal(t, enc.Buffer(
			"\x05\x2d\x07\x28\x08\x04test\x01\x20"+
				"\x54\x88\xf2\xc1\x1b\x56\x6d\x49\xe9\x90\x4f\xb5\x2a\xa6\xf6\xf9"+
				"\xe6\x6a\x95\x41\x68\x10\x9c\xe1\x56\xee\xa2\xc9\x2c\x57\xe4\xc2"+
				"\x0c\x01\x05",
		), buf)

		timer.MoveForward(4 * time.Millisecond)
		require.NoError(t, face.FeedPacket(
			enc.Buffer("\x06\x13\x07\x06\x08\x04test\x14\x03\x18\x01\x00\x15\x04test"),
		))
		require.Equal(t, 1, hitCnt)
		timer.MoveForward(1 * time.Second)
		require.Equal(t, 2, hitCnt)
	})
}

// No need to test AppParam for expression. If `spec.MakeInterest` works, `engine.Express` will.

// (AI GENERATED DESCRIPTION): Tests that an Interest matching a registered prefix (`/not`) is routed to its handler, which verifies the Interest and replies with a correctly‑encoded Data packet containing the string “test”.
func TestRoute(t *testing.T) {
	executeTest(t, func(face *face.DummyFace, engine *basic_engine.Engine, timer *basic_engine.DummyTimer) {
		hitCnt := 0
		spec := engine.Spec()

		handler := func(args ndn.InterestHandlerArgs) {
			hitCnt += 1
			require.Equal(t, []byte(
				"\x05\x15\x07\x10\x08\x03not\x08\timportant\x0c\x01\x05",
			), args.RawInterest.Join())
			require.True(t, args.Interest.Signature().SigType() == ndn.SignatureNone)
			data, err := spec.MakeData(
				args.Interest.Name(),
				&ndn.DataConfig{
					ContentType: optional.Some(ndn.ContentTypeBlob),
				},
				enc.Wire{[]byte("test")},
				sig.NewTestSigner(enc.Name{}, 0))
			require.NoError(t, err)
			args.Reply(data.Wire)
		}

		prefix := tu.NoErr(enc.NameFromStr("/not"))
		engine.AttachHandler(prefix, handler)
		face.FeedPacket([]byte("\x05\x15\x07\x10\x08\x03not\x08\timportant\x0c\x01\x05"))
		require.Equal(t, 1, hitCnt)
		buf := tu.NoErr(face.Consume())
		require.Equal(t, enc.Buffer(
			"\x06\x22\x07\x10\x08\x03not\x08\timportant\x14\x03\x18\x01\x00\x15\x04test"+
				"\x16\x03\x1b\x01\xc8",
		), buf)
	})
}

// (AI GENERATED DESCRIPTION): Tests that an Interest matching a registered prefix correctly invokes its handler, which replies with a signed Data packet containing the string “test”, verifying that the PIT token is processed and the generated packet matches the expected format.
func TestPitToken(t *testing.T) {
	executeTest(t, func(face *face.DummyFace, engine *basic_engine.Engine, timer *basic_engine.DummyTimer) {
		hitCnt := 0
		spec := engine.Spec()

		handler := func(args ndn.InterestHandlerArgs) {
			hitCnt += 1
			data, err := spec.MakeData(
				args.Interest.Name(),
				&ndn.DataConfig{
					ContentType: optional.Some(ndn.ContentTypeBlob),
				},
				enc.Wire{[]byte("test")},
				sig.NewTestSigner(enc.Name{}, 0))
			require.NoError(t, err)
			args.Reply(data.Wire)
		}

		prefix := tu.NoErr(enc.NameFromStr("/not"))
		engine.AttachHandler(prefix, handler)
		face.FeedPacket([]byte(
			"\x64\x1f\x62\x04\x01\x02\x03\x04\x50\x17" +
				"\x05\x15\x07\x10\x08\x03not\x08\timportant\x0c\x01\x05",
		))
		buf := tu.NoErr(face.Consume())
		require.Equal(t, enc.Buffer(
			"\x64\x2c\x62\x04\x01\x02\x03\x04\x50\x24"+
				"\x06\x22\x07\x10\x08\x03not\x08\timportant\x14\x03\x18\x01\x00\x15\x04test"+
				"\x16\x03\x1b\x01\xc8",
		), buf)
	})
}
