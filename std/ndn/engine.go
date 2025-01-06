package ndn

import (
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
)

// Engine represents a running NDN App low-level engine.
// Used by NTSchema.
type Engine interface {
	// EngineTrait is the type trait of the NDN engine.
	EngineTrait() Engine
	// Spec returns an NDN packet specification.
	Spec() Spec
	// Timer returns a Timer managed by the engine.
	Timer() Timer

	// Start processing packets. Should not block.
	Start() error
	// Stops processing packets.
	Stop() error
	// Checks if the engine is running.
	IsRunning() bool

	// AttachHandler attaches an Interest handler to the namespace of prefix.
	AttachHandler(prefix enc.Name, handler InterestHandler) error
	// DetachHandler detaches an Interest handler from the namespace of prefix.
	DetachHandler(prefix enc.Name) error

	// Express expresses an Interest, with callback called when there is result.
	// To simplify the implementation, finalName needs to be the final Interest name given by MakeInterest.
	// The callback should create go routine or channel back to another routine to avoid blocking the main thread.
	Express(interest *EncodedInterest, callback ExpressCallbackFunc) error

	// RegisterRoute registers a route of prefix to the local forwarder.
	RegisterRoute(prefix enc.Name) error
	// UnregisterRoute unregisters a route of prefix to the local forwarder.
	UnregisterRoute(prefix enc.Name) error
	// ExecMgmtCmd executes a management command.
	//   args are the control arguments (*mgmt.ControlArgs)
	//   returns response and error if any (*mgmt.ControlResponse, error)
	ExecMgmtCmd(module string, cmd string, args any) (any, error)
}

type Timer interface {
	// Now returns current time.
	Now() time.Time
	// Sleep sleeps for the duration.
	Sleep(time.Duration)
	// Schedule schedules the callback function to be called after the duration,
	// and returns a cancel callback to cancel the scheduled function.
	Schedule(time.Duration, func()) func() error
	// Nonce generates a random nonce.
	Nonce() []byte
}

// ExpressCallbackFunc represents the callback function for Interest expression.
type ExpressCallbackFunc func(args ExpressCallbackArgs)

// ExpressCallbackArgs represents the arguments passed to the ExpressCallbackFunc.
type ExpressCallbackArgs struct {
	Result     InterestResult
	Data       Data
	RawData    enc.Wire
	SigCovered enc.Wire
	NackReason uint64
	Error      error // for InterestResultError
}

// InterestHandler represents the callback function for an Interest handler.
// It should create a go routine to avoid blocking the main thread, if either
// 1) Data is not ready to send; or
// 2) Validation is required.
type InterestHandler func(args InterestHandlerArgs)

// Extra information passed to the InterestHandler
type InterestHandlerArgs struct {
	// Decoded interest packet
	Interest Interest
	// Function to reply to the Interest
	Reply WireReplyFunc
	// Raw Interest packet wire
	RawInterest enc.Wire
	// Signature covered part of the Interest
	SigCovered enc.Wire
	// Deadline of the Interest
	Deadline time.Time
	// PIT token
	PitToken []byte
	// Incoming face ID (if available)
	IncomingFaceId *uint64
}

// ReplyFunc represents the callback function to reply for an Interest.
type WireReplyFunc func(wire enc.Wire) error
