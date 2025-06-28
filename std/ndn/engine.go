package ndn

import (
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/types/optional"
)

// Engine represents a running NDN App low-level engine.
// Used by NTSchema.
type Engine interface {
	// String is the instance log identifier.
	String() string
	// EngineTrait is the type trait of the NDN engine.
	EngineTrait() Engine
	// Spec returns an NDN packet specification.
	Spec() Spec
	// Timer returns a Timer managed by the engine.
	Timer() Timer
	// Face returns the face of the engine.
	Face() Face

	// Start processing packets.
	// If the engine is attached to a face, this will attempt
	// to open the face, and may block until the face is up.
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

	// ExecMgmtCmd executes a management command.
	//   args are the control arguments (*mgmt.ControlArgs)
	//   returns response and error if any (*mgmt.ControlResponse, error)
	ExecMgmtCmd(module string, cmd string, args any) (any, error)
	// SetCmdSec sets the interest signing parameters for management commands.
	SetCmdSec(signer Signer, validator func(enc.Name, enc.Wire, Signature) bool)
	// RegisterRoute registers a route of prefix to the local forwarder.
	RegisterRoute(prefix enc.Name) error
	// UnregisterRoute unregisters a route of prefix to the local forwarder.
	UnregisterRoute(prefix enc.Name) error

	// Post a task to the engine goroutine (internal usage only).
	// Be careful not to deadlock the engine.
	Post(func())
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
	// Result of the Interest expression.
	// If the result is not InterestResultData, Data fields are invalid.
	Result InterestResult
	// Data fetched.
	Data Data
	// Raw Data wire.
	RawData enc.Wire
	// Signature covered part of the Data.
	SigCovered enc.Wire
	// NACK reason code, if the result is InterestResultNack.
	NackReason uint64
	// Error, if the result is InterestResultError.
	Error error
	// IsLocal indicates if a local copy of the Data was found.
	// e.g. returned by ExpressR when used with TryStore.
	IsLocal bool
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
	IncomingFaceId optional.Optional[uint64]
}

// ReplyFunc represents the callback function to reply for an Interest.
type WireReplyFunc func(wire enc.Wire) error
