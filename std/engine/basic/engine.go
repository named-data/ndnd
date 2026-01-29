// Package basic gives a default implementation of the Engine interface.
// It only connects to local forwarding node via Unix socket.
package basic

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	sig "github.com/named-data/ndnd/std/security/signer"
	"github.com/named-data/ndnd/std/types/optional"
	"github.com/named-data/ndnd/std/utils"
)

const DefaultInterestLife = 4 * time.Second
const TimeoutMargin = 10 * time.Millisecond

type fibEntry = ndn.InterestHandler

type pendInt struct {
	callback    ndn.ExpressCallbackFunc
	deadline    time.Time
	canBePrefix bool
	// mustBeFresh is actually not useful, since Freshness is decided by the cache, not us.
	mustBeFresh   bool
	impSha256     []byte
	timeoutCancel func() error
}

type pitEntry = []*pendInt

type Engine struct {
	face  ndn.Face
	timer ndn.Timer

	// fib contains the registered Interest handlers.
	fib *NameTrie[fibEntry]
	// pit contains pending outgoing Interests.
	pit *NameTrie[pitEntry]

	// Since there is only one main coroutine, no need for RW locks.
	fibLock sync.Mutex
	pitLock sync.Mutex

	// mgmtConf is the configuration for the management protocol.
	mgmtConf *mgmt.MgmtConfig
	// cmdChecker is used to validate NFD management packets.
	cmdChecker ndn.SigChecker

	// inQueue is the incoming packet queue.
	// The face will be blocked when the queue is full.
	inQueue chan []byte
	// taskQueue is the task queue for the main goroutine.
	taskQueue chan func()
	// close is the channel to signal the main goroutine to stop.
	close chan struct{}
	// running is the flag to indicate if the engine is running.
	running atomic.Bool

	// (advanced usage) global hook on receiving data packets
	OnDataHook func(data ndn.Data, raw enc.Wire, sigCov enc.Wire) error
}

// (AI GENERATED DESCRIPTION): Creates and initializes a new Engine instance, wiring the given face and timer into its state and setting up all internal data structures, locks, queues, and configuration needed for packet processing.
func NewEngine(face ndn.Face, timer ndn.Timer) *Engine {
	if face == nil || timer == nil {
		return nil
	}
	mgmtCfg := mgmt.NewConfig(face.IsLocal(), sig.NewSha256Signer(), spec.Spec{})
	return &Engine{
		face:  face,
		timer: timer,

		fib: NewNameTrie[fibEntry](),
		pit: NewNameTrie[pitEntry](),

		fibLock: sync.Mutex{},
		pitLock: sync.Mutex{},

		mgmtConf:   mgmtCfg,
		cmdChecker: func(enc.Name, enc.Wire, ndn.Signature) bool { return true },

		inQueue:   make(chan []byte, 256),
		taskQueue: make(chan func(), 512),
		close:     make(chan struct{}),
		running:   atomic.Bool{},
	}
}

// (AI GENERATED DESCRIPTION): Returns the fixed string `"basic-engine"` as the Engine’s string representation.
func (e *Engine) String() string {
	return "basic-engine"
}

// (AI GENERATED DESCRIPTION): Returns the Engine instance itself as an ndn.Engine.
func (e *Engine) EngineTrait() ndn.Engine {
	return e
}

// (AI GENERATED DESCRIPTION): Returns the engine’s NDN specification, which is currently an empty `spec.Spec` instance.
func (*Engine) Spec() ndn.Spec {
	return spec.Spec{}
}

// (AI GENERATED DESCRIPTION): Returns the `ndn.Timer` instance used by the Engine.
func (e *Engine) Timer() ndn.Timer {
	return e.timer
}

// (AI GENERATED DESCRIPTION): Returns the ndn.Face instance that the Engine uses for communication.
func (e *Engine) Face() ndn.Face {
	return e.face
}

// (AI GENERATED DESCRIPTION): Registers an `InterestHandler` for a given name prefix in the Engine’s FIB, rejecting the operation if a handler is already attached for that prefix.
func (e *Engine) AttachHandler(prefix enc.Name, handler ndn.InterestHandler) error {
	e.fibLock.Lock()
	defer e.fibLock.Unlock()
	n := e.fib.MatchAlways(prefix)
	if n.Value() != nil {
		return fmt.Errorf("%w: %s", ndn.ErrMultipleHandlers, prefix)
	}
	n.SetValue(handler)
	return nil
}

// (AI GENERATED DESCRIPTION): Detaches the handler associated with the specified prefix by removing the corresponding FIB entry.
func (e *Engine) DetachHandler(prefix enc.Name) error {
	e.fibLock.Lock()
	defer e.fibLock.Unlock()

	n := e.fib.ExactMatch(prefix)
	if n == nil {
		return ndn.ErrInvalidValue{Item: "prefix", Value: prefix}
	}
	n.SetValue(nil)
	n.Prune()
	return nil
}

// (AI GENERATED DESCRIPTION): Parses an incoming packet frame (handling optional LP encapsulation), determines whether it carries an Interest, Data, or Nack, and forwards the packet to the appropriate engine handler.
func (e *Engine) onPacket(frame []byte) error {
	reader := enc.NewBufferView(frame)

	var nackReason uint64 = spec.NackReasonNone
	var pitToken []byte = nil
	var incomingFaceId optional.Optional[uint64]
	var raw enc.Wire = nil

	if hasLogTrace() {
		wire := reader.Range(0, reader.Length())
		log.Trace(e, "Received packet bytes", "wire", hex.EncodeToString(wire.Join()))
	}

	// Parse the outer packet - could be either L2 or L3
	pkt, ctx, err := spec.ReadPacket(reader)
	if err != nil {
		// Recoverable error. Should continue.
		log.Error(e, "Failed to parse packet", "err", err)
		return nil
	}

	// Now, exactly one of Interest, Data, LpPacket is not nil
	// First check LpPacket, and do further parse.
	if pkt.LpPacket != nil {
		lpPkt := pkt.LpPacket
		if lpPkt.FragIndex.IsSet() || lpPkt.FragCount.IsSet() {
			log.Warn(e, "Fragmented LpPackets are not supported - DROP")
			return nil
		}

		// Parse the inner packet.
		raw = pkt.LpPacket.Fragment
		if len(raw) == 1 {
			pkt, ctx, err = spec.ReadPacket(enc.NewBufferView(raw[0]))
		} else {
			pkt, ctx, err = spec.ReadPacket(enc.NewWireView(raw))
		}

		// Make sure there is an inner packet.
		if err != nil || (pkt.Data == nil) == (pkt.Interest == nil) {
			if hasLogTrace() {
				wire := reader.Range(0, reader.Length())
				log.Trace(e, "Failed to parse packet bytes", "wire", hex.EncodeToString(wire.Join()))
			}

			// Recoverable error. Should continue.
			log.Error(e, "Failed to parse packet in LpPacket", "err", err)
			return nil
		}

		// Set parameters
		if lpPkt.Nack != nil {
			nackReason = lpPkt.Nack.Reason
		}
		pitToken = lpPkt.PitToken
		incomingFaceId = lpPkt.IncomingFaceId
	} else {
		raw = reader.Range(0, reader.Length())
	}

	// Now pkt is either Data or Interest (including Nack).
	if nackReason != spec.NackReasonNone {
		if pkt.Interest == nil {
			log.Error(e, "Nack received for non-Interest", "reason", nackReason)
			return nil
		}
		log.Trace(e, "Nack received", "reason", nackReason, "name", pkt.Interest.Name())
		e.onNack(pkt.Interest.NameV, nackReason)
	} else if pkt.Interest != nil {
		log.Trace(e, "Interest received", "name", pkt.Interest.Name())
		e.onInterest(ndn.InterestHandlerArgs{
			Interest:       pkt.Interest,
			RawInterest:    raw,
			SigCovered:     ctx.Interest_context.SigCovered(),
			PitToken:       pitToken,
			IncomingFaceId: incomingFaceId,
		})
	} else if pkt.Data != nil {
		log.Trace(e, "Data received", "name", pkt.Data.Name())
		// PitToken is not used for now
		e.onData(pkt.Data, ctx.Data_context.SigCovered(), raw, pitToken)
	} else {
		panic("[BUG] unexpected packet type") // checked above
	}

	return nil
}

// (AI GENERATED DESCRIPTION): Processes an incoming Interest by computing its deadline, performing a longest‑prefix FIB lookup to obtain the appropriate handler, attaching a reply callback, and invoking that handler.
func (e *Engine) onInterest(args ndn.InterestHandlerArgs) {
	name := args.Interest.Name()

	// Compute deadline
	args.Deadline = e.timer.Now().Add(
		args.Interest.Lifetime().GetOr(DefaultInterestLife))

	// Match node
	handler := func() ndn.InterestHandler {
		e.fibLock.Lock()
		defer e.fibLock.Unlock()
		n := e.fib.PrefixMatch(name)

		// If we have the prefix-free condition, we can return the value here
		// directly. But we need longest prefix match now.
		// return n.Value()

		for n != nil && n.Value() == nil {
			n = n.Parent()
		}
		if n != nil {
			return n.Value()
		}
		return nil
	}()
	if handler == nil {
		log.Warn(e, "No handler for interest", "name", name)
		return
	}

	// The reply callback function
	args.Reply = e.newDataReplyFunc(args.PitToken)

	// Call the handler. The handler should create goroutine to avoid blocking.
	// Do not `go` here because if Data is ready at hand, creating a goroutine is slower.
	handler(args)
}

// (AI GENERATED DESCRIPTION): Creates a reply function that forwards a Data packet (or nil) over the engine’s face, optionally wrapping it in an LP packet with the supplied PIT token, and returns any send errors.
func (e *Engine) newDataReplyFunc(pitToken []byte) ndn.WireReplyFunc {
	return func(dataWire enc.Wire) error {
		if dataWire == nil {
			return nil
		}

		// Check if the face is running
		if !e.IsRunning() || !e.face.IsRunning() {
			return ndn.ErrFaceDown
		}

		// Outgoing packet
		var outWire enc.Wire = dataWire

		// Wrap the data in LP packet if needed
		if pitToken != nil {
			lpPkt := &spec.Packet{
				LpPacket: &spec.LpPacket{
					PitToken: pitToken,
					Fragment: dataWire,
				},
			}
			encoder := spec.PacketEncoder{}
			encoder.Init(lpPkt)
			wire := encoder.Encode(lpPkt)
			if wire == nil {
				log.Error(e, "[BUG] Failed to encode LP packet")
			} else {
				outWire = wire
			}
		}

		return e.face.Send(outWire)
	}
}

// (AI GENERATED DESCRIPTION): Matches an incoming Data packet against the Pending Interest Table, removes any pending interests that satisfy the packet’s name, CanBePrefix, and implicit digest constraints, and returns those matched entries.
func (e *Engine) onDataMatch(pkt *spec.Data, raw enc.Wire) pitEntry {
	e.pitLock.Lock()
	defer e.pitLock.Unlock()

	n := e.pit.PrefixMatch(pkt.NameV)
	if n == nil {
		log.Warn(e, "Received data for an unknown interest - DROP", "name", pkt.Name())
		return nil
	}

	ret := make(pitEntry, 0, 4)
	for cur := n; cur != nil; cur = cur.Parent() {
		entries := cur.Value()
		for i := 0; i < len(entries); i++ {
			entry := entries[i]

			// we don't check MustBeFresh, as it is the job of the cache/forwarder.
			// check CanBePrefix
			if cur.Depth() < len(pkt.NameV) && !entry.canBePrefix {
				continue
			}

			// check ImplicitDigest256
			if entry.impSha256 != nil {
				h := sha256.New()
				for _, buf := range raw {
					h.Write(buf)
				}
				digest := h.Sum(nil)
				if !bytes.Equal(entry.impSha256, digest) {
					continue
				}
			}

			// pop entry
			entries[i] = entries[len(entries)-1]
			entries = entries[:len(entries)-1]
			i-- // recheck the current index
			ret = append(ret, entry)
		}
		cur.SetValue(entries)
	}

	n.PruneIf(func(lst []*pendInt) bool { return len(lst) == 0 })

	return ret
}

// (AI GENERATED DESCRIPTION): Processes a received Data packet by invoking the optional OnDataHook, matching pending PIT entries, canceling their timeouts, and invoking each matched entry’s callback with either the Data payload (or raw data) or an error if the hook failed.
func (e *Engine) onData(pkt *spec.Data, sigCovered enc.Wire, raw enc.Wire, pitToken []byte) {
	var hookErr error = nil
	if e.OnDataHook != nil {
		hookErr = e.OnDataHook(pkt, raw, sigCovered)
	}

	for _, entry := range e.onDataMatch(pkt, raw) {
		entry.timeoutCancel()
		if entry.callback == nil {
			panic("[BUG] PIT has empty entry")
		}

		if hookErr != nil {
			entry.callback(ndn.ExpressCallbackArgs{
				Result: ndn.InterestResultError,
				Error:  hookErr,
			})
			continue
		}

		entry.callback(ndn.ExpressCallbackArgs{
			Result:     ndn.InterestResultData,
			Data:       pkt,
			RawData:    raw,
			SigCovered: sigCovered,
			NackReason: spec.NackReasonNone,
		})
	}
}

// (AI GENERATED DESCRIPTION): Handles an Interest Nack by finding the matching PIT entries, cancelling their timeouts, and invoking each entry’s callback with the Nack reason.
func (e *Engine) onNack(name enc.Name, reason uint64) {
	entries := func() []*pendInt {
		e.pitLock.Lock()
		defer e.pitLock.Unlock()

		n := e.pit.ExactMatch(name)
		if n == nil {
			log.Warn(e, "Received Nack for an unknown interest - DROP", "name", name)
			return nil
		}

		ret := n.Value()
		n.SetValue(nil)
		n.Prune()
		return ret
	}()

	for _, entry := range entries {
		entry.timeoutCancel()

		if entry.callback == nil {
			panic("[BUG] PIT has empty entry")
		}

		entry.callback(ndn.ExpressCallbackArgs{
			Result:     ndn.InterestResultNack,
			NackReason: reason,
		})
	}
}

// (AI GENERATED DESCRIPTION): Starts the engine by opening its face, registering packet and error callbacks, and launching a goroutine that processes received packets and queued tasks until the engine is stopped.
func (e *Engine) Start() error {
	if e.face.IsRunning() {
		return fmt.Errorf("face is already running")
	}

	e.face.OnPacket(func(frame []byte) {
		// Copy received buffer from face so face can reuse it
		frameCopy := make([]byte, len(frame))
		copy(frameCopy, frame)
		e.inQueue <- frameCopy
	})
	e.face.OnError(func(err error) {
		log.Error(e, "Error on face", "err", err, "face", e.face)
		e.Stop()
	})

	err := e.face.Open()
	if err != nil {
		return err
	}

	e.running.Store(true)
	go func() {
		defer e.face.Close()
		defer e.running.Store(false)

		for {
			select {
			case frame := <-e.inQueue:
				err := e.onPacket(frame)
				if err != nil {
					// This never really happens.
					log.Error(e, "[BUG] Engine::onPacket error", "err", err)
				}
			case <-e.close:
				return
			case task := <-e.taskQueue:
				task()
			}
		}
	}()

	return nil
}

// (AI GENERATED DESCRIPTION): Stops the engine by signaling its close channel (terminating its operation) and returns an error if the engine was not running.
func (e *Engine) Stop() error {
	if !e.IsRunning() {
		return fmt.Errorf("engine is not running")
	}

	e.close <- struct{}{} // closes face too
	return nil
}

// (AI GENERATED DESCRIPTION): **IsRunning** – Returns `true` if the engine is currently running, otherwise `false`.
func (e *Engine) IsRunning() bool {
	return e.running.Load()
}

// (AI GENERATED DESCRIPTION): Handles timeout of pending Interest entries by removing them from the PIT and invoking their callbacks with a timeout result.
func (e *Engine) onExpressTimeout(n *NameTrie[pitEntry]) {
	now := e.timer.Now()

	expired := func() []*pendInt {
		e.pitLock.Lock()
		defer e.pitLock.Unlock()

		ret := make([]*pendInt, 0, 4)
		entries := n.Value()
		for i := 0; i < len(entries); i++ {
			entry := entries[i]
			if entry.deadline.After(now) {
				continue
			}

			// pop entry
			entries[i] = entries[len(entries)-1]
			entries = entries[:len(entries)-1]
			i-- // recheck the current index
			ret = append(ret, entry)
		}

		n.SetValue(entries)
		n.PruneIf(func(lst []*pendInt) bool { return len(lst) == 0 })

		return ret
	}()

	for _, entry := range expired {
		if entry.callback == nil {
			panic("[BUG] PIT has empty entry")
		}

		entry.callback(ndn.ExpressCallbackArgs{
			Result:     ndn.InterestResultTimeout,
			NackReason: spec.NackReasonNone,
		})
	}
}

// (AI GENERATED DESCRIPTION): Expresses an NDN interest by inserting it into the PIT with deadline and callback handling, optionally wrapping it in a link packet, and sending it through the configured face.
func (e *Engine) Express(interest *ndn.EncodedInterest, callback ndn.ExpressCallbackFunc) error {
	var impSha256 []byte = nil

	finalName := interest.FinalName
	nodeName := interest.FinalName

	if callback == nil {
		callback = func(ndn.ExpressCallbackArgs) {}
	}

	// Handle implicit digest
	if len(finalName) <= 0 {
		return ndn.ErrInvalidValue{Item: "finalName", Value: finalName}
	}
	lastComp := finalName[len(finalName)-1]
	if lastComp.Typ == enc.TypeImplicitSha256DigestComponent {
		impSha256 = lastComp.Val
		nodeName = finalName[:len(finalName)-1]
	}

	// Handle deadline
	lifetime := interest.Config.Lifetime.GetOr(DefaultInterestLife)
	deadline := e.timer.Now().Add(lifetime)

	// Inject interest into PIT
	func() {
		e.pitLock.Lock()
		defer e.pitLock.Unlock()

		n := e.pit.MatchAlways(nodeName)
		entry := &pendInt{
			callback:    callback,
			deadline:    deadline,
			canBePrefix: interest.Config.CanBePrefix,
			mustBeFresh: interest.Config.MustBeFresh,
			impSha256:   impSha256,
			timeoutCancel: e.timer.Schedule(lifetime+TimeoutMargin, func() {
				e.onExpressTimeout(n)
			}),
		}
		n.SetValue(append(n.Value(), entry))
	}()

	// Wrap the interest in link packet if needed
	wire := interest.Wire
	if interest.Config.NextHopId.IsSet() {
		lpPkt := &spec.Packet{
			LpPacket: &spec.LpPacket{
				Fragment:      wire,
				NextHopFaceId: interest.Config.NextHopId,
			},
		}
		encoder := spec.PacketEncoder{}
		encoder.Init(lpPkt)
		wire = encoder.Encode(lpPkt)
	}

	// Send interest to face
	err := e.face.Send(wire)
	if err != nil {
		log.Error(e, "Failed to send interest", "err", err)
	}

	log.Trace(e, "Interest sent", "name", finalName)
	return err
}

// (AI GENERATED DESCRIPTION): Executes a named‑data management command by crafting a signed Interest for the specified module and command with the given arguments, sending it, validating the response signature, parsing the control response, and returning the result or an error.
func (e *Engine) ExecMgmtCmd(module string, cmd string, args any) (any, error) {
	cmdArgs, ok := args.(*mgmt.ControlArgs)
	if !ok {
		return nil, ndn.ErrInvalidValue{Item: "args", Value: args}
	}

	intCfg := &ndn.InterestConfig{
		Lifetime:    optional.Some(1 * time.Second),
		Nonce:       utils.ConvertNonce(e.timer.Nonce()),
		MustBeFresh: true,

		// Signed interest shenanigans (NFD wants this)
		SigNonce: e.timer.Nonce(),
		SigTime:  optional.Some(time.Duration(e.timer.Now().UnixMilli()) * time.Millisecond),
	}
	interest, err := e.mgmtConf.MakeCmd(module, cmd, cmdArgs, intCfg)
	if err != nil {
		return nil, err
	}

	type mgmtResp struct {
		err error
		val *mgmt.ControlResponse
	}
	respCh := make(chan *mgmtResp)

	err = e.Express(interest, func(args ndn.ExpressCallbackArgs) {
		resp := &mgmtResp{}
		defer func() {
			respCh <- resp
			close(respCh)
		}()

		if args.Result == ndn.InterestResultNack {
			resp.err = fmt.Errorf("nack received: %v", args.NackReason)
		} else if args.Result == ndn.InterestResultTimeout {
			resp.err = ndn.ErrDeadlineExceed
		} else if args.Result == ndn.InterestResultData {
			data := args.Data
			valid := e.cmdChecker(data.Name(), args.SigCovered, data.Signature())
			if !valid {
				resp.err = fmt.Errorf("command signature is not valid")
			} else {
				ret, err := mgmt.ParseControlResponse(enc.NewWireView(data.Content()), true)
				if err != nil {
					resp.err = err
				} else {
					resp.val = ret
					if ret.Val != nil {
						if ret.Val.StatusCode == 200 {
							return
						} else {
							resp.err = fmt.Errorf("command failed due to error %d: %s",
								ret.Val.StatusCode, ret.Val.StatusText)
						}
					} else {
						resp.err = fmt.Errorf("improper response")
					}
				}
			}
		} else {
			resp.err = fmt.Errorf("unknown result: %v", args.Result)
		}
	})
	if err != nil {
		return nil, err
	}

	resp := <-respCh
	return resp.val, resp.err
}

// (AI GENERATED DESCRIPTION): Sets the Engine’s command security by assigning a signer for management packets and a validator function for checking incoming command signatures.
func (e *Engine) SetCmdSec(signer ndn.Signer, validator func(enc.Name, enc.Wire, ndn.Signature) bool) {
	e.mgmtConf.SetSigner(sig.AsContextSigner(signer))
	e.cmdChecker = validator
}

// (AI GENERATED DESCRIPTION): Registers the supplied name prefix with the engine’s routing information base by issuing a RIB‑management command.
func (e *Engine) RegisterRoute(prefix enc.Name) error {
	_, err := e.ExecMgmtCmd("rib", "register", &mgmt.ControlArgs{Name: prefix})
	if err != nil {
		log.Error(e, "Failed to register prefix", "err", err, "name", prefix)
		return err
	} else {
		log.Debug(e, "Prefix registered", "name", prefix)
	}
	return nil
}

// (AI GENERATED DESCRIPTION): Unregisters the specified NDN prefix from the Engine’s routing information base (RIB) by issuing a management command and logs the result.
func (e *Engine) UnregisterRoute(prefix enc.Name) error {
	_, err := e.ExecMgmtCmd("rib", "unregister", &mgmt.ControlArgs{Name: prefix})
	if err != nil {
		log.Error(e, "Failed to unregister prefix", "err", err, "name", prefix)
		return err
	} else {
		log.Debug(e, "Prefix unregistered", "name", prefix)
	}
	return nil
}

// (AI GENERATED DESCRIPTION): Enqueues a task to the engine's internal task queue, performing a non‑blocking send and spawning a goroutine to enqueue the task if the channel is currently full.
func (e *Engine) Post(task func()) {
	select {
	case e.taskQueue <- task:
	default:
		// Do not block in case this is being called from the
		// main goroutine itself - ideally this never happens.
		go func() { e.taskQueue <- task }()
	}
}

// (AI GENERATED DESCRIPTION): Checks whether the default logger is set to trace level (or more verbose) and returns true if trace logging is enabled.
func hasLogTrace() bool {
	return log.Default().Level() <= log.LevelTrace
}
