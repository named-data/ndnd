// Package basic gives a default implementation of the Engine interface.
// It only connects to local forwarding node via Unix socket.
package basic

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/engine/face"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
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
	face  face.Face
	timer ndn.Timer

	// fib contains the registered Interest handlers.
	fib *NameTrie[fibEntry]

	// pit contains pending outgoing Interests.
	pit *NameTrie[pitEntry]

	// Since there is only one main coroutine, no need for RW locks.
	fibLock sync.Mutex
	pitLock sync.Mutex

	// log is used to log events, with "module=DefaultEngine". Need apex/log initialized.
	// Use WithField to set "name=".
	log *log.Entry

	// mgmtConf is the configuration for the management protocol.
	mgmtConf *mgmt.MgmtConfig

	// cmdChecker is used to validate NFD management packets.
	cmdChecker ndn.SigChecker
}

func (e *Engine) EngineTrait() ndn.Engine {
	return e
}

func (*Engine) Spec() ndn.Spec {
	return spec.Spec{}
}

func (e *Engine) Timer() ndn.Timer {
	return e.timer
}

func (e *Engine) AttachHandler(prefix enc.Name, handler ndn.InterestHandler) error {
	e.fibLock.Lock()
	defer e.fibLock.Unlock()
	n := e.fib.MatchAlways(prefix)
	if n.Value() != nil {
		return ndn.ErrMultipleHandlers
	}
	n.SetValue(handler)
	return nil
}

func (e *Engine) DetachHandler(prefix enc.Name) error {
	e.fibLock.Lock()
	defer e.fibLock.Unlock()

	n := e.fib.ExactMatch(prefix)
	if n == nil {
		return ndn.ErrInvalidValue{Item: "prefix", Value: prefix}
	}
	n.Delete()
	return nil
}

func (e *Engine) onPacket(reader enc.ParseReader) error {
	var nackReason uint64 = spec.NackReasonNone
	var pitToken []byte = nil
	var incomingFaceId *uint64 = nil
	var raw enc.Wire = nil

	if e.log.Level <= log.TraceLevel {
		wire := reader.Range(0, reader.Length())
		e.log.Tracef("Received packet bytes: %v", wire.Join())
	}

	pkt, ctx, err := spec.ReadPacket(reader)
	if err != nil {
		e.log.Errorf("Failed to parse packet: %v", err)
		// Recoverable error. Should continue.
		return nil
	}
	// Now, exactly one of Interest, Data, LpPacket is not nil
	// First check LpPacket, and do further parse.
	if pkt.LpPacket != nil {
		lpPkt := pkt.LpPacket
		if lpPkt.FragIndex != nil || lpPkt.FragCount != nil {
			e.log.Warnf("Fragmented LpPackets are not supported. Drop.")
			return nil
		}
		// Parse the inner packet.
		raw = pkt.LpPacket.Fragment
		if len(raw) == 1 {
			pkt, ctx, err = spec.ReadPacket(enc.NewBufferReader(raw[0]))
		} else {
			pkt, ctx, err = spec.ReadPacket(enc.NewWireReader(raw))
		}
		if err != nil || (pkt.Data == nil) == (pkt.Interest == nil) {
			e.log.Errorf("Failed to parse packet in LpPacket: %v", err)
			if e.log.Level <= log.TraceLevel {
				wire := reader.Range(0, reader.Length())
				e.log.Tracef("Failed packet bytes: %v", wire.Join())
			}
			// Recoverable error. Should continue.
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
			e.log.Errorf("Received nack for an Data")
			return nil
		}
		if e.log.Level <= log.TraceLevel {
			e.log.WithField("name", pkt.Interest.NameV.String()).
				Tracef("Nack received for %v", nackReason)
		}
		e.onNack(pkt.Interest.NameV, nackReason)
	} else if pkt.Interest != nil {
		if e.log.Level <= log.TraceLevel {
			e.log.WithField("name", pkt.Interest.NameV.String()).
				Trace("Interest received.")
		}
		e.onInterest(ndn.InterestHandlerArgs{
			Interest:       pkt.Interest,
			RawInterest:    raw,
			SigCovered:     ctx.Interest_context.SigCovered(),
			PitToken:       pitToken,
			IncomingFaceId: incomingFaceId,
		})
	} else if pkt.Data != nil {
		if e.log.Level <= log.TraceLevel {
			e.log.WithField("name", pkt.Data.NameV.String()).
				Trace("Data received.")
		}
		// PitToken is not used for now
		e.onData(pkt.Data, ctx.Data_context.SigCovered(), raw, pitToken)
	} else {
		log.Fatalf("Unreachable. Check spec implementation.")
	}
	return nil
}

func (e *Engine) onInterest(args ndn.InterestHandlerArgs) {
	name := args.Interest.Name()

	// Compute deadline
	args.Deadline = e.timer.Now()
	if args.Interest.Lifetime() != nil {
		args.Deadline = args.Deadline.Add(*args.Interest.Lifetime())
	} else {
		args.Deadline = args.Deadline.Add(DefaultInterestLife)
	}

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
		e.log.WithField("name", name.String()).Warn("No handler. Drop.")
		return
	}

	// The reply callback function
	args.Reply = func(encodedData enc.Wire) error {
		now := e.timer.Now()
		if args.Deadline.Before(now) {
			e.log.WithField("name", name).Warn("Deadline exceeded. Drop.")
			return ndn.ErrDeadlineExceed
		}
		if !e.face.IsRunning() {
			e.log.WithField("name", name).Error("Cannot send through a closed face. Drop.")
			return ndn.ErrFaceDown
		}
		if args.PitToken != nil {
			lpPkt := &spec.Packet{
				LpPacket: &spec.LpPacket{
					PitToken: args.PitToken,
					Fragment: encodedData,
				},
			}
			encoder := spec.PacketEncoder{}
			encoder.Init(lpPkt)
			wire := encoder.Encode(lpPkt)
			if wire == nil {
				return ndn.ErrFailedToEncode
			}
			return e.face.Send(wire)
		} else {
			return e.face.Send(encodedData)
		}
	}

	// Call the handler. The handler should create goroutine to avoid blocking.
	// Do not `go` here because if Data is ready at hand, creating a go routine may be slower. Not tested though.
	handler(args)
}

func (e *Engine) onData(pkt *spec.Data, sigCovered enc.Wire, raw enc.Wire, pitToken []byte) {
	e.pitLock.Lock()
	defer e.pitLock.Unlock()

	n := e.pit.PrefixMatch(pkt.NameV)
	if n == nil {
		e.log.WithField("name", pkt.NameV.String()).Warn("Received Data for an unknown interest. Drop.")
		return
	}

	for cur := n; cur != nil; cur = cur.Parent() {
		curListSize := len(cur.Value())
		if curListSize <= 0 {
			continue
		}

		newList := make([]*pendInt, 0, curListSize)
		for _, entry := range cur.Value() {
			// we don't check MustBeFresh, as it is the job of the cache/forwarder.

			// check CanBePrefix
			if cur.Depth() < len(pkt.NameV) && !entry.canBePrefix {
				newList = append(newList, entry)
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
					newList = append(newList, entry)
					continue
				}
			}

			// entry satisfied
			entry.timeoutCancel()
			if entry.callback == nil {
				panic("[BUG] PIT has empty entry")
			}

			entry.callback(ndn.ExpressCallbackArgs{
				Result:     ndn.InterestResultData,
				Data:       pkt,
				RawData:    raw,
				SigCovered: sigCovered,
				NackReason: spec.NackReasonNone,
			})
		}

		cur.SetValue(newList)
	}

	n.DeleteIf(func(lst []*pendInt) bool {
		return len(lst) == 0
	})
}

func (e *Engine) onNack(name enc.Name, reason uint64) {
	e.pitLock.Lock()
	defer e.pitLock.Unlock()
	n := e.pit.ExactMatch(name)
	if n == nil {
		e.log.WithField("name", name.String()).Warn("Received Nack for an unknown interest. Drop.")
		return
	}
	for _, entry := range n.Value() {
		entry.timeoutCancel()
		if entry.callback != nil {
			entry.callback(ndn.ExpressCallbackArgs{
				Result:     ndn.InterestResultNack,
				NackReason: reason,
			})
		} else {
			e.log.Fatalf("PIT has empty entry. This should not happen. Please check the implementation.")
		}
	}
	n.Delete()
}

func (e *Engine) onError(err error) error {
	e.log.Errorf("error on face, quit: %v", err)
	// TODO: Handle Interest cancellation
	return err
}

func (e *Engine) Start() error {
	if e.face.IsRunning() {
		return errors.New("face is already running")
	}
	e.face.SetCallback(e.onPacket, e.onError)
	err := e.face.Open()
	if err != nil {
		return err
	}
	return nil
}

func (e *Engine) Stop() error {
	if !e.face.IsRunning() {
		return errors.New("face is not running")
	}
	return e.face.Close()
}

func (e *Engine) IsRunning() bool {
	return e.face.IsRunning()
}

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
	lifetime := DefaultInterestLife
	if interest.Config.Lifetime != nil {
		lifetime = *interest.Config.Lifetime
	}
	deadline := e.timer.Now().Add(lifetime)

	// Inject interest into PIT
	func() {
		e.pitLock.Lock()
		defer e.pitLock.Unlock()

		n := e.pit.MatchAlways(nodeName)
		timeoutFunc := func() {
			e.pitLock.Lock()
			defer e.pitLock.Unlock()
			now := e.timer.Now()
			lst := n.Value()
			newLst := make([]*pendInt, 0, len(lst))
			for _, entry := range lst {
				if entry.deadline.After(now) {
					newLst = append(newLst, entry)
				} else {
					if entry.callback != nil {
						entry.callback(ndn.ExpressCallbackArgs{
							Result:     ndn.InterestResultTimeout,
							NackReason: spec.NackReasonNone,
						})
					} else {
						e.log.Fatalf("PIT has empty entry. This should not happen. Please check the implementation.")
					}
				}
			}
			n.SetValue(newLst)
			n.DeleteIf(func(lst []*pendInt) bool {
				return len(lst) == 0
			})
		}
		entry := &pendInt{
			callback:      callback,
			deadline:      deadline,
			canBePrefix:   interest.Config.CanBePrefix,
			mustBeFresh:   interest.Config.MustBeFresh,
			impSha256:     impSha256,
			timeoutCancel: e.timer.Schedule(lifetime+TimeoutMargin, timeoutFunc),
		}
		n.SetValue(append(n.Value(), entry))
	}()

	// Send interest
	err := e.face.Send(interest.Wire)
	if err != nil {
		e.log.Errorf("Failed to send Interest: %v", err)
	} else if e.log.Level <= log.TraceLevel {
		e.log.WithField("name", finalName.String()).
			Trace("Interest sent.")
	}

	return err
}

func (e *Engine) ExecMgmtCmd(module string, cmd string, args any) (any, error) {
	cmdArgs, ok := args.(*mgmt.ControlArgs)
	if !ok {
		return nil, ndn.ErrInvalidValue{Item: "args", Value: args}
	}

	intCfg := &ndn.InterestConfig{
		Lifetime: utils.IdPtr(1 * time.Second),
		Nonce:    utils.ConvertNonce(e.timer.Nonce()),
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
				ret, err := mgmt.ParseControlResponse(enc.NewWireReader(data.Content()), true)
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

func (e *Engine) RegisterRoute(prefix enc.Name) error {
	_, err := e.ExecMgmtCmd("rib", "register", &mgmt.ControlArgs{Name: prefix})
	if err != nil {
		e.log.WithField("name", prefix.String()).
			Errorf("Failed to register prefix: %v", err)
		return err
	} else {
		e.log.WithField("name", prefix.String()).
			Info("Prefix registered.")
	}
	return nil
}

func (e *Engine) UnregisterRoute(prefix enc.Name) error {
	_, err := e.ExecMgmtCmd("rib", "unregister", &mgmt.ControlArgs{Name: prefix})
	if err != nil {
		e.log.WithField("name", prefix.String()).
			Errorf("Failed to register prefix: %v", err)
		return err
	} else {
		e.log.WithField("name", prefix.String()).
			Info("Prefix registered.")
	}
	return nil
}

func NewEngine(face face.Face, timer ndn.Timer, cmdSigner ndn.Signer, cmdChecker ndn.SigChecker) *Engine {
	if face == nil || timer == nil || cmdSigner == nil || cmdChecker == nil {
		return nil
	}
	logger := log.WithField("module", "basic_engine")
	logger.Level = log.InfoLevel
	mgmtCfg := mgmt.NewConfig(face.IsLocal(), cmdSigner, spec.Spec{})
	return &Engine{
		face:       face,
		timer:      timer,
		mgmtConf:   mgmtCfg,
		cmdChecker: cmdChecker,
		log:        logger,
		fib:        NewNameTrie[fibEntry](),
		pit:        NewNameTrie[pitEntry](),
		fibLock:    sync.Mutex{},
		pitLock:    sync.Mutex{},
	}
}
