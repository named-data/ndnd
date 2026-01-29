package face

import (
	"sync"
	"sync/atomic"
)

// baseFace is the base struct for face implementations.
type baseFace struct {
	running atomic.Bool
	local   bool
	onPkt   func(frame []byte)
	onError func(err error)
	sendMut sync.Mutex

	onUp     sync.Map
	onDown   sync.Map
	onUpHndl int
	onDnHndl int
}

// (AI GENERATED DESCRIPTION): Creates a new `baseFace` with the given `local` flag and initializes empty `onUp` and `onDown` handler maps.
func newBaseFace(local bool) baseFace {
	return baseFace{
		local:  local,
		onUp:   sync.Map{},
		onDown: sync.Map{},
	}
}

// (AI GENERATED DESCRIPTION): Returns `true` if the `baseFace` is currently running, otherwise `false`.
func (f *baseFace) IsRunning() bool {
	return f.running.Load()
}

// (AI GENERATED DESCRIPTION): Returns true if the face is local, otherwise false.
func (f *baseFace) IsLocal() bool {
	return f.local
}

// (AI GENERATED DESCRIPTION): Registers a callback function to handle incoming packets by assigning the provided function to the face's `onPkt` handler.
func (f *baseFace) OnPacket(onPkt func(frame []byte)) {
	f.onPkt = onPkt
}

// (AI GENERATED DESCRIPTION): Sets the callback function that will be invoked whenever the face encounters an error.
func (f *baseFace) OnError(onError func(err error)) {
	f.onError = onError
}

// (AI GENERATED DESCRIPTION): Registers an “up” event handler for the face, storing the callback under a unique handle and returning a function that, when called, removes the handler.
func (f *baseFace) OnUp(onUp func()) (cancel func()) {
	hndl := f.onUpHndl
	f.onUp.Store(hndl, onUp)
	f.onUpHndl++
	return func() { f.onUp.Delete(hndl) }
}

// (AI GENERATED DESCRIPTION): Registers a callback to be invoked when the face goes down, returning a function that can be called to unregister that callback.
func (f *baseFace) OnDown(onDown func()) (cancel func()) {
	hndl := f.onDnHndl
	f.onDown.Store(hndl, onDown)
	f.onDnHndl++
	return func() { f.onDown.Delete(hndl) }
}

// setStateDown sets the face to down state, and makes the down
// callback if the face was previously up.
func (f *baseFace) setStateDown() {
	if f.running.Swap(false) {
		f.onDown.Range(func(_, cb any) bool {
			cb.(func())()
			return true
		})
	}
}

// setStateUp sets the face to up state, and makes the up
// callback if the face was previously down.
func (f *baseFace) setStateUp() {
	if !f.running.Swap(true) {
		f.onUp.Range(func(_, cb any) bool {
			cb.(func())()
			return true
		})
	}
}

// setStateClosed sets the face to closed state without
// making the onDown callback. Returns if the face was running.
func (f *baseFace) setStateClosed() bool {
	return f.running.Swap(false)
}
