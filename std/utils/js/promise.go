//go:build js && wasm

package js

import (
	"errors"
	"syscall/js"
)

var promiseGlobal = js.Global().Get("Promise")

// (AI GENERATED DESCRIPTION): Creates a JavaScript function that runs the supplied Go function asynchronously and returns a Promise that resolves with its result or rejects with its error.
func AsyncFunc(f func(this js.Value, p []js.Value) (any, error)) js.Func {
	return js.FuncOf(func(this js.Value, p []js.Value) any {
		promise, resolve, reject := Promise()
		go func() {
			ret, err := f(this, p)
			if err != nil {
				reject(err.Error())
			} else {
				resolve(ret)
			}
		}()
		return promise
	})
}

// (AI GENERATED DESCRIPTION): Creates a new JavaScript Promise, returning the Promise object and Go-wrapped `resolve` and `reject` functions to fulfill or reject it.
func Promise() (promise js.Value, resolve func(args ...any), reject func(args ...any)) {
	var jsResolve, jsReject js.Value

	promiseConstructor := js.FuncOf(func(this js.Value, args []js.Value) any {
		jsResolve = args[0]
		jsReject = args[1]
		return nil
	})

	promise = promiseGlobal.New(promiseConstructor)
	resolve = func(args ...any) { jsResolve.Invoke(args...) }
	reject = func(args ...any) { jsReject.Invoke(args...) }

	promiseConstructor.Release()
	return
}

// (AI GENERATED DESCRIPTION): Blocks until the given JavaScript Promise settles, returning the resolved value or an error.
func Await(promise js.Value) (val js.Value, err error) {
	res := make(chan any, 1)

	var resolve, reject js.Func
	resolve = js.FuncOf(func(this js.Value, p []js.Value) any {
		res <- p[0]
		resolve.Release()
		reject.Release()
		return nil
	})
	reject = js.FuncOf(func(this js.Value, p []js.Value) any {
		res <- errors.New(p[0].String())
		resolve.Release()
		reject.Release()
		return nil
	})

	promise.Call("then", resolve).Call("catch", reject)

	result := <-res
	switch v := result.(type) {
	case js.Value:
		return v, nil
	case error:
		return js.Undefined(), v
	default:
		return js.Undefined(), errors.New("unexpected type")
	}
}
