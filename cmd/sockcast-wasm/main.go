//go:build js && wasm

package main

import (
	"syscall/js"

	"github.com/theraphim/sockcast-server/internal/wasmengine"
)

func main() {
	engine := wasmengine.NewEngine()
	api := js.Global().Get("Object").New()
	api.Set("engineType", "go-wasm")
	api.Set("callJSON", js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 1 {
			return `{"ok":false,"error":"missing JSON argument"}`
		}
		return engine.CallJSON(args[0].String())
	}))
	js.Global().Set("__sockcastGoWasm", api)
	select {}
}
