.PHONY: build test vet wasm wasm-serve clean

build:
	go build -trimpath ./...

test:
	go test -race ./...

vet:
	go vet ./...

wasm:
	GOOS=js GOARCH=wasm go build -trimpath -ldflags="-s -w" \
		-o web/public/certkit.wasm ./cmd/wasm/
	cp "$$(go env GOROOT)/lib/wasm/wasm_exec.js" web/public/wasm_exec.js

wasm-serve: wasm
	@echo "Serving at http://localhost:8080"
	cd web/public && python3 -m http.server 8080

clean:
	rm -f web/public/certkit.wasm web/public/wasm_exec.js
