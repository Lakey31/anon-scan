BINARY=anon-scan
CLI_PKG=./cmd/cli
LDFLAGS=-s -w

.PHONY: all build test vet install-termux build-linux clean

all: build

build:
	go build -ldflags="$(LDFLAGS)" -o $(BINARY) $(CLI_PKG)

vet:
	go vet ./...

test: vet
	go test -v ./...

install-termux: build
	pkill -9 $(BINARY) 2>/dev/null || true
	rm -f $(PREFIX)/bin/$(BINARY)
	cp $(BINARY) $(PREFIX)/bin/$(BINARY)
	chmod +x $(PREFIX)/bin/$(BINARY)
	@echo "[✓] Installed $(BINARY) to $(PREFIX)/bin/$(BINARY)"

build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(BINARY)-linux-amd64 $(CLI_PKG)

clean:
	rm -f $(BINARY) $(BINARY)-linux-amd64
