BINARY    := ak-asset-check
DIST      := dist
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS   := -ldflags="-s -w -X main.buildDate=$(BUILD_DATE)"

.PHONY: all build build-all tidy clean release snapshot

all: build

build: tidy
	mkdir -p $(DIST)
	go build $(LDFLAGS) -o $(DIST)/$(BINARY) .

build-all: tidy
	mkdir -p $(DIST)
	GOOS=linux   GOARCH=amd64 go build $(LDFLAGS) -o $(DIST)/$(BINARY)-linux .
	GOOS=darwin  GOARCH=amd64 go build $(LDFLAGS) -o $(DIST)/$(BINARY)-macos-amd64 .
	GOOS=darwin  GOARCH=arm64 go build $(LDFLAGS) -o $(DIST)/$(BINARY)-macos-arm64 .
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(DIST)/$(BINARY)-windows.exe .

tidy:
	go mod tidy

release:
	goreleaser release --clean

snapshot:
	goreleaser release --snapshot --clean

clean:
	rm -rf $(DIST)
