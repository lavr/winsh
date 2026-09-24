VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
sq = $(subst ','\'',$(1))

.PHONY: build test integration integration-transfer race vet fmt check cross-build clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags='-s -w -X main.version=$(call sq,$(VERSION))' -o dist/winsh .

test:
	go test -timeout=60s ./...

integration:
	go test -tags=integration -timeout=120s ./...

integration-transfer:
	WINSH_TEST_TRANSFER_LARGE=1 go test -tags=integration -timeout=90m ./internal/remote -run '^TestLiveTransfer' -count=1 -v

race:
	go test -race -timeout=90s ./...

vet:
	go vet ./...

fmt:
	gofmt -w *.go internal

check: vet test race
	@test -z "$$(gofmt -l *.go internal)" || { echo 'Run make fmt'; exit 1; }

cross-build:
	@mkdir -p dist
	@set -e; for target in linux/amd64 linux/arm64 darwin/arm64 windows/amd64; do \
		os=$${target%/*}; arch=$${target#*/}; ext=; \
		if [ "$$os" = windows ]; then ext=.exe; fi; \
		echo "Building $$target"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath \
			-ldflags='-s -w -X main.version=$(call sq,$(VERSION))' -o "dist/winsh-$$os-$$arch$$ext" .; \
	done

clean:
	rm -rf dist coverage.out
