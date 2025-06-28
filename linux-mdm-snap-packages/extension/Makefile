.PHONY: build clean test

# Build the extension
build:
	go mod tidy
	go build -o snap_packages.ext

# Clean build artifacts
clean:
	rm -f snap_packages.ext

# Run tests
test:
	go test ./...

# Install dependencies
deps:
	go mod download
	go mod tidy

# Build for different architectures
build-linux-amd64:
	GOOS=linux GOARCH=amd64 go build -o snap_packages.ext

build-linux-arm64:
	GOOS=linux GOARCH=arm64 go build -o snap_packages.ext

# Default target
all: deps build 