.PHONY: build run test clean deploy

# Build the server
build:
	go build -o git-vet-server ./cmd/gitscan-server

# Run locally
run: build
	./git-vet-server -listen :6633

# Run tests
test:
	go test ./...

# Clean build artifacts
clean:
	rm -f git-vet-server
	rm -f gitscan.db

# Build for Linux (for deployment)
build-linux:
	GOOS=linux GOARCH=amd64 go build -o git-vet-server-linux ./cmd/gitscan-server

# Deploy to server (requires SSH access)
# Usage: make deploy SERVER=user@your-server.com
deploy: build-linux
	scp git-vet-server-linux $(SERVER):/tmp/
	ssh $(SERVER) 'sudo mv /tmp/git-vet-server-linux /opt/gitvet/git-vet-server && sudo systemctl restart gitvet'
