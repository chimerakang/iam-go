.PHONY: proto proto-lint proto-breaking build test lint clean init

# Proto generation
proto:
	buf generate

proto-lint:
	buf lint

proto-breaking:
	buf breaking --against '.git#branch=main'

# Go build targets
build:
	go build ./...

test:
	go test ./...

test-v:
	go test -v ./...

lint:
	go vet ./...

clean:
	rm -f proto/iam/v1/*.pb.go

# Install dependencies (one-time setup)
init:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	go install github.com/bufbuild/buf/cmd/buf@latest
