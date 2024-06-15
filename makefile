BINARY_NAME=auth-server

build:
	go build -o dist/$(BINARY_NAME) cmd/server/main.go

run-dev:
	go run cmd/server/main.go -dev

run:
	go run cmd/server/main.go
