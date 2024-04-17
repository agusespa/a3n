BINARY_NAME=auth-server

build:
	go build -o dist/$(BINARY_NAME) cmd/server/main.go

run:
	go run cmd/server/main.go
