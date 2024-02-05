BINARY_NAME=ecom-server

build:
	go build -o $(BINARY_NAME) cmd/server/main.go

run:
	go run cmd/server/main.go
