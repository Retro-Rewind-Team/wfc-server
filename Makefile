VERSION := $(shell git rev-parse --short HEAD)

all:
	go build -ldflags "-X main.version=$(VERSION)"
