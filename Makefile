BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
COMMIT := $(shell git describe --always --dirty)

all:
	go build -ldflags "-X main.version=$(BRANCH)-$(COMMIT)"
