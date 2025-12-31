go build -ldflags "-X main.version=$(git rev-parse --short HEAD)"
