VERSION = 1.3.0.0

.PHONY: all install clean test coverage

all: yanfd

yanfd: clean
	CGO_ENABLED=0 go build -o yanfd -ldflags "-X 'github.com/named-data/ndnd/fw/core.Version=${VERSION}'" cmd/yanfd/main.go

install:
	install -m 755 yanfd /usr/local/bin
	mkdir -p /usr/local/etc/ndn
	install -m 644 yanfd.sample.yml /usr/local/etc/ndn

clean:
	rm -f yanfd coverage.out

test:
	go test ./... -coverprofile=coverage.out

coverage:
	go tool cover -html=coverage.out
