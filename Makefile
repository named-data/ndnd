VERSION= $(shell git describe --tags --always --dirty)
STD_PACKAGE = github.com/named-data/ndnd/std

.PHONY: all install clean test coverage e2e

all: ndnd

ndnd: clean
	CGO_ENABLED=0 go build -o ndnd \
		-ldflags "-X '${STD_PACKAGE}/utils.NDNdVersion=${VERSION}'" \
		cmd/ndnd/main.go

generate:
	go generate ./...

install:
	install -m 755 ndnd /usr/local/bin

clean:
	rm -f ndnd coverage.out

clean-gen:
	rm -f gondn_tlv_gen

test:
	CGO_ENABLED=0 go test ./... -coverprofile=coverage.out

e2e: # minindn container
	sed -i 's/readvertise_nlsr no/readvertise_nlsr yes/g' /usr/local/etc/ndn/nfd.conf.sample
	python3 e2e/runner.py e2e/topo.sprint.conf

coverage:
	go tool cover -html=coverage.out

gondn_tlv_gen: clean-gen
	go build ${STD_PACKAGE}/cmd/gondn_tlv_gen
	go install ${STD_PACKAGE}/cmd/gondn_tlv_gen