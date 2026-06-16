BINARY := gorial
PKG := ./...

.PHONY: build test vet fmt run tidy clean

build:
	go build -o $(BINARY) ./cmd/gorial

test:
	go test -race $(PKG)

vet:
	go vet $(PKG)

fmt:
	gofmt -l -w .

tidy:
	go mod tidy

run: build
	./$(BINARY) -config config.yaml

clean:
	rm -f $(BINARY) coverage.out
