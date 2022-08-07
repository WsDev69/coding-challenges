export GO111MODULE=on
BIN_NAME := $(or $(PROJECT_NAME),'api')

LD_FLAGS="-X ${PKG}/src/services/stats.version=${VERSION} \
 -X ${PKG}/src/services/stats.buildTime=${BUILD_TIME} \
 -X ${PKG}/src/services/stats.commit=${COMMIT}"

dep: # Download required dependencies
	go mod vendor

lint: dep ## Lint the files local env
	golangci-lint run -c .golangci.yml

fix:
	go fmt github.com/fiskaly/...
	goimports -local "github.com/fiskaly/coding-challenges/signing-service-challenge" -w .

build: dep ## Build the binary file
	go build -o ./bin/${BIN_NAME} -a -tags netgo -ldflags '-w -extldflags "-static"' -ldflags ${LD_FLAGS} .

docker-build:
	docker build -f Dockerfile -t challenge:0.1 .

docker-run:
	docker run -i -t --rm -p 8080:8080/tcp challenge:0.1