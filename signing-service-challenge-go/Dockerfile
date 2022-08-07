# image for building application
FROM golang:1.18-alpine as builder

# install dependencies
RUN apk add --no-cache ca-certificates make g++

WORKDIR /src

COPY go.mod .
RUN go mod download

COPY . .
RUN make build

#FROM scratch as runtime
FROM alpine:3.9.6
WORKDIR /app
COPY --from=builder /src/bin/api .
EXPOSE 8080
CMD ["./api"]
