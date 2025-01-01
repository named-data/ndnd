FROM golang:1.23-alpine3.21 AS build
WORKDIR /app
COPY . .
RUN env CGO_ENABLED=0 GOBIN=/build go install ./cmd/ndnd

FROM scratch
COPY --from=build /build/* /app/*/*.sample.yml /
ENTRYPOINT ["/ndnd"]
