FROM golang:1.24 AS build
WORKDIR /app
COPY . .
RUN make

FROM scratch
COPY --from=build /app/ndnd /app/*/*.sample.yml /
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
ENTRYPOINT ["/ndnd"]
