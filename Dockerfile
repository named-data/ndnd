FROM golang:1.25 AS build
WORKDIR /app
COPY . .
RUN make

FROM scratch
COPY --from=build /app/ndnd /app/*/*.sample.yml /
ENTRYPOINT ["/ndnd"]
