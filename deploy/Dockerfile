FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/ostia-server ./cmd/ostia-server
RUN mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/ostia-server /usr/local/bin/ostia-server
COPY --from=build --chown=65532:65532 /out/data /var/lib/ostia-server
VOLUME /var/lib/ostia-server
EXPOSE 443
ENTRYPOINT ["/usr/local/bin/ostia-server"]
CMD ["-config", "/etc/ostia-server/ostia-server.toml"]
