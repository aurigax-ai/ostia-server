FROM --platform=$BUILDPLATFORM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/ostia-server ./cmd/ostia-server
RUN mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.source=https://github.com/aurigax-ai/ostia-server
ENV OSTIA_SERVER_CONFIG=/etc/ostia-server/ostia-server.toml
COPY --from=build /out/ostia-server /usr/local/bin/ostia-server
COPY --from=build --chown=65532:65532 /out/data /var/lib/ostia-server
VOLUME /var/lib/ostia-server
EXPOSE 443
ENTRYPOINT ["/usr/local/bin/ostia-server"]
