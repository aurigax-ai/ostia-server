# ostia-server

A small, self-hostable server for [Ostia](https://github.com/aurigax-ai/ostia), the terminal-first workspace for coding agents. One static Go binary, one config file, four optional modules:

| Module | What it does | What the server can see |
|---|---|---|
| `relay` | Lets the Ostia phone app reach a desktop that has no Tailscale and is not on the same network. The desktop dials out; the phone's TLS connection is passed through untouched. | Connection times, byte counts, and the phone's IP while connected (memory only). Never the traffic. |
| `publish` | Shares an artifact as a single encrypted file at a path of the API host. The key lives in the URL fragment and never reaches the server. | Size, time, view count. Never the content (unless the owner explicitly chose a public share). |
| `sync` | Keeps settings in step across a person's devices. Everything is encrypted on the device before upload. | Number and size of files, and when they change. Never names or contents. |
| `push` | Wakes the phone app with an empty ping through FCM or APNs. | A random handle and when it was pinged. |

Every module is off unless the operator turns it on, and the Ostia apps use none of them unless the person turns them on too.

## Run it

```sh
go build -o ostia-server ./cmd/ostia-server
cp deploy/ostia-server.example.toml ostia-server.toml
$EDITOR ostia-server.toml
./ostia-server admin invite
./ostia-server
```

`admin invite` prints a one-time code. Paste it into the Ostia desktop app under Settings to sign in. GitHub sign-in is available on instances that set `auth.github_client_id`.

Container and systemd examples are in `deploy/`; DNS, certificates and reverse-proxy setups are covered in [docs/self-hosting.md](docs/self-hosting.md).

## Documentation

- [docs/self-hosting.md](docs/self-hosting.md): DNS, certificates, Docker, systemd, backups, admin commands.
- [docs/configuration.md](docs/configuration.md): every configuration key and its default.
- [docs/protocol.md](docs/protocol.md): the HTTP, WebSocket and file-format contract used by the Ostia apps, with [docs/openapi.json](docs/openapi.json) for the HTTP routes.
- [docs/design.md](docs/design.md): the decisions behind the server and the reasons for them.

## Development

```sh
go vet ./...
go tool staticcheck ./...
go test -race ./...
node --test 'web/share-shell/*.test.mjs' 'testdata/vectors/*.test.mjs'
```

`e2e/` starts the real binary and drives it with scripted desktop, phone and device clients (`internal/testkit`): a phone reaching a desktop through the relay with a pinned certificate, publish/open/expire/delete, two devices syncing with merge and rollback refusal, push registration and ping against fake FCM and APNs servers, and the rate limits and authentication on every route.

`testdata/vectors/` holds the cryptographic vectors (share encryption, sync blobs, manifests and wraps, registration and challenge signatures). The Go tests and the Node tests read the same files, so the Ostia apps can check their implementations against them.

## License

ostia-server is licensed under the [Functional Source License, Version 1.1, MIT Future License](LICENSE) (FSL-1.1-MIT), the same license as Ostia. It is source-available, not open source.

- You may use, copy, modify and redistribute it for anything except a Competing Use: making it available to others in a commercial product or service that substitutes for it or offers substantially similar functionality. Running it for yourself, your team or inside your company is fine.
- Each release converts to the MIT license two years after it is published.
