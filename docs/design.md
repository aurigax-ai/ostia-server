# Design notes

Why the server is built the way it is. Each entry is a decision someone changing the code should know before reversing it.

## One binary, modules switched in config

`relay`, `publish`, `sync` and `push` share accounts, device keys, rate limits, quotas, storage and the admin commands. A person running a homelab starts one process. A larger deployment can start the same binary with only one module on; the modules talk to each other only through the database.

## The relay passes TLS through

The phone already pins the desktop gateway's certificate fingerprint and ignores the host name. An SNI passthrough relay leaves that handshake untouched, so the relay cannot read or alter the traffic and the pairing check code is unchanged. A relay that terminated TLS would show a different certificate and fail the pin.

The desktop dials out over a WebSocket, so it needs no open port. There is one WebSocket per phone connection and TCP provides the flow control, so there is no multiplexer.

Unknown labels and non-TLS connections are held for the hello timeout and then closed without a reply. A known label with no desktop listening is reset at once. Answering differently would let a scanner tell which desktops exist or are online.

## Shares: one origin each, a fixed shell, the key in the fragment

The key is in the URL fragment, which browsers never send. A fixed shell page fetches the ciphertext, decrypts it with WebCrypto and renders it inside `<iframe sandbox="allow-scripts" srcdoc>`. The limit of every web-delivered end-to-end page applies: a compromised server could serve a different shell that leaks the fragment. Self-hosters trust their own box; the shell is plain unminified JavaScript in `web/share-shell/` so it can be read.

The shell's Content-Security-Policy allows inline scripts and styles (`'unsafe-inline'`). A `srcdoc` frame inherits the embedding page's policy, and the shared artifact is one HTML file with inline script and style, so a policy of `script-src 'self'` would stop every artifact. The shell has no injection point: all shared content lives inside the sandboxed frame, whose opaque origin cannot reach the parent or the fragment.

Public shares are served raw with `Content-Security-Policy: sandbox allow-scripts`, so the document gets an opaque origin even when opened directly.

## Sync blobs are named by their content

The plan for the sync protocol derived a blob id from the path alone. That lets a device overwrite a blob that another device's manifest still points at, and a write that loses the manifest race would leave a manifest whose hash does not match its blob. The id is now `HMAC(pathKey, path || hash)`, blobs are write-once, and a lost race leaves harmless unreferenced blobs that `POST /v1/sync/gc` collects. The server cannot read manifests, so only a client can say which blobs are still referenced.

Key rotation is one transaction (`POST /v1/sync/rotate`): the new manifest and every changed wrap land together, so no device ever sees a manifest it has no wrap for.

## Push handles are not tied to accounts

A phone has no account, so its handle cannot belong to one. The handle is the credential: over 150 random bits, known only to the phone and the desktop it was given to. The desktop deletes the handle when it revokes the phone; deleting an account does not reach handles because nothing links them. A ping has no content, so a leaked handle can cause at most one wake-up per 30 seconds.

Each operator uses their own FCM and APNs credentials. Platform tokens are bound to the app build, so a server can only push to phones running a build registered under its credentials. There is no shared push gateway.

## Rate limits and authentication on every route

Public routes (sign-in, challenge, reports, push registration and ping, share hosts, `/v1/info`, `/healthz`) have per-address limiters. Every other route needs a bearer token and is limited per device. Share deletion is authorised by the delete token or the owner's bearer and is limited per address.\n\n`docs/openapi.json` states the security of every route. `internal/server/openapi_test.go` fails when the document and the registered routes differ, when a route marked as authenticated answers an anonymous or invalid bearer with anything but 401, and when a route marked as public is not rate limited. Adding a route means deciding both in the document.

## No access logs

Request logs would hold addresses and share ids. The server logs start-up and errors, never successful requests. Rate-limit state is in memory only.
