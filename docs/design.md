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

## Push registration is a desktop-issued ticket

A phone has no account, so it cannot prove anything itself. The desktop does: a signed-in desktop mints a single-use ticket and gives it to its own phone, which registers with it. The handle is therefore bound to the desktop's account, a stranger cannot fill the table, an account can only hold a few, and only that account's session can ping or delete the handle. A ping has no content, at most one wake-up per 30 seconds per handle.

Each operator uses their own FCM and APNs credentials. Platform tokens are bound to the app build, so a server can only push to phones running a build registered under its credentials. There is no shared push gateway.

## Elevated sessions for destructive actions

The bearer token lives in the desktop's main process for an hour. If it leaks, an attacker must not be able to delete devices, wraps, blobs or the account. Those actions need another signed-in device to approve (the person clicks on that device) or a fresh GitHub sign-in by the same GitHub user. Elevation lasts five minutes and is attached to the session that asked. The approver must also have belonged to the account for a day (longer than a session lives), and adding a device beyond the second is itself elevated, counting open invites: otherwise a stolen token could invite devices of its own and use them to approve each other. The owner can always fight back during that day: an established device removes a device still on probation without elevation, and the last established device cannot be revoked by a token alone. Wraps carry no signature, so an unelevated session may only fill empty wrap slots. Reading the passphrase or recovery wrap, which a thief could try to guess offline, and pushing a manifest, which a thief could use to push real history out of the retained versions, need a device signature like inviting does (see protocol.md). The cost is that an account with a single non-GitHub device cannot do these things itself; the operator can still delete the account from the command line.

## Client addresses behind a proxy

Rate limits key on the client address. Behind a proxy that address is only known from a header, and a header anyone can send is worthless. The server reads the header only from connections whose peer is listed in `listen.trusted_proxies`, and believes exactly one hop: the last address in the header, which the nearest proxy appended. Entries to its left are never read, so a client cannot pick its own key by prepending addresses, not even ones inside the trusted range. Walking past trusted addresses to the first untrusted one was dropped because a caller whose own address is inside the range (another pod, or a pod using the public name) would then hand the server the choice. A caller that reaches the server directly, bypassing the proxy, is still believed if its address is in the range, so the range should list the proxy and the network should only let the proxy in. The limiter tables are capped: once a table is full, new addresses share one bucket instead of growing memory. In `forward` mode the server tells the proxy the client address with PROXY protocol v2, since it cannot add a header to a TLS stream it does not terminate.

## Request deadlines

The proxy in front may allow an hour of silence, so the server bounds every phase itself: ten seconds for the headers, then each route a deadline set through `http.ResponseController` as it starts, one minute to read the body and one to write the answer for JSON routes, five minutes for blob transfers (sync blobs, share uploads). `http.Server` carries the five minute limit as the outer bound for what no route narrows, such as share downloads. A connection that trickles a body therefore frees its slot after a minute instead of holding one of the proxy's connections open. WebSocket upgrades hijack the connection, which clears the deadline.

## Relay streams start unconfirmed

A label is an identifier, not a secret: it is in the pairing QR and in every address list. Without a check, anyone who learned it could hold the label's connection slots and burn the owner's byte quota with idle or garbage streams. A stream is therefore unconfirmed until the desktop says its gateway accepted the phone (valid device token or live pairing code). Unconfirmed streams are short lived, capped separately, and unbilled; when the pool is full the oldest unconfirmed stream is evicted so squatters cannot lock out the real phone, and the per-label budget is spent only on confirmed streams. The accept side of the relay never learns what the traffic is; the gateway tells the desktop client, which tells the relay only the stream id.

## Pre-handshake connections are pooled per address

The router holds a connection until its ClientHello arrives, which is a slow-connection attack surface. The pool is capped, each source address (an IPv6 /64 counts as one) may hold only a few places, and when the pool is three quarters full the router stops holding connections that are not TLS.

## The share domain is a different site

Browsers decide same-site by registrable domain from the public suffix list. A share domain under the API's registrable domain would let a malicious share set cookies for, or be treated as part of, the API's site. The server refuses to start in that case.

## Rate limits and authentication on every route

Public routes (sign-in, challenge, reports, push registration and ping, share hosts, `/v1/info`, `/healthz`) have per-address limiters. Every other route needs a bearer token and is limited per device. Share deletion is authorised by the delete token or the owner's bearer and is limited per address.\n\n`docs/openapi.json` states the security of every route. `internal/server/openapi_test.go` fails when the document and the registered routes differ, when a route marked as authenticated answers an anonymous or invalid bearer with anything but 401, and when a route marked as public is not rate limited. Adding a route means deciding both in the document.

## No access logs

Request logs would hold addresses and share ids. The server logs start-up and errors, never successful requests. Rate-limit state is in memory only.
