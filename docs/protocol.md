# Protocol

This is the contract between ostia-server and its clients (the Ostia desktop app and the phone app). [`openapi.json`](openapi.json) describes every HTTP route, and a test fails when it and the code disagree. The cryptographic parts have test vectors in `testdata/vectors/`. The API is versioned by path (`/v1`); `GET /v1/info` reports `api: 1`. HTTP and JSON carry request/response calls; WebSocket carries the long-lived relay channels, with the messages listed below.

## Conventions

- Base URL: `https://<api domain>/v1`. Bodies are JSON (`Content-Type: application/json`) unless a route says otherwise.
- Binary values in JSON are unpadded base64url (padding is accepted on input). Timestamps are Unix milliseconds.
- Errors are `{"error": "<code>", "message": "<optional text>"}` with the status in the table at the end.
- Authenticated routes need `Authorization: Bearer <session token>` (see Accounts). Public routes are rate limited per source address; authenticated routes per device. A refused request is `429` with `Retry-After` in seconds.
- Requests with a body are size limited; an oversize body is `413 too-large`.

## Public routes

| Route | Answer |
|---|---|
| `GET /healthz` | `{"ok": true}` |
| `GET /v1/info` | `{api, modules: {relay, publish, sync, push}, auth: {invite, github}, relayDomain, limits}`; the modules are booleans |

A disabled module's routes do not exist (`404`).

## Accounts, devices and sessions

Signing in identifies an account; it never decrypts anything. A device holds an Ed25519 signing key and an X25519 box key. Both public keys are registered with the server, which keeps only public keys.

### Registration

Registration proves possession of the signing key. The message is

```
ostia-server/register/v1\n<signPub, base64url>\n<boxPub, base64url>
```

and `proof` is the Ed25519 signature of its UTF-8 bytes. `signPub` and `boxPub` are 32 bytes; `name` is 1 to 64 printable characters.

**Invite code** (the default for self-hosted instances; `ostia-server admin invite` mints one). A plain code makes a new account. A code that the operator minted with `admin invite -account <id>` adds the device to that account. No device and no API mints an invite code:

```
POST /v1/auth/invite  {code, name, signPub, boxPub, proof}
201 {accountId, deviceId, provider}
```

Codes are typed by people, so case and dashes are ignored. A code works once. `403 invalid-invite` covers unknown, used and expired codes alike. `409 device-limit` when the account already has `auth.max_devices_per_account` devices.

**GitHub device flow** (only when the instance sets `auth.github_client_id`):

```
POST /v1/auth/github/device
200 {flowId, userCode, verificationUri, interval, expiresIn}

POST /v1/auth/github/poll  {flowId, name, signPub, boxPub, proof}
202 {status: "pending", interval}        keep polling, no faster than `interval` seconds
201 {accountId, deviceId, provider}      signed in
403 denied | 410 expired | 404 unknown-flow | 502 github-unavailable
```

The person opens `verificationUri` and enters `userCode`. The same GitHub user always lands in the same account. The server stores only an HMAC of the GitHub id.

### Sessions

```
POST /v1/auth/challenge  {deviceId}              200 {nonce}
POST /v1/auth/verify     {deviceId, nonce, sig}  200 {token, expiresAt, accountId}
DELETE /v1/auth/session                          204
```

`sig` is the Ed25519 signature over

```
ostia-server/auth/v1\n<deviceId>\n<nonce>
```

A nonce is single use and lives 60 seconds. A device holds at most five open nonces. `challenge` answers the same way for unknown devices, but keeps nothing for them. The token is valid for `auth.session_ttl` (default one hour). Keep the token and the private keys in the main process only.

**Why a bearer token and not a signature on every request.** All traffic is TLS to a known host, so the transport already authenticates the server and hides the token. A per-request signature would add a signed body-hash format, a replay window and clock handling, and it does not fit the WebSocket upgrade or streaming uploads, while protecting against little: the signing key lives in the same process as the token. What matters instead is how little a stolen token can do. It lives one hour, the server stores only its hash, and the destructive actions below need a signature with the device key, which a token alone does not give.

### Devices

```
POST   /v1/devices/heartbeat     204   no body; checks the device in so an idle client is not removed for inactivity (any other authenticated request does the same, at most once an hour)
```

There is no device list and no API that removes a device. A device that signs out ends its session with `DELETE /v1/auth/session`. Its row stays until the inactivity sweep removes it. A lost device keeps its session until the session expires. A key replacement (see Sync) stops it from reading data that comes after.

### Actions that need the device key

Some actions can destroy data or help an offline guess of the passphrase, so a bearer token alone is not enough: the request must also be signed with the calling device's Ed25519 key (the key registered with the device). The signature goes in `X-Device-Signature` (unpadded base64url) over a prefixed message that names the device and the target. Every signed action also sends `X-Device-Timestamp` (milliseconds, within two minutes of the server clock, and larger than the device's previous one, so a captured request cannot be replayed):

| Action | Message |
|---|---|
| `GET /v1/sync/wraps/passphrase`, `GET /v1/sync/wraps/recovery` | `ostia-server/wrap-read/v1\n<device id>\n<timestamp>\n<slot>` (`passphrase` or `recovery`) |
| `PUT /v1/sync/manifest` | `ostia-server/manifest-put/v1\n<device id>\n<timestamp>\n<if-match>\n<body hash>`. `<if-match>` is the version in `If-Match` as a decimal number without quotes. `<body hash>` is the unpadded base64url SHA-256 of the exact request body bytes |
| `POST /v1/sync/rotate` | `ostia-server/sync-rotate/v1\n<device id>\n<timestamp>\n<if-match>\n<body hash>`, with `<if-match>` and `<body hash>` as for `PUT /v1/sync/manifest` |
| `POST /v1/sync/gc` | `ostia-server/sync-gc/v1\n<device id>\n<timestamp>\n<if-match>\n<body hash>`, with `<if-match>` and `<body hash>` as for `PUT /v1/sync/manifest` |

A missing signature answers `403 device-signature-required`, a wrong one `403 bad-signature`, an old or reused timestamp `403 stale-signature`. A stolen session token therefore cannot download the passphrase or recovery wrap to guess it offline, replace the account key, delete blobs, or push manifest versions that push real history out.

The timestamp counter is one per device, shared by every action in the table: a timestamp must be larger than the last one the server accepted from that device, whichever action it signed. A client keeps `stamp = max(now, previous stamp + 1)` and does not send two signed requests concurrently. The signature covers what the request asks for, so a captured header cannot be attached to another slot, another `If-Match`, another body or another action (`403 bad-signature`). A signed request that fails after the signature was checked (for example a manifest `PUT` answered `412`) has still used its timestamp, so a retry signs a new one. The server reads the whole body before it checks the signature, so sign over the bytes you send and do not re-serialize between hashing and sending. The manifest, blobs and listings stay readable with the token, since they are sealed under `K`.

### Inactive devices

An hourly sweep revokes every device whose last activity is older than `devices.inactive_after` (90 days by default). Its sessions and relay label end and its open relay streams close. The sweep then purges each account that has no active device: its sync data (manifests, blobs, the key and its wraps) and push registrations are deleted, and the account too when none of its shares is live (removed or expired shares do not count). The row of a revoked device is deleted `auth.revoked_device_retention` (30 days) after the revocation. `ostia-server admin delete-account` removes an account at once.

## Relay

The relay forwards a phone's TLS connection to the desktop without terminating it. The phone keeps pinning the desktop gateway's certificate, so the relay cannot read or alter the traffic.

```
POST /v1/relay/label   200 {label, host, port}
```

The label is a random 128-bit value (26 characters, `a-z2-7`), stable per device. `host` is `<label>.<relay domain>` and `port` is the server's `domains.port` (443 by default). The phone connects to `host:port` and verifies the desktop's pinned certificate fingerprint, not the name. DNS for `*.<relay domain>` points at the server.

### Desktop side

1. `GET /v1/relay/listen` (WebSocket, `Authorization` header). A newer connection for the same device replaces the older one.
2. The listener lives as long as the session that opened it: when the session expires, is ended with `DELETE /v1/auth/session`, or the device is revoked, the server closes it at once. Open a new session and connect again before the old one expires; a newer listener replaces the older at once. The server sends JSON text frames: `{"t": "ping"}` every `relay.ping_interval` and `{"t": "incoming", "stream": "<id>", "peer": "ip:port", "family": 4|6}` per phone connection. The desktop answers pings with `{"t": "pong"}`. A listener that stays silent for 2.5 intervals is dropped.
3. For each `incoming` the desktop opens `GET /v1/relay/accept/<stream>` (WebSocket, same bearer) within `relay.accept_timeout` (10 seconds). A stream id works once and only for the device it was offered to.
4. Binary frames on the accept socket carry the phone's TCP stream in both directions. The first bytes the desktop receives are the phone's TLS ClientHello, then the rest of the stream.

The Ostia desktop writes `PROXY TCP4|TCP6 <peer ip> 127.0.0.1 <port> <port>\r\n` followed by those bytes into its loopback gateway listener, so pairing limits and the audit log see the phone's address.

**Confirming a stream.** Anyone who knows a label can open a connection to it, so a stream starts unconfirmed. The desktop confirms it with `{"t": "confirm", "stream": "<id>"}` on the control socket once the gateway has accepted the phone: a hello that carried a valid device token, or a pairing request that carried a live pairing code. An unconfirmed stream is closed after `relay.unconfirmed_timeout` (15 seconds) or after 32 KiB (a TLS handshake and a hello fit comfortably), counts against `relay.max_unconfirmed_per_label` instead of the confirmed limit, and is not billed to the account's byte quota. A confirmed stream counts against `relay.max_streams_per_label` and the quota.

### Phone side and limits

- The server reads only the SNI of the ClientHello. A known label with no desktop listening is reset at once. An unknown label, a non-TLS first message, or a stalled handshake is held for `relay.hello_timeout` (5 seconds) and closed without a reply, so scanning learns nothing.
- Per label: `relay.max_streams_per_label` confirmed streams and `relay.connections_per_minute` confirmations a minute; `relay.max_unconfirmed_per_label` unconfirmed streams, where a new connection evicts the oldest unconfirmed one when the pool is full (squatting on a label cannot lock out the real phone), `relay.unconfirmed_opens_per_minute_per_address` and `relay.unconfirmed_opens_per_minute` new connections per source address and per label. Per source address: `relay.connections_per_minute_per_ip`. Per account: `relay.monthly_bytes_per_account`, counted in memory and flushed every 10 seconds. A stream with no bytes for `relay.idle_timeout` is closed.
- There is no presence endpoint: nothing tells a third party whether a desktop is online.

## Publish

A share is one file (the Ostia portable artifact, at most `publish.max_file_bytes`) at `https://<api domain>/s/<id>` (plus `:<domains.port>` when that is not the scheme's default port). Shares share the API's origin; the shell keeps them apart by id and sandboxes every artifact.

### Modes

| Mode | Key | Server holds |
|---|---|---|
| `link` | 256-bit key in the URL fragment: `https://<api domain>/s/<id>#k=<base64url>` | ciphertext |
| `password` | PBKDF2-HMAC-SHA256 (600000 rounds) of the NFKC-normalised password and a 16-byte salt; optionally combined with a fragment key | ciphertext and salt |
| `public` | none | the file itself (only when `publish.allow_public` is on, and only when the owner chose it) |

### File format `ostia-share/1`

```
blob = 0x01 || nonce (12 bytes) || AES-256-GCM(key, plaintext) (ciphertext || 16-byte tag)
AAD  = "ostia-share/1:" || share id (UTF-8)
```

- `link`: `key` is the 32-byte fragment key.
- `password`: `key = PBKDF2-HMAC-SHA256(NFKC(password), salt, 600000, 32)`. With a fragment key `k` as well: `key = HKDF-SHA256(ikm = pbkdf2 || k, salt = empty, info = "ostia-share/1/key", length = 32)`.

The size declared at creation is the exact blob size: `len(plaintext) + 29` for encrypted modes.

### API

```
POST /v1/shares  {mode, size, expiresInSeconds?, salt?}
201 {id, url, uploadUrl, deleteToken, expiresAt}

PUT  <uploadUrl>                        raw body of exactly `size` bytes, once        204
GET  /v1/shares                         {shares: [{id, url, mode, size, views, createdAt, expiresAt, uploaded, expired?}]}
DELETE /v1/shares/{id}                  204; send X-Delete-Token: <deleteToken> or the owner's bearer
POST /v1/report/{id}  {reason}          204; no authentication
```

- `salt` is required for `password` and must be 16 bytes.
- `expiresInSeconds` omitted: `publish.default_expiry` (30 days). `0` means never and works only when `publish.allow_never` is on. Otherwise it must lie between `publish.min_expiry` and `publish.max_expiry` (one year).
- `deleteToken` is shown once. Keep it with the share; it deletes without a session.
- Quotas per account: `publish.max_shares_per_account` and `publish.max_bytes_per_account` (`507 quota-exceeded`).
- `reason` is one of `illegal`, `malware`, `abuse`, `other`. Reports store only the share id, the reason and the time.

### Share routes

All share routes are on the API host, under `/s/<id>`. A share id is validated before any lookup; any other path under `/s/` is `404`.

| Path | Answer |
|---|---|
| `GET /s/<id>` (or with a trailing `/`) | The fixed shell page, for every mode. |
| `GET /s/<id>/meta` | `{v: 1, mode, size, salt, expiresAt, warning}`; `warning` is the server's `publish.share_warning` and no share can change it; `404` unknown or not uploaded, `410` expired or removed |
| `GET /s/<id>/blob` | The ciphertext, or the file itself for a public share. Sent with `Content-Disposition: attachment`. Answers `404` to a top-level navigation (`Sec-Fetch-Mode: navigate` or `Sec-Fetch-Dest: document`), as does `/meta`, so a link cannot download it |
| `POST /s/<id>/view` | Counts one view; the shell calls it once the page is shown, after the visitor accepted the notice. `204`; `404` for an unknown, expired or removed share |
| `POST /s/<id>/report` | `{reason}` as above, for the shell's report button |
| `GET /s/-/shell.js`, `/s/-/crypto.js`, `/s/-/shell.css` | The shell's static assets; `-` is not a valid share id |

The shell fetches `/s/<id>/meta` and `/s/<id>/blob`, decrypts with WebCrypto (not for public shares), shows a notice bar and a one-time interstitial, and renders the file in `<iframe sandbox="allow-scripts" srcdoc>`. Responses carry `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin`, `X-Robots-Tag: noindex`, a `Permissions-Policy` that denies fullscreen and the other powerful features, and `Cache-Control: no-store`. The server sets no cookies and stores no addresses or user agents; it counts views only.

Artifacts open links with `parent.postMessage({ostiaOpen: url}, '*')`: the shell takes `http(s)` URLs of up to 2048 characters from its own frame only, asks the visitor in a bar outside the frame, and opens the link with `window.open(url, '_blank', 'noopener,noreferrer')` only from the visitor's click on Open. Navigating the frame, popups, forms, downloads and `alert`/`confirm`/`prompt` are blocked; in-page DOM dialogs work.

Expired shares are removed hourly (`publish.sweep_interval`). `ostia-server admin takedown <id>` disables a share and deletes its content at once.

## WebSocket messages

Only the relay uses WebSocket. Control frames are JSON text; relayed bytes are binary.

| Socket | Direction | Message |
|---|---|---|
| `/v1/relay/listen` | server to desktop | `{"t": "ping"}` |
| `/v1/relay/listen` | server to desktop | `{"t": "incoming", "stream": string, "peer": "ip:port", "family": 4 or 6}` |
| `/v1/relay/listen` | desktop to server | `{"t": "pong"}` |
| `/v1/relay/listen` | desktop to server | `{"t": "confirm", "stream": string}` |
| `/v1/relay/accept/{stream}` | both | binary frames: the phone's TCP stream |

Close codes: 1008 when a newer listener replaced this one, the device or its account was removed, the session ended, or the pongs stopped; 1001 when the server shuts down.

## Sync

The server stores opaque blobs. The client keeps a 32-byte **profile key** `K`; the server never receives it. A client implements the merge: per top-level key, three-way against the last synced state, with conflicts reported to the person.

### Keys

```
blobKey     = HKDF-SHA256(K, salt = empty, info = "ostia-sync/blob",     32)
manifestKey = HKDF-SHA256(K, salt = empty, info = "ostia-sync/manifest", 32)
pathKey     = HKDF-SHA256(K, salt = empty, info = "ostia-sync/path",     32)
```

### Blobs

```
hash    = SHA-256(content)
blobId  = base64url(HMAC-SHA256(pathKey, path || 0x00 || hash))          43 characters
sealed  = nonce (12) || AES-256-GCM(blobKey, content), AAD = "ostia-sync/blob/v1\n" || path
```

A blob id names its content, so a blob is write-once: uploading the same bytes again is a no-op, different bytes under an existing id are `409 blob-exists`. A write that loses the manifest race therefore never corrupts what another device points at.

### Manifest

The manifest is JSON, sealed with `manifestKey` and AAD `ostia-sync/manifest/v1`:

```json
{"counter": 7, "files": {"settings.json": {"blobId": "…", "hash": "…"}}}
```

The server stores sealed manifests with a monotonically increasing `version` and the key version they are sealed under. It keeps the newest `sync.manifest_history`, plus the last version of each of the previous `sync.manifest_checkpoint_days` days, so a flood of writes from a stolen token cannot push every earlier version out of the history.

**Rollback guard.** Each device remembers the highest `counter` it has seen and refuses a manifest with a lower one (`stale-manifest`). A server that serves an old manifest is caught as soon as a device has seen a newer one. A manifest written by a key replacement continues the counter.

### The account key

Each account has one profile key `K` at a time, with three things on the server: a passphrase wrap, a recovery wrap and a key version. The key version is 0 before sync is set up. It goes up by one each time `K` is replaced. All wraps are opaque to the server.

- Both wraps use one format: `0x01 || memoryKiB (4 bytes BE) || passes (1) || lanes (1) || salt (16) || nonce (12) || AES-256-GCM(argon2id(secret, salt, passes, memoryKiB, lanes) → 32 bytes, K)`, AAD = `"ostia-sync/wrap/passphrase/v1"` followed by the first 23 header bytes. The secret is the passphrase or the recovery key. Production parameters are 64 MiB, 3 passes, 4 lanes.
- Set up and every replacement go through `POST /v1/sync/rotate`. One request carries the new manifest, the new passphrase wrap and the new recovery wrap. The server writes all three and the new key version in one transaction, so no device sees a manifest without the wraps for its key.
- A replacement needs no approval from another device. The server does not check that the caller holds `K`. Only a device that unlocked `K` with the passphrase can re-seal the data under `K'`. The request is signed with the device key, so a stolen token alone cannot replace `K`.

A new device gets `K` from the passphrase or from the recovery key. There is no device wrap, link code or approval.

### API

```
GET  /v1/sync/manifest[?version=N]    {version, keyVersion, blob, updatedAt}; 404 no-manifest. keyVersion is the key version the manifest is sealed under
PUT  /v1/sync/manifest                {blob}; If-Match: <current version>; signed with the device key → 200 {version}
                                      412 {error: "version-mismatch", current}; 428 without If-Match; 409 no-key before set up. The manifest keeps the current key version
GET  /v1/sync/manifest/versions       {versions: [{version, keyVersion, updatedAt}]}
GET  /v1/sync/blobs/{blobId}          raw bytes
PUT  /v1/sync/blobs/{blobId}          raw bytes → 201 created | 200 identical | 409 | 413 | 507
GET  /v1/sync/wraps/{slot}            {slot, blob, keyVersion, updatedAt}; slot: passphrase | recovery (400 bad-slot otherwise); signed with the device key; 404 before set up
POST /v1/sync/rotate                  {manifest, passphrase, recovery}; If-Match: <manifest version read, 0 for none>; signed with the device key
                                      → 200 {version, keyVersion}; 412 {error: "version-mismatch", current}; 428 without If-Match; 400 bad-request when a part is missing or too large
POST /v1/sync/gc                      {keep: [blobId]} → {deleted}     removes blobs older than sync.gc_grace that are not listed. Signed with the device key (`ostia-server/sync-gc/v1`) and `If-Match: <manifest version the caller pushed>`: `428` without If-Match, `412 {error: "version-mismatch", current}` when the manifest has moved. Uploading a blob that already exists refreshes its age, so a blob id that returns to an earlier state is not collected by an old grace period
GET  /v1/sync/usage                   {blobs, bytes, quotaBytes}
```

### Client algorithm

1. `GET manifest`. If `keyVersion` is not the key version this device unlocked, `K` was replaced: ask the person for the passphrase once, `GET` the passphrase wrap and unwrap the new `K`. Do not upload anything before that.
2. Open the manifest and refuse a counter lower than the highest seen. Fetch and open the blobs it lists and check each content hash.
3. Merge per key with the last synced state as base. Upload blobs whose id the remote manifest does not list, then `PUT manifest` with `If-Match: <version read>` and `counter = highest + 1`.
4. On `412`, repeat from step 1 (the reference client tries three times).

### Changing the passphrase

1. Read and open the current manifest and its blobs with `K`.
2. Make a new `K'` and re-seal every blob and the manifest under it.
3. Send one `POST /v1/sync/rotate` with the new manifest, a passphrase wrap and a recovery wrap of `K'`, and `If-Match: <version read>`.
4. Show the new recovery key to the person once.

The same steps set a new passphrase after a recovery with the recovery key. The other devices see the new key version and ask for the new passphrase once. A device that knew only the old passphrase cannot read what comes after. It keeps what it already decrypted.

## Push

Push is content free and bound to an account. A signed-in desktop gets a single-use ticket and hands it to its phone over the gateway socket; the phone registers its platform token with the ticket and gets an opaque handle; only the desktop's session can ping it.

```
POST /v1/push/tickets   (session)                          201 {ticket, expiresAt}   valid push.ticket_ttl, at most 10 open
POST /v1/push/register  {platform: "fcm" | "apns", token, ticket}   201 {handle}     no session; 403 invalid-ticket
POST /v1/push/{handle}  (session, empty body)              204
DELETE /v1/push/{handle} (session)                         204
```

- The handle belongs to the ticket's account. At `push.max_handles_per_account` a new registration replaces the account's oldest handle, so handles abandoned by phones that switched desktops or were reinstalled end by themselves; another account's session gets `410` for a handle that is not its own. Deleting the account deletes its handles.
- A ping has no body (`400` otherwise). At most one per 30 seconds and 60 per hour per handle (`429`, `Retry-After`).
- Android receives a high-priority data-only message `{"v": "1"}`. iOS receives an alert with the fixed localisation key `DESKTOP_NEEDS_YOU` and `mutable-content: 1`. The app wakes, connects to its desktop and builds its own alert.
- `410 gone`: the handle is unknown, deleted, someone else's, or its token was rejected by the platform (the handle is then deleted).
- The server holds platform tokens, sealed with a key derived from `server.key`, and talks to FCM and APNs with the operator's own credentials.

## Error codes

| Status | `error` |
|---|---|
| 400 | `bad-request`, `bad-proof`, `bad-slot`, `size-mismatch` |
| 401 | `unauthorized` |
| 403 | `forbidden`, `invalid-invite`, `denied`, `invalid-ticket`, `device-signature-required`, `bad-signature`, `stale-signature`, `public-disabled`, `publish-disabled` |
| 404 | `not-found`, `no-manifest`, `unknown-flow` |
| 409 | `conflict`, `blob-exists`, `already-uploaded`, `device-limit`, `no-key` |
| 410 | `gone`, `expired` |
| 412 | `version-mismatch` |
| 413 | `too-large` |
| 428 | `precondition-required` |
| 429 | `rate-limited` |
| 501 | `platform-unavailable` |
| 502 | `delivery-failed`, `github-unavailable`, `upstream-unavailable`, `upstream-failed` |
| 503 | `busy` |
| 507 | `quota-exceeded` |
