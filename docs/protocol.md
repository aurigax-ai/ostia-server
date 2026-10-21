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
| `GET /v1/info` | `{api, modules: {relay, publish, sync, push}, auth: {invite, github}, relayDomain, shareDomain, limits}`; the modules are booleans |

A disabled module's routes do not exist (`404`).

## Accounts, devices and sessions

Signing in identifies an account; it never decrypts anything. A device holds an Ed25519 signing key and an X25519 box key. Both public keys are registered with the server, which keeps only public keys.

### Registration

Registration proves possession of the signing key. The message is

```
ostia-server/register/v1\n<signPub, base64url>\n<boxPub, base64url>
```

and `proof` is the Ed25519 signature of its UTF-8 bytes. `signPub` and `boxPub` are 32 bytes; `name` is 1 to 64 printable characters.

**Invite code** (the default for self-hosted instances; `ostia-server admin invite` mints one, or a signed-in device mints one for another device of the same account):

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

**Why a bearer token and not a signature on every request.** All traffic is TLS to a known host, so the transport already authenticates the server and hides the token. A per-request signature would add a signed body-hash format, a replay window and clock handling, and it does not fit the WebSocket upgrade or streaming uploads, while protecting against little: the signing key lives in the same process as the token. What matters instead is how little a stolen token can do. It lives one hour, the server stores only its hash, and the destructive actions below need an elevated session that a token alone cannot obtain.

### Devices and accounts

```
GET    /v1/devices               {devices: [{id, name, signPub, boxPub, createdAt, lastSeen, current?, new?}]}   `new`: added after the calling device and not yet acknowledged
POST   /v1/devices/invite        201 {code, expiresAt}      one-time code for a new device of this account, valid 10 minutes by default; an elevated session once the account has two or more devices
POST   /v1/devices/{id}/seen     {sig} → 204   the person has seen this device on the calling device; clears its `new` flag. `sig` is the calling device's Ed25519 signature over `ostia-server/seen/v1\n<calling device id>\n<target device id>`: a stolen session token does not hold that key and cannot silence the warning
DELETE /v1/devices/{id}          204   revokes sessions, the relay label and the device's key wrap; open relay streams close
DELETE /v1/account               204   removes every row and blob, push handles included, and closes the relay listener (elevated session)
```

### Actions that need the device key

Some actions change who belongs to the account, so a bearer token alone is not enough: the request must also be signed with the calling device's Ed25519 key (the key registered with the device). The signature goes in `X-Device-Signature` (unpadded base64url) over a prefixed message that names the device and the target:

| Action | Message |
|---|---|
| `POST /v1/devices/invite` | `ostia-server/invite/v1\n<device id>\n<timestamp>`; also send `X-Device-Timestamp` (milliseconds, within two minutes of the server clock, and larger than the device's previous one, so a captured request cannot be replayed) |
| `POST /v1/auth/elevation/approval` | `ostia-server/elevate/v1\n<device id>\n<timestamp>`, with `X-Device-Timestamp` as for invites |
| `DELETE /v1/devices/{id}` | `ostia-server/revoke/v1\n<device id>\n<target id>` |
| `POST /v1/auth/approvals/{id}/approve` | `ostia-server/approve/v1\n<approver id>\n<approval id>\n<requester id>` |
| `POST /v1/devices/{id}/seen` | body `{sig}` over `ostia-server/seen/v1\n<viewer id>\n<target id>` |

A missing signature answers `403 device-signature-required`, a wrong one `403 bad-signature`, an old or reused timestamp `403 stale-signature`. A stolen session token therefore cannot add, remove or approve devices. An approval is also refused (`403 requester-too-new`) when the device asking for elevation has not belonged to the account for `auth.approver_min_age`, whoever approves.

### Revoking devices

Revoking another device or the account normally needs an elevated session. Exceptions, so an owner can always remove an intruder: a device may revoke a device that is still younger than `auth.approver_min_age` (probation) and was added after it, without elevation, and a device may revoke itself without elevation only while an older active device remains (a token alone cannot remove an account's oldest device, even when the account is new). `DELETE /v1/auth/session` (sign out) is always free. A client should show every device with `new: true` to the person and keep asking until they acknowledge it; a relay listener receives `{"t": "device-added", "deviceId", "name", "createdAt"}` when a device joins an account that already had one, and again for every unacknowledged device each time it connects (so a listener that was replaced or offline still learns of it).

### Elevated sessions

A stolen bearer token must not be able to destroy an account. These actions need a session that was elevated within the last `auth.elevation_ttl` (five minutes), otherwise they answer `403 elevation-required`: revoking another device, deleting the account, deleting a sync wrap, replacing the passphrase or recovery wrap, `POST /v1/sync/gc` and `POST /v1/sync/rotate`. A session is elevated one of two ways, per session and never for the approving device. Adding a device must not be a way around this, so `POST /v1/devices/invite` also needs an elevated session once the account has two or more devices **counting invites that are still open** (one stolen token cannot mint several invites while the count is one), and an invite minted without elevation stops working if the account has grown to two devices before it is redeemed, and a device may approve only after it has been part of the account for `auth.approver_min_age` (24 hours, longer than a session lives): a stolen token that adds a device of its own cannot use that device to approve itself (`403 device-too-new`).

```
GET  /v1/auth/elevation                          {elevatedUntil}              0 when not elevated

POST /v1/auth/elevation/approval                 201 {approvalId, expiresAt}  409 no-second-device with one device; signed with the device key
GET  /v1/auth/approvals                          {approvals: [{id, deviceId, deviceName, deviceCreatedAt, createdAt, expiresAt}]}   requests from the account's other devices
POST /v1/auth/approvals/{id}/approve             204   403 for the requesting device itself
GET  /v1/auth/approvals/{id}                     {status: "pending"|"approved", elevatedUntil?}   the requester polls
DELETE /v1/auth/approvals/{id}                   204   only the requesting device may cancel its own request; an approver who does not want to approve simply lets it expire

POST /v1/auth/elevation/github                   like /v1/auth/github/device, for a GitHub account; 409 not-a-github-account
POST /v1/auth/elevation/github/poll {flowId}     200 {elevatedUntil} | 202 pending | 403 wrong-account
```

The approving device must show who is asking (`deviceName`) and how long that device has existed (`deviceCreatedAt`, "added 3 minutes ago"), and approve only on the person's click. A client should also tell the person on every device when `GET /v1/devices` shows a device it has not seen before.

## Relay

The relay forwards a phone's TLS connection to the desktop without terminating it. The phone keeps pinning the desktop gateway's certificate, so the relay cannot read or alter the traffic.

```
POST /v1/relay/label   200 {label, host, port: 443}
```

The label is a random 128-bit value (26 characters, `a-z2-7`), stable per device. `host` is `<label>.<relay domain>`. The phone connects to `host:443` and verifies the desktop's pinned certificate fingerprint, not the name. DNS for `*.<relay domain>` points at the server.

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

A share is one file (the Ostia portable artifact, at most `publish.max_file_bytes`) at `https://<id>.<share domain>/`. Every share has its own origin.

### Modes

| Mode | Key | Server holds |
|---|---|---|
| `link` | 256-bit key in the URL fragment: `https://<id>.<share domain>/#k=<base64url>` | ciphertext |
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

### Share host

All requests are served by Host: `<id>.<share domain>`.

| Path | Answer |
|---|---|
| `GET /` | The fixed shell page. A public share returns the file itself instead, with `Content-Security-Policy: sandbox allow-scripts`. |
| `GET /meta` | `{v: 1, mode, size, salt, expiresAt}`; `404` unknown or not uploaded, `410` expired or removed |
| `GET /blob` | The ciphertext; counts one view |
| `POST /report` | `{reason}` as above, for the shell's report button |
| `GET /shell.js`, `/crypto.js`, `/shell.css` | The shell's static assets |

The shell fetches `/meta` and `/blob`, decrypts with WebCrypto and renders the file in `<iframe sandbox="allow-scripts" srcdoc>`. Responses carry `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin`, `X-Robots-Tag: noindex` and `Cache-Control: no-store`. The server sets no cookies and stores no addresses or user agents; it counts views only.

Expired shares are removed hourly (`publish.sweep_interval`). `ostia-server admin takedown <id>` disables a share and deletes its content at once.

## WebSocket messages

Only the relay uses WebSocket. Control frames are JSON text; relayed bytes are binary.

| Socket | Direction | Message |
|---|---|---|
| `/v1/relay/listen` | server to desktop | `{"t": "ping"}` |
| `/v1/relay/listen` | server to desktop | `{"t": "incoming", "stream": string, "peer": "ip:port", "family": 4 or 6}` |
| `/v1/relay/listen` | server to desktop | `{"t": "device-added", "deviceId": string, "name": string, "createdAt": ms}` |
| `/v1/relay/listen` | desktop to server | `{"t": "pong"}` |
| `/v1/relay/listen` | desktop to server | `{"t": "confirm", "stream": string}` |
| `/v1/relay/accept/{stream}` | both | binary frames: the phone's TCP stream |

Close codes: 1008 when a newer listener replaced this one, the device was removed, the session ended, or the pongs stopped; 1001 when the server shuts down.

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
{"counter": 7, "files": {"settings.json": {"blobId": "…", "hash": "…"}}, "devices": [{"id": "…", "name": "…"}]}
```

The server stores sealed manifests with a monotonically increasing `version`. It keeps the newest `sync.manifest_history`, plus the last version of each of the previous `sync.manifest_checkpoint_days` days, so a flood of writes from a stolen token cannot push every earlier version out of the history.

**Rollback guard.** Each device remembers the highest `counter` it has seen and refuses a manifest with a lower one (`stale-manifest`). A server that serves an old manifest is caught as soon as a device has seen a newer one.

### Wrapping `K`

All wraps are opaque to the server.

- `passphrase` and `recovery` slots: `0x01 || memoryKiB (4 bytes BE) || passes (1) || lanes (1) || salt (16) || nonce (12) || AES-256-GCM(argon2id(secret, salt, passes, memoryKiB, lanes) → 32 bytes, K)`, AAD = `"ostia-sync/wrap/passphrase/v1"` followed by the first 23 header bytes. Production parameters are 64 MiB, 3 passes, 4 lanes.
- `device:<deviceId>` slot: `0x01 || ephemeral X25519 public key (32) || nonce (12) || AES-256-GCM(wrapKey, K)` with `wrapKey = HKDF-SHA256(X25519(ephemeral, deviceBoxPub), salt = empty, info = "ostia-sync/wrap/device" || ephemeralPub || deviceBoxPub, 32)` and AAD = the first 33 bytes.

A new device gets `K` from the passphrase, the recovery key, or from a signed-in device that uploads the device wrap after the person approves it.

### API

```
GET  /v1/sync/manifest[?version=N]    {version, blob, updatedAt}; 404 no-manifest
PUT  /v1/sync/manifest                {blob}; If-Match: <current version, 0 for none> → 200 {version}
                                      412 {error: "version-mismatch", current}; 428 without If-Match
GET  /v1/sync/manifest/versions       {versions: [{version, updatedAt}]}
GET  /v1/sync/blobs/{blobId}          raw bytes
PUT  /v1/sync/blobs/{blobId}          raw bytes → 201 created | 200 identical | 409 | 413 | 507
GET  /v1/sync/wraps                   {wraps: [{slot, updatedAt}]}
GET  /v1/sync/wraps/{slot}            {slot, blob, updatedAt}
PUT  /v1/sync/wraps/{slot}            {blob} → 204        slot: passphrase | recovery | device:<id of an active device>; an unelevated session may only fill an empty slot; replacing any existing wrap needs an elevated session. Wraps carry no sender signature yet, so a client must not adopt a new profile key from a wrap it did not ask for (tracked as a follow-up: signed wraps)
DELETE /v1/sync/wraps/{slot}          204
POST /v1/sync/rotate                  {ifMatch, manifest, wraps: {slot: blob}, deleteSlots: [slot]} → 200 {version} | 412
POST /v1/sync/gc                      {keep: [blobId]} → {deleted}     removes blobs older than sync.gc_grace that are not listed
GET  /v1/sync/usage                   {blobs, bytes, quotaBytes}
```

### Client algorithm

1. `GET manifest`; open it; refuse a counter lower than the highest seen. Fetch and open the blobs it lists; check each content hash.
2. Merge per key with the last synced state as base. Upload blobs whose id the remote manifest does not list, then `PUT manifest` with `If-Match: <version read>` and `counter = highest + 1`.
3. On `412`, repeat from step 1 (the reference client tries three times).
4. A manifest that does not open with `K` means the key was rotated: read the `device:<own id>` wrap, unwrap the new key, retry.

### Removing a device

`DELETE /v1/devices/{id}` ends its sessions and deletes its wrap. The remaining device then generates a new `K'`, re-seals every blob and the manifest under it, and sends one `POST /v1/sync/rotate` with the new manifest, the new passphrase wrap, a recovery wrap only if the person re-entered the recovery key (otherwise the slot is deleted), and a device wrap for every remaining device. The server swaps manifest and wraps in one transaction. A removed device keeps what it already decrypted; rotation protects what comes after.

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
| 403 | `forbidden`, `invalid-invite`, `denied`, `device-too-new`, `wrong-account`, `invalid-ticket`, `elevation-required`, `public-disabled`, `publish-disabled` |
| 404 | `not-found`, `no-manifest`, `unknown-flow`, `unknown-device` |
| 409 | `conflict`, `blob-exists`, `already-uploaded`, `device-limit`, `no-second-device`, `not-a-github-account` |
| 410 | `gone`, `expired` |
| 412 | `version-mismatch` |
| 413 | `too-large` |
| 428 | `precondition-required` |
| 429 | `rate-limited` |
| 501 | `platform-unavailable` |
| 502 | `delivery-failed`, `github-unavailable`, `upstream-unavailable`, `upstream-failed` |
| 503 | `busy` |
| 507 | `quota-exceeded` |
