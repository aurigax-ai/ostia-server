# Configuration

`ostia-server -config ostia-server.toml` (or `OSTIA_SERVER_CONFIG`). Unknown keys are an error, so a mistyped key never goes unnoticed. Durations use Go syntax (`90s`, `10m`, `720h`). [`deploy/ostia-server.example.toml`](../deploy/ostia-server.example.toml) lists every key with its default and is loaded by a test, so it cannot drift.

## Top level

| Key | Default | |
|---|---|---|
| `data_dir` | `./data` | SQLite database, blobs and `server.key`. Created with mode 0700; the database files are 0600. |
| `log_level` | `info` | `debug`, `info`, `warn`, `error`. The server logs no addresses and no share or sync access. |

## `[domains]`

| Key | Default | |
|---|---|---|
| `api` | required | Host name of the HTTP API (not an IP address). |
| `share` | required with `publish` | A different registrable domain than `api`, judged with the public suffix list (`api.example.com` and `shares.example.com` are refused; the server will not start). A share domain that is itself a public suffix is fine. Each share is `<id>.<share>`. |
| `relay` | required with `relay` | Phones connect to `<label>.<relay>`. Must not be a parent of `api`. |
| `port` | `443`, or `80` with `scheme = "http"` | The port clients use to reach this server from outside (for example a mapped port); it goes into the share and upload URLs and into the relay label answer. |
| `scheme` | `https` | `http` only for local development; it changes the URLs the server hands out. |

## `[listen]` and `[tls]`

| Key | Default | |
|---|---|---|
| `listen.https` | `:443` | The SNI router: relay hosts are passed through, other hosts are terminated or forwarded (see `tls.mode`). Required by the relay. Empty to disable. |
| `listen.http` | empty | Plain HTTP for use behind a reverse proxy that terminates TLS. Serves the API and share hosts by `Host`. |
| `listen.client_ip_header` | `X-Forwarded-For` | Header that carries the client address when a trusted proxy sits in front. Used only for rate limiting. |
| `listen.trusted_proxies` | empty | Addresses or CIDR ranges of the proxies allowed to set that header. Only a connection from one of them is believed, and then only the last address in the header, the one that proxy appended, is the client: entries to its left are never read. Empty means the header is never read. List the proxy's own addresses and not a whole pod or node range: anything inside a listed range that can reach the server directly chooses its own address. |
| `tls.mode` | `files` | `files`: terminate TLS with the certificates below. `forward`: pass non-relay connections, untouched, to `tls.forward_addr` (a proxy that holds the certificates). |
| `tls.forward_addr` | empty | `host:port` for `forward`. |
| `tls.forward_proxy_protocol` | `true` | Send a PROXY protocol v2 header to the proxy so it learns the client's address. The proxy must be set up to read it. |
| `[[tls.certs]]` `cert`, `key` | | PEM files. List one pair per certificate; the first that matches the requested name wins. Reloaded on `SIGHUP`. |

## `[modules]`

| Key | Default | |
|---|---|---|
| `relay`, `publish`, `sync` | `true` | Switch a module off to remove its routes. |
| `push` | `false` | Needs `push.fcm` or `push.apns` credentials. |

## `[auth]`

| Key | Default | |
|---|---|---|
| `github_client_id` | empty | Enables GitHub device-flow sign-in. Create an OAuth app and tick "Enable Device Flow"; no secret is needed. |
| `github_base_url`, `github_api_url` | github.com | For GitHub Enterprise. |
| `session_ttl` | `1h` | Lifetime of a bearer token. |
| `max_devices_per_account` | `10` | |
| `invite_ttl` | `168h` | Default and maximum lifetime of `admin invite` codes. The admin web UI offers 7 days, 1 day and 1 hour, leaving out any that exceed this. Must be positive: a code that never expires is not allowed. |
| `device_invite_ttl` | `10m` | Lifetime of a code a signed-in device mints for a new device. Must be positive. |
| `revoked_device_retention` | `720h` | How long the row of a revoked device is kept before the sweep deletes it. Must be positive. |
| `elevation_ttl` | `5m` | How long a session stays elevated after another device approved it or a fresh GitHub sign-in succeeded. |
| `approval_ttl` | `5m` | How long a request for another device's approval stays open. |
| `approver_min_age` | `24h` | How long a device must have belonged to the account before its approvals count. `0` turns the wait off and removes the protection that stops a stolen session from approving itself with a device it just added; use it for tests only. Otherwise it must be at least `session_ttl`. |

## `[admin]`

The admin web UI at `https://<domains.api>/admin/`. See [Administration](self-hosting.md#admin-web-ui).

| Key | Default | |
|---|---|---|
| `enabled` | `false` | Serve the admin UI. Off, `/admin` does not exist (404) and `ostia-server admin setup` refuses to print a code. The UI is served on `domains.api` only, never on the share or relay domains. Needs a restart to change. Requires the client id and secret below. |
| `github_client_id` | empty | Client id of the GitHub OAuth App used for admin sign-in (web redirect flow). Its callback URL is `https://<domains.api>/admin/github/callback`. Separate from `auth.github_client_id`. Required when `enabled`. |
| `github_client_secret_file` | empty | File holding that app's client secret. The environment variable `OSTIA_ADMIN_GITHUB_CLIENT_SECRET` works instead; set one, not both. The file must not be readable by group or others (0600 or 0400). The secret is never read from the TOML. Required (file or variable) when `enabled`. |

## `[relay]`

| Key | Default | |
|---|---|---|
| `max_streams_per_label` | `8` | Concurrent phone connections per desktop that the desktop confirmed. |
| `max_unconfirmed_per_label` | `4` | Connections the desktop has not confirmed yet (see the protocol). When full, the oldest is evicted. |
| `unconfirmed_timeout` | `15s` | An unconfirmed connection is closed after this long. |
| `connections_per_minute` | `30` | Confirmed streams per desktop and minute. |
| `unconfirmed_opens_per_minute` | `600` | New connections per desktop and minute, confirmed or not. |
| `unconfirmed_opens_per_minute_per_address` | `30` | The same, per source address (IPv6 per /64) and desktop. |
| `connections_per_minute_per_ip` | `10` | New connections per source address. |
| `monthly_bytes_per_account` | `5368709120` | Relayed bytes per account and month; `0` is unlimited. |
| `idle_timeout` | `10m` | A stream with no bytes is closed. |
| `ping_interval` | `25s` | Control-socket ping. |
| `accept_timeout` | `10s` | How long a phone connection waits for the desktop to accept it. |
| `hello_timeout` | `5s` | How long a connection may take to send its ClientHello; unknown labels are held this long before closing. |
| `max_pending_hellos` | `1024` | Connections allowed to be mid-handshake at once. Above three quarters of this, connections that are not TLS are closed at once instead of held. |
| `max_pending_hellos_per_ip` | `16` | Of those, how many one source address may hold. |

## `[publish]`

| Key | Default | |
|---|---|---|
| `max_file_bytes` | `16777216` | |
| `max_shares_per_account`, `max_bytes_per_account` | `100`, `524288000` | |
| `min_expiry`, `default_expiry`, `max_expiry` | `1m`, `720h`, `8760h` | |
| `allow_never` | `false` | Allow shares that never expire. Intended for self-hosted instances. |
| `allow_public` | `true` | Allow plaintext public shares. Owners must still choose them explicitly. |
| `sweep_interval` | `1h` | How often expired shares are removed. |

## `[storage]`

| Key | Default | |
|---|---|---|
| `sqlite_journal` | `wal` | SQLite journal mode, `wal` or `delete`; anything else is refused. Use `delete` when `data_dir` is on NFS or any other network filesystem: WAL keeps a shared-memory index that does not work there. `delete` is slower for concurrent writes and needs exactly one server process on the data. Every process that opens the database, including `ostia-server admin`, reads the same setting; the mode is stored in the file, so opening with the other value converts it. |

## `[sync]`

| Key | Default | |
|---|---|---|
| `max_blob_bytes`, `max_manifest_bytes` | `16777216`, `4194304` | |
| `quota_bytes` | `536870912` | Blob storage per account. |
| `manifest_history` | `10` | Newest sealed manifest versions kept. |
| `manifest_checkpoint_days` | `14` | Also keep the last version of each of this many earlier days. |
| `gc_grace` | `1h` | `POST /v1/sync/gc` never removes blobs younger than this, so a device that is still uploading is safe. |

## `[push]`

| Key | Default | |
|---|---|---|
| `max_handles` | `100000` | Push registrations the server accepts. |
| `max_handles_per_account` | `20` | Push registrations per account. |
| `ticket_ttl` | `10m` | How long a registration ticket stays valid. |
| `ticket_burst` | `3` | Tickets an account may request at once; then one every 10 minutes, so a stolen session cannot cycle the account's handles. |
| `fcm.service_account_file` | empty | Firebase service account JSON. `fcm.endpoint` overrides the API base for testing. |
| `apns.key_file`, `key_id`, `team_id`, `topic`, `production` | empty | Apple token-based credentials (`.p8`). `apns.endpoint` overrides the API base for testing. |
