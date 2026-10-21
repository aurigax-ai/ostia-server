# Configuration

`ostia-server -config ostia-server.toml` (or `OSTIA_SERVER_CONFIG`). Unknown keys are an error, so a mistyped key never goes unnoticed. Durations use Go syntax (`90s`, `10m`, `720h`). [`deploy/ostia-server.example.toml`](../deploy/ostia-server.example.toml) lists every key with its default and is loaded by a test, so it cannot drift.

## Top level

| Key | Default | |
|---|---|---|
| `data_dir` | `./data` | SQLite database, blobs and `server.key`. Created with mode 0700. |
| `log_level` | `info` | `debug`, `info`, `warn`, `error`. The server logs no addresses and no share or sync access. |

## `[domains]`

| Key | Default | |
|---|---|---|
| `api` | required | Host of the HTTP API. |
| `share` | required with `publish` | A separate registrable domain for published pages, so shares never share an origin with the API. Each share is `<id>.<share>`. |
| `relay` | required with `relay` | Phones connect to `<label>.<relay>`. Must not be a parent of `api`. |
| `scheme` | `https` | `http` only for local development; it changes the URLs the server hands out. |

## `[listen]` and `[tls]`

| Key | Default | |
|---|---|---|
| `listen.https` | `:443` | The SNI router: relay hosts are passed through, other hosts are terminated or forwarded (see `tls.mode`). Required by the relay. Empty to disable. |
| `listen.http` | empty | Plain HTTP for use behind a reverse proxy that terminates TLS. Serves the API and share hosts by `Host`. |
| `listen.client_ip_header` | empty | Header that carries the client address when a trusted proxy sits in front (`X-Forwarded-For`, `CF-Connecting-IP`). Used only for rate limiting. |
| `tls.mode` | `files` | `files`: terminate TLS with the certificates below. `forward`: pass non-relay connections, untouched, to `tls.forward_addr` (a proxy that holds the certificates). |
| `tls.forward_addr` | empty | `host:port` for `forward`. |
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
| `invite_ttl` | `168h` | Default lifetime of `admin invite` codes. |
| `device_invite_ttl` | `10m` | Lifetime of a code a signed-in device mints for a new device. |

## `[relay]`

| Key | Default | |
|---|---|---|
| `max_streams_per_label` | `8` | Concurrent phone connections per desktop. |
| `connections_per_minute` | `30` | New connections per desktop. |
| `connections_per_minute_per_ip` | `10` | New connections per source address. |
| `monthly_bytes_per_account` | `5368709120` | Relayed bytes per account and month; `0` is unlimited. |
| `idle_timeout` | `10m` | A stream with no bytes is closed. |
| `ping_interval` | `25s` | Control-socket ping. |
| `accept_timeout` | `10s` | How long a phone connection waits for the desktop to accept it. |
| `hello_timeout` | `5s` | How long a connection may take to send its ClientHello; unknown labels are held this long before closing. |
| `max_pending_hellos` | `1024` | Connections allowed to be mid-handshake at once. |

## `[publish]`

| Key | Default | |
|---|---|---|
| `max_file_bytes` | `16777216` | |
| `max_shares_per_account`, `max_bytes_per_account` | `100`, `524288000` | |
| `min_expiry`, `default_expiry`, `max_expiry` | `1m`, `720h`, `8760h` | |
| `allow_never` | `false` | Allow shares that never expire. Intended for self-hosted instances. |
| `allow_public` | `true` | Allow plaintext public shares. Owners must still choose them explicitly. |
| `sweep_interval` | `1h` | How often expired shares are removed. |

## `[sync]`

| Key | Default | |
|---|---|---|
| `max_blob_bytes`, `max_manifest_bytes` | `16777216`, `4194304` | |
| `quota_bytes` | `536870912` | Blob storage per account. |
| `manifest_history` | `10` | Sealed manifest versions kept for recovery. |
| `gc_grace` | `1h` | `POST /v1/sync/gc` never removes blobs younger than this, so a device that is still uploading is safe. |

## `[push]`

| Key | Default | |
|---|---|---|
| `max_handles` | `100000` | Push registrations the server accepts. |
| `fcm.service_account_file` | empty | Firebase service account JSON. `fcm.endpoint` overrides the API base for testing. |
| `apns.key_file`, `key_id`, `team_id`, `topic`, `production` | empty | Apple token-based credentials (`.p8`). `apns.endpoint` overrides the API base for testing. |
