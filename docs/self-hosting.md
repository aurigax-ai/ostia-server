# Self-hosting

The server is one process with one config file. Nothing here deploys anything for you; these are the pieces to put in place.

## DNS

Three names. The share domain must be on a different registrable domain than the API domain (the server checks with the public suffix list and refuses to start otherwise), so a page on a share can never act as part of the API's site:

| Record | Points at |
|---|---|
| `api.example.com` | the server |
| `*.r.example.com` | the server (relay hosts; no certificate is needed for these) |
| `*.example-share.net` | the server (one subdomain per share) |

Only port 443 has to be reachable.

## Certificates

Relay traffic is never terminated, so the relay domain needs no certificate. The API host and the share domain do:

- API: a certificate for `api.example.com`.
- Shares: a **wildcard** certificate for `*.example-share.net`. Wildcards need the DNS-01 challenge, which the ACME clients below support for most DNS providers:

```sh
lego --email you@example.com --dns cloudflare \
  --domains example-share.net --domains '*.example-share.net' run
```

List the resulting PEM files under `[[tls.certs]]` and send `SIGHUP` (or `systemctl reload ostia-server`) after each renewal. The server does not run ACME itself.

### Behind a reverse proxy

If Caddy, nginx or a load balancer already holds the certificates, keep the relay on port 443 and hand everything else to the proxy:

```toml
[listen]
https = ":443"
http = "127.0.0.1:8080"
trusted_proxies = ["127.0.0.1"]

[tls]
mode = "forward"
forward_addr = "127.0.0.1:8443"
```

The proxy listens on `127.0.0.1:8443`, terminates TLS for the API and share hosts, and proxies to `listen.http`. The server connects to the proxy with a PROXY protocol v2 header, so the proxy sees the real client address. Configure the proxy to read it and to put the address in `X-Forwarded-For`; for example nginx `listen 8443 ssl proxy_protocol; set_real_ip_from 127.0.0.1; real_ip_header proxy_protocol;` with `proxy_set_header X-Forwarded-For $remote_addr;`, or Caddy's `proxy_protocol` listener wrapper. List the proxy under `listen.trusted_proxies`: only its connections may set the header, and the rightmost address that is not a trusted proxy is taken as the client, so a forged header cannot move or share a rate-limit bucket. **Upgrading:** `forward_proxy_protocol` defaults to `true`. A forward-mode deployment whose proxy does not read PROXY protocol stops working until the proxy is configured to read it or `forward_proxy_protocol = false` is set. A proxy that cannot read PROXY protocol needs `forward_proxy_protocol = false`, and then every client appears to come from the proxy's address on the relay path only (the API still sees the header). Relay hosts never reach the proxy.

Without the relay you can drop `listen.https` entirely and run only `listen.http` behind the proxy.

## Sign-in

- **Invite codes** (always on): `ostia-server admin invite`, then paste the code into the desktop app.
- **GitHub**: create a GitHub OAuth App, tick "Enable Device Flow", put its client id in `auth.github_client_id`. No client secret is stored.

## Docker

```sh
cd deploy
cp ostia-server.example.toml ostia-server.toml
mkdir certs
docker compose up -d --build
docker compose exec ostia-server /usr/local/bin/ostia-server admin invite
```

Every push to `main` publishes `ghcr.io/aurigax-ai/ostia-server:main-<short-sha>` and `:main` for `linux/amd64` and `linux/arm64` (the `publish` job in `.github/workflows/ci.yml`). Pin deployments to a `main-<short-sha>` tag. The image sets `OSTIA_SERVER_CONFIG=/etc/ostia-server/ostia-server.toml`, so `ostia-server` and `ostia-server admin ...` both find the config there. Mount the config at that path and set `data_dir = "/var/lib/ostia-server"`, which is the volume the image owns.

The image is distroless and runs as a non-root user; the compose file lowers `net.ipv4.ip_unprivileged_port_start` so it can bind 443.

## systemd

```sh
install -m 0755 ostia-server /usr/local/bin/ostia-server
useradd --system --home /var/lib/ostia-server ostia-server
install -d -o root -g ostia-server -m 0750 /etc/ostia-server
install -m 0640 -g ostia-server ostia-server.toml /etc/ostia-server/
install -m 0644 deploy/ostia-server.service /etc/systemd/system/
systemctl enable --now ostia-server
```

Point `data_dir` at `/var/lib/ostia-server` (the unit's `StateDirectory`).

## Push

Push is off by default. Turn it on with `modules.push = true` and give the server the credentials of the app build whose phones will register. A phone registers only with a ticket that a signed-in desktop of the same account requested, and the desktop's session is needed to ping: a Firebase service account (`push.fcm.service_account_file`) for Android and an Apple token key (`push.apns.*`) for iOS. A self-hosted server therefore pushes to a phone app you built and signed with your own Firebase project and Apple team; the publisher's hosted instance uses the publisher's credentials. The server sees a handle, a timestamp and a platform, nothing else.

## Network filesystems

SQLite's WAL mode needs shared memory and file locks that NFS and other network filesystems do not provide, so a database there can corrupt. If `data_dir` is on one, set

```toml
[storage]
sqlite_journal = "delete"
```

and run exactly one replica (one server process, with no second instance mounting the same directory; `admin` commands on the same host are fine). If the database already exists in WAL mode, switch it while the data is still on local disk: start the server (or run any `ostia-server admin` command) once with `delete` before moving `data_dir` to the network filesystem. Opening a WAL database on NFS, even to convert it, is the unsafe case this setting exists to avoid. The switch needs the database closed by every other process and waits up to five seconds for them.

## Backups

Back up `data_dir` as a whole: the database, `blobs/` and `server.key`. `server.key` seals push tokens and keys the GitHub-id hashes; without it GitHub users would get new accounts and push registrations would stop opening.

Take the database with the server's own command, which copies it consistently while the server runs and encrypts the copy to an [age](https://age-encryption.org) public key. The encrypted file is the only copy that leaves the host:

```
age-keygen -o backup.key                       # once, keep backup.key off the node
ostia-server admin backup -recipient age1... -out /backups/ostia-$(date +%F).sqlite.age
age -d -i backup.key ostia-2026-10-21.sqlite.age > ostia.sqlite     # to restore
```

`-out` must not exist yet and is created with mode 0600. `-out -` writes to standard output instead (refused on a terminal), which is the way to take a backup from a container with a read-only root filesystem and no `tar`:

```
kubectl exec -n ostia-server deploy/ostia-server -- ostia-server admin backup -recipient age1... -out - > ostia.sqlite.age
```

`VACUUM INTO` needs a file, so the command first writes a plaintext copy into a `.backup-scratch-*` directory inside `data_dir` (mode 0700, file mode 0600), encrypts from it and deletes it before returning, also on an error or SIGINT/SIGTERM. A SIGKILL, an out-of-memory kill or a lost `kubectl exec` can leave that directory behind: the server removes any directory with that name prefix in `data_dir` when it starts, and nothing else, so a file you name `backup-<date>.age` there is safe. The freed blocks are not wiped, so the copy is as exposed to the node's disk as the live database is. `blobs/` holds ciphertext only and `server.key` is 32 bytes; copy them with your usual tool, to storage you trust with the key.

Everything the server writes is owner-only (the process sets umask 077, and the database files are forced to 0600 on start). Create `data_dir` mode 0700 as well, so other users on the host cannot list it. The database runs with `secure_delete` on, so deleted rows are overwritten in the database file. In WAL mode the older page images stay in the `-wal` file until a checkpoint; the server truncates the WAL every minute during its sweep and caps it at 4 MiB after a checkpoint (`journal_size_limit`).

## Administration

```
ostia-server admin invite [-ttl 168h]
ostia-server admin backup -recipient <age1...> -out <file>
ostia-server admin accounts
ostia-server admin reports
ostia-server admin takedown <share-id>
ostia-server admin disable-publish <account-id>
ostia-server admin enable-publish <account-id>
ostia-server admin delete-account <account-id>
```

`invite` refuses a ttl of zero or below and one longer than `auth.invite_ttl`: a code always expires. These work against the same data directory while the server is running. A reported share is disabled with `takedown`; its content is deleted and the share page says it was removed. Repeat abuse is handled with `disable-publish`.

## Privacy defaults

No access logs, no addresses or user agents stored, view counts only. Addresses are held in memory for rate limiting and for the lifetime of a relayed connection. A device's last activity is stored as a day, not a time, and a revoked device is deleted after a retention period. Telemetry and analytics do not exist.

## Upgrading

Replace the binary and restart. The database migrates itself and refuses to open a schema newer than the binary understands.

## Accounts with one device

Adding a third device, revoking another device, deleting the account, deleting or replacing sync key wraps, garbage collection and key rotation need an elevated session: another device of the account approves, or the owner signs in with GitHub again. A device must belong to the account for 24 hours before its approval counts (`auth.approver_min_age = 0` switches that protection off and is for tests only), so a stolen session cannot approve itself with a device it just added. An account with a single device that did not sign in with GitHub cannot elevate. The operator can still run `admin delete-account`; the other actions wait until a second device is added.
