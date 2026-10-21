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

## Backups

Back up `data_dir` as a whole: `ostia.sqlite` (copy it with `sqlite3 ostia.sqlite ".backup backup.sqlite"` while running), `blobs/` and `server.key`. `server.key` seals push tokens and keys the GitHub-id hashes; without it GitHub users would get new accounts and push registrations would stop opening.

## Administration

```
ostia-server admin invite [-ttl 168h]
ostia-server admin accounts
ostia-server admin reports
ostia-server admin takedown <share-id>
ostia-server admin disable-publish <account-id>
ostia-server admin enable-publish <account-id>
ostia-server admin delete-account <account-id>
```

These work against the same data directory while the server is running. A reported share is disabled with `takedown`; its content is deleted and the share page says it was removed. Repeat abuse is handled with `disable-publish`.

## Privacy defaults

No access logs, no addresses or user agents stored, view counts only. Addresses are held in memory for rate limiting and for the lifetime of a relayed connection. Telemetry and analytics do not exist.

## Upgrading

Replace the binary and restart. The database migrates itself and refuses to open a schema newer than the binary understands.

## Accounts with one device

Adding a third device, revoking another device, deleting the account, deleting or replacing sync key wraps, garbage collection and key rotation need an elevated session: another device of the account approves, or the owner signs in with GitHub again. A device must belong to the account for 24 hours before its approval counts (`auth.approver_min_age = 0` switches that protection off and is for tests only), so a stolen session cannot approve itself with a device it just added. An account with a single device that did not sign in with GitHub cannot elevate. The operator can still run `admin delete-account`; the other actions wait until a second device is added.
