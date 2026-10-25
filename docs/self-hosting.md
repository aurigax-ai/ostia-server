# Self-hosting

The server is one process with one config file. Nothing here deploys anything for you; these are the pieces to put in place.

## DNS

Two names. Shares are paths of the API host (`https://api.example.com/s/<id>`), so they need no name of their own:

| Record | Points at |
|---|---|
| `api.example.com` | the server (the API, the admin UI and the shares) |
| `*.r.example.com` | the server (relay hosts; no certificate is needed for these) |

The relay keeps one hostname per desktop because its TLS is end to end and routed by SNI; see [why](design.md#the-relay-passes-tls-through). Shares run on the API's origin, which is why the shell is strict and every artifact is sandboxed ([why](design.md#shares-run-on-the-apis-origin-so-the-shell-is-strict-and-the-artifact-is-sandboxed)).

Only port 443 has to be reachable.

## Certificates

Relay traffic is never terminated, so the relay domain needs no certificate. The API host needs one, and it covers the shares too:

- API: a certificate for `api.example.com`. Any ACME client works; no wildcard and no DNS challenge are needed.

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

The proxy listens on `127.0.0.1:8443`, terminates TLS for the API host, and proxies to `listen.http`. The server connects to the proxy with a PROXY protocol v2 header, so the proxy sees the real client address. Configure the proxy to read it and to put the address in `X-Forwarded-For`; for example nginx `listen 8443 ssl proxy_protocol; set_real_ip_from 127.0.0.1; real_ip_header proxy_protocol;` with `proxy_set_header X-Forwarded-For $remote_addr;`, or Caddy's `proxy_protocol` listener wrapper. List the proxy under `listen.trusted_proxies`: only its connections may set the header, and the rightmost address that is not a trusted proxy is taken as the client, so a forged header cannot move or share a rate-limit bucket. **Upgrading:** `forward_proxy_protocol` defaults to `true`. A forward-mode deployment whose proxy does not read PROXY protocol stops working until the proxy is configured to read it or `forward_proxy_protocol = false` is set. A proxy that cannot read PROXY protocol needs `forward_proxy_protocol = false`, and then every client appears to come from the proxy's address on the relay path only (the API still sees the header). Relay hosts never reach the proxy.

Without the relay you can drop `listen.https` entirely and run only `listen.http` behind the proxy.

### Behind a proxy that passes the relay through

When the proxy owns port 443 for every name (a cloud load balancer, Envoy Gateway, an ingress), the server needs no `listen.https` at all: the proxy terminates TLS for the API host and sends it to `listen.http`, and passes the relay hosts through, still encrypted, to `listen.relay`.

```toml
[domains]
api = "sync.ostia.example.com"
relay = "relay.ostia.example.com"

[listen]
https = ""
http = ":8080"
relay = ":8443"
client_ip_header = "X-Forwarded-For"
trusted_proxies = ["10.1.4.0/28"]

[modules]
relay = true
publish = true
```

`trusted_proxies` is the address range of the proxy pods only (a placeholder: use the Envoy pods' real addresses), never a whole pod network. The proxy must send a PROXY protocol v1 or v2 header on the relay connection, because the server cannot see through the phone's TLS to learn who is calling and every per-address limit (connections, unconfirmed opens, pending hellos) keys on that address. The header is believed only from `trusted_proxies`, and a trusted address that sends none is dropped. Anything else that can open a connection to a trusted address can claim any client address, so `trusted_proxies` should list the proxy's addresses and a network policy (or firewall) must restrict who can reach `listen.relay` and `listen.http` to the proxy.

DNS for this layout: `sync.ostia.example.com` and `*.relay.ostia.example.com` point at the proxy. The proxy holds a certificate for the first; the relay hosts need none, because the phone checks the desktop's pinned certificate, not a name.

#### Example: Envoy Gateway

Add a listener beside the existing HTTPS listener on the same Gateway. It matches on SNI, passes the stream through, and never holds a certificate:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: lab
  namespace: envoy-gateway-system
spec:
  gatewayClassName: envoy
  listeners:
    - name: https
      protocol: HTTPS
      port: 443
      tls:
        mode: Terminate
        certificateRefs:
          - name: ostia-sync-tls
      allowedRoutes:
        namespaces:
          from: All
    - name: ostia-relay
      protocol: TLS
      port: 443
      hostname: "*.relay.ostia.example.com"
      tls:
        mode: Passthrough
      allowedRoutes:
        namespaces:
          from: All
        kinds:
          - kind: TLSRoute
```

Route the relay hosts to the server's relay port, and have Envoy send PROXY protocol v2 to that backend:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: TLSRoute
metadata:
  name: ostia-relay
  namespace: ostia-server
spec:
  parentRefs:
    - name: lab
      namespace: envoy-gateway-system
      sectionName: ostia-relay
  hostnames:
    - "*.relay.ostia.example.com"
  rules:
    - backendRefs:
        - name: ostia-server-relay
          port: 8443
---
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: BackendTrafficPolicy
metadata:
  name: ostia-relay
  namespace: ostia-server
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: TLSRoute
      name: ostia-relay
  proxyProtocol:
    version: V2
---
apiVersion: v1
kind: Service
metadata:
  name: ostia-server-relay
  namespace: ostia-server
spec:
  selector:
    app: ostia-server
  ports:
    - name: relay
      port: 8443
      targetPort: relay
```

The pod exposes `containerPort: 8443` as `relay`. Add `8443` next to `8080` in a NetworkPolicy that admits only the Gateway's Envoy pods. This is required, not optional: the PROXY header is believed from every address in `trusted_proxies`, so anything else that can open a connection to the relay port could claim any client address. The API and share hosts keep their HTTPRoute to `listen.http` (the share HTTPRoute lists `*.share.ostia.example.com`).

## Sign-in

- **Invite codes** (always on): `ostia-server admin invite`, then paste the code into the desktop app.
- **GitHub**: create a GitHub OAuth App, tick "Enable Device Flow", put its client id in `auth.github_client_id`. No client secret is stored.
- The admin web UI signs in with GitHub through its own OAuth App, see [Admin web UI](#admin-web-ui).

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
ostia-server admin invite [-ttl 168h] [-account <account-id>]
ostia-server admin backup -recipient <age1...> -out <file>
ostia-server admin setup
ostia-server admin reset
ostia-server admin logout-all
ostia-server admin audit [-n 50]
ostia-server admin accounts
ostia-server admin reports
ostia-server admin takedown <share-id>
ostia-server admin disable-publish <account-id>
ostia-server admin enable-publish <account-id>
ostia-server admin delete-account <account-id>
```

`invite` refuses a ttl of zero or below and one longer than `auth.invite_ttl`: a code always expires. With `-account`, the code adds a new device to that account instead of making a new account (see [Accounts and devices](#accounts-and-devices)). These work against the same data directory while the server is running. A reported share is disabled with `takedown`; its content is deleted and the share page says it was removed. Repeat abuse is handled with `disable-publish`.

### Admin web UI

A small web UI for the operator: create and revoke invites, list accounts, see an account's devices and sizes, delete an account. It shows ids, device names, sizes and times only, never synced content, and it does not remove single devices (that stays with the account's own devices, so signed actions keep their meaning). It is off by default:

```toml
[admin]
enabled = true
github_client_id = "Ov23liAbCdEfGhIjKlMn"
github_client_secret_file = "/run/secrets/ostia-admin-github-client-secret"
```

Sign-in is GitHub only. Register a GitHub OAuth App for it (separate from the app behind `auth.github_client_id`, which the desktop app uses with the device flow):

1. GitHub, Settings, Developer settings, OAuth Apps, New OAuth App. An organisation's own settings work too.
2. Homepage URL `https://<domains.api>/admin/`. Authorization callback URL exactly `https://<domains.api>/admin/github/callback`, with the same scheme and port as `domains.scheme` and `domains.port` (for `sync.ostia.apogex.dev`: `https://sync.ostia.apogex.dev/admin/github/callback`). Leave "Enable Device Flow" off.
3. Copy the client id into `admin.github_client_id`.
4. Generate a client secret and give it to the server as a file (`admin.github_client_secret_file`, mounted from a secret store; trailing whitespace is ignored; the server refuses a file readable by group or others, so mount a Kubernetes secret with `defaultMode: 0400` and no `fsGroup` read bit, or use the variable) or as the environment variable `OSTIA_ADMIN_GITHUB_CLIENT_SECRET`. Set one, not both. The secret is never read from the TOML, which is meant to live in git. With `admin.enabled = true` the server refuses to start without the id and the secret. A GitHub Enterprise server uses `auth.github_base_url` and `auth.github_api_url`.

First-time setup, on a server that has no admin yet:

```sh
ostia-server admin setup
# docker compose exec ostia-server /usr/local/bin/ostia-server admin setup
# kubectl -n <namespace> exec -it deploy/<ostia-server> -- /usr/local/bin/ostia-server admin setup
```

The command prints a one-time setup code and the address. The code works once, for 10 minutes, and only while no admin exists; asking for a new one voids the old one. Open `https://<domains.api>/admin/`: with no admin the page reads **Set up admin**. Enter the code, choose **Continue with GitHub** and authorise the app. The GitHub account that returns becomes the site admin: its numeric id (not its name, which can change) is stored in the database and the code is spent. From then on the page only offers **Sign in with GitHub**, and only that stored id gets a session (8 hours).

If the admin account is lost or must change hands, run `ostia-server admin reset` in the pod. It removes every admin, every admin session and every pending code or sign-in, and is audited. The server is then back at first-time setup. Nothing else is touched: accounts, invites and synced data stay.

The route is on the API host only, so it is reachable wherever the API is, and nowhere on the relay domain; a share route under `/s/` is never answered by it. Behind a proxy that terminates TLS, forward `/admin` like the rest of the API, keep HTTPS (the cookies are `Secure`) and list the proxy under `listen.trusted_proxies`. A proxy that is not listed makes every client share the proxy's address, so the per-address limits below apply to everyone together.

What protects it:

- GitHub uses the web redirect flow (never the device flow) with a one-time `state` and PKCE (S256). The state is random, stored hashed, single use and valid for 10 minutes, and it is bound to the browser that started the sign-in by a `__Host-ostia_admin_oauth` cookie (`HttpOnly; Secure; SameSite=Strict; Path=/`, ten minutes) that is compared in constant time. The PKCE verifier waits next to the hashed state in the database for those ten minutes; it is useless without the matching GitHub code. GitHub returns to `/admin/github/callback`, which holds no secret and only hands the browser on to `/admin/github/finish` as a navigation from this site; that is what lets the Strict cookie travel. A callback without the cookie, with another browser's state, with a used or expired state, or with an error from GitHub is refused and signs nobody in.
- Setup needs both the code and a GitHub sign-in in the same flow. The code carries 100 bits, is stored hashed, is checked when the flow starts and spent in one database transaction together with storing the admin, and that transaction fails if an admin exists by then. Failed code attempts are limited per address (five, then one every 12 seconds) and overall (30, then one every 2 seconds); a valid code is never held back by the overall limit. The start and callback routes are limited per address. A refused attempt is logged without the code, the state, any GitHub code or token, and without an address.
- The GitHub access token is used once to read the account id and login, then revoked at GitHub (`DELETE /applications/{client_id}/token`; a failure is logged and does not block the sign-in) and dropped. The client secret goes only to GitHub's token endpoint.
- The session cookie is `__Host-ostia_admin`, so the browser accepts it only from this host over HTTPS with `Path=/` and no `Domain`, and refuses a cookie of that name set by any other host, including a sibling under the same registrable domain. Every such cookie in a request is still checked and the one that matches a live session wins, so a planted cookie cannot sign the admin out.
- A session is tied to its admin's row: it works only while that admin still exists, so `admin reset` ends every session at once, and sign-in and session creation happen in one transaction. Sessions also end at the next server start, and `ostia-server admin logout-all` ends them at any time (it is audited). Use it if a cookie may have leaked.
- The session is a random token stored hashed, in a cookie that is `HttpOnly; Secure; SameSite=Strict; Path=/` (required by the `__Host-` prefix; the server reads it only on `/admin`). Every state-changing request also needs a CSRF token that belongs to the session, and must be same-origin: `Sec-Fetch-Site: same-origin`, or, from a browser that sends no fetch metadata, an `Origin` equal to the API's origin (`Origin: null` is refused). There is no CORS.
- Pages carry a strict Content-Security-Policy (no inline script or style, no external origin); the assets are embedded in the binary.
- Every action (setup code issued, setup, sign-in, refusal with its reason, sign-out, invite created or revoked, account deleted, reset) is written with its time, who did it (`github:<numeric id>`, which never changes, with the login as the target of setup and sign-in rows; `anonymous` for a refusal; or `cli`) and the target (the login, the reason with the GitHub id, or the object id). Cheap unauthenticated refusals (`state-mismatch`, `state-unknown`, a wrong setup code at the start) are logged each time but counted in the table: one row per reason per minute, shown as `state-mismatch x37` to the `admin_audit` table and to the log. Read it with `ostia-server admin audit`. The row is written after the action; if the database refuses it the action still stands and the failure is logged.
- Deleting an account removes its devices, sessions, key wraps, sync blobs and manifests, shares and push registrations, and disconnects its relay streams; the blob files are deleted from disk. It cannot be undone.

## Privacy defaults

No access logs, no addresses or user agents stored, view counts only. Addresses are held in memory for rate limiting and for the lifetime of a relayed connection. A device's last activity is stored as a day, not a time, and a revoked device is deleted after a retention period. Telemetry and analytics do not exist.

## Upgrading

Replace the binary and restart. The database migrates itself and refuses to open a schema newer than the binary understands.

## Accounts and devices

A plain `admin invite` code makes a new account with one device. A second computer joins an existing account in one of two ways:

- GitHub sign-in with the same GitHub user, on a server that sets `auth.github_client_id`. This needs nothing from the operator.
- An account invite. Find the account id with `admin accounts`, then run `ostia-server admin invite -account <account-id>` and give the code to the person. The code works once, expires like any invite, and stops working when the account is deleted. Only the operator can mint it: no device and no API can.

The new computer then enters the sync passphrase once. No action needs another device's approval. The server has no API that removes a device or deletes an account: run `admin delete-account`, or let the inactivity sweep remove devices that stay silent for `devices.inactive_after`.

The configuration keys `auth.device_invite_ttl`, `auth.elevation_ttl`, `auth.approval_ttl` and `auth.approver_min_age` are removed. The server refuses to start while the file still sets one of them, so remove them before you upgrade.
