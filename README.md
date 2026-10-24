*Guard is a proof-of-concept and is not ready for production use. Please visit [The Roadmap](https://github.com/lighthouse-search/guard/projects) to see what's happening before beta*.

# Why
Writing and mantaining an authentication proxy for each project (e.g. grafana.example.com) is complex and exhausting. Solutions like Cloudflare Access and Tailscale exist but you're deeply integrated into those networks while sacraficing administrative control. Guard aims to be a convinient and self-hostable solution to Identity Access Management without managing your own complex authentication codebases.

Microsoft, Google and Okta/Auth0 control large portions of authentication to sensitive infrastructure, if those services were breached or used for [surveillance](https://www.theguardian.com/world/2013/jun/06/us-tech-giants-nsa-data) the internet's independence would be undermined for the rest of us.

If anything, this is a proof of concept and something I needed to build regardless. I became sick of mantaining a hardcoded NGINX Subrequest responder codebase for each project.

Guard's core mission is:
- Run anywhere, including with or without a database.
- Act as an authentication server for all major authentication protocols (OAuth, SAML, Kerberos)
- Act as an app's authentication. Either via library support in major programming languages or proxying requests to an application.
- Authenticate reverse proxies (e.g. [Guard + NGINX](#integration-examples))

# Example
Guard allows you to create great, styled, authentication with a simple configuration.
![Screenshot 2025-06-22 230233](https://github.com/user-attachments/assets/40fe9c2f-0f9c-449e-a637-81ec4a89796d)


```
[features]
reverse_proxy_authentication = true

[reverse_proxy_authentication.config]
header = "x-original-url"

[frontend.metadata]
instance_hostname = "guard.example.com"
alias = "ACME"
public_description = "You're accessing sensitive information. Please login."
image = "https://example.com/amazing-image.jpg"
domain_placeholder="example.com"
username_placeholder="username"

[database.mysql]
username = "example-user"
password_env = "example_user_mysql_password"
hostname = "mariadb.internal.example.com"
port = 3306
database = "guard"

[smtp]
host="smtp.sendgrid.net"
port=587
username="apikey"
from_alias="Guard"
from_header="noreply@paperplane.example.com"
reply_to_address="noreply@paperplane.example.com"
password_env="smtp_password"

[authentication_methods.email]
active = true
method_type = "email"
should_create_new_users = false

[sql.tables]
user = "users"
device = "devices"
magiclink = "magiclinks"
bearer_token = "bearer_tokens"

[policies.staff_only]
active = true
action = "allow"
property = "email"
ends_with = "@staff.example.com"

[hostname.sydney]
active = true
host = "sydney.example.com"
alias = "Sydney"
authentication_methods = ["email"]
multistep_authentication_methods = false
applied_policies = ["staff_only"]
```

# Quickstart
Grab the archive for your platform from the [latest release](https://github.com/lighthouse-search/guard/releases/latest):

| Platform | Asset |
| --- | --- |
| Linux x86-64 | [`guard-linux-amd64.zip`](https://github.com/lighthouse-search/guard/releases/latest/download/guard-linux-amd64.zip) |
| Linux arm64 | [`guard-linux-arm64.zip`](https://github.com/lighthouse-search/guard/releases/latest/download/guard-linux-arm64.zip) |
| macOS (Apple silicon) | [`guard-darwin-arm64.zip`](https://github.com/lighthouse-search/guard/releases/latest/download/guard-darwin-arm64.zip) |
| Windows x86-64 | [`guard-windows-amd64.zip`](https://github.com/lighthouse-search/guard/releases/latest/download/guard-windows-amd64.zip) |
| Windows arm64 | [`guard-windows-arm64.zip`](https://github.com/lighthouse-search/guard/releases/latest/download/guard-windows-arm64.zip) |

Each archive unzips to a `guard-server` binary alongside `frontend/` (the login
pages) and `example/` (starter configs). Keep them together — the server reads
the frontend from beside the binary.

`guard_config` takes the **contents** of a config file, not a path to one.

## Linux / macOS
```sh
unzip guard-linux-amd64.zip -d guard && cd guard
export guard_config=$(cat ./example/email-config.toml)
./guard-server
```

## Windows
```powershell
Expand-Archive guard-windows-amd64.zip -DestinationPath guard; cd guard
$env:guard_config = Get-Content -Raw .\example\email-config.toml
.\guard-server.exe
```

Guard listens on port 8000; pass `--port <n>` to change it.

`email-config.toml` expects a MySQL database and an SMTP server. Fill in the
`[YOUR ...]` placeholders first — note that `password_env` holds the *name* of
an environment variable, not the password itself, so Guard never needs the
secret written into the config:
```sh
export smtp_password='...'   # [smtp].password_env is already set to this name
```
To build a config of your own, use the [Config Creator](https://lighthouse-search.github.io/guard)
or start from one of the [`example/`](example/) files. For a local development
setup, see [docs/development.md](docs/development.md).

## Docker
```sh
docker run -p 8000:8000 -e guard_config="$(cat ./example/email-config.toml)" ghcr.io/lighthouse-search/guard:latest
```
`:latest` tracks releases from `main`; `:nightly-latest` tracks the nightly
branch. See [Guard + Docker](#guard--docker-guard-as-the-proxy) for a compose
setup where Guard authenticates and proxies to another container.

# Integration examples
Guard has two integration models, controlled by `[features]`:

| Model | Feature flag | How it works |
| --- | --- | --- |
| **Guard as the proxy** | `proxy = true` | Guard receives the request, authenticates it, then proxies to the app itself using the hostname's `proxy_to`. The app needs no published port and is never reachable directly. |
| **Guard as an auth subrequest** | `reverse_proxy_authentication = true` | Your existing proxy asks Guard "is this request allowed?" once per request, then proxies to the app itself. Use this when something else must stay in front of the app. |

The first is the stronger default: if the app is only reachable through Guard, a
misconfigured proxy rule cannot expose it. Reach for the subrequest model when
you already have a proxy that owns the routing.

> Policies attach to a **hostname** (`[hostname.*].applied_policies`), not to an
> authentication method. `AuthMethod` has no `applied_policies` field, and Guard
> does not reject unknown config keys — so putting it under
> `[authentication_methods.*]` is silently ignored and enforces nothing.

### Guard + Docker (Guard as the proxy)
Guard authenticates, then proxies to a Grafana container that publishes no ports
at all — so the only route to Grafana is through Guard. `nginx` here only
terminates TLS and hands both hostnames to Guard, which routes on `Host`.

`docker-compose.yml`:
```yaml
services:
  guard:
    image: ghcr.io/lighthouse-search/guard:latest
    expose:
      - "8000/tcp"          # not `ports` — reachable only on the compose network
    environment:
      # Guard reads its whole config from this one env var (TOML).
      guard_config: |
        [features]
        proxy = true

        [frontend.metadata]
        instance_hostname = "guard.example.com"

        [authentication_methods.email]
        active = true
        method_type = "email"

        [policies.staff_only]
        active = true
        action = "allow"
        property = "email"
        ends_with = "@staff.example.com"

        [hostname.grafana]
        active = true
        host = "grafana.example.com"
        alias = "Grafana"
        authentication_methods = ["email"]
        multistep_authentication_methods = false
        applied_policies = ["staff_only"]
        # Where Guard sends the request once the user is authorised. This is a
        # compose service name, resolved on Guard's own network.
        proxy_to = "http://grafana:3000"
    networks: [internal]

  grafana:
    image: grafana/grafana:latest
    expose:
      - "3000/tcp"          # deliberately not published to the host
    environment:
      GF_SERVER_ROOT_URL: "https://grafana.example.com"
    networks: [internal]

networks:
  internal:
```

The TLS terminator in front. Both hostnames go to Guard — Grafana is never an
upstream here, which is what keeps it off the internet:
```nginx
# Docker's embedded DNS, so upstreams resolve per request rather than at startup
# (otherwise nginx fails to boot whenever Guard isn't up yet).
resolver 127.0.0.11 valid=30s;

server {
    listen 443 ssl;
    server_name guard.example.com grafana.example.com;

    ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    location / {
        # Guard picks the [hostname.*] block from Host, so it must survive the hop.
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;

        # Grafana can import large dashboards; the nginx default is 1m.
        client_max_body_size 50m;

        # A variable forces per-request DNS resolution via the resolver above.
        set $guard_upstream "http://guard:8000";
        proxy_pass $guard_upstream;
    }
}
```

> Guard does not proxy WebSockets yet, so do not add the `Upgrade`/`Connection`
> headers for a `proxy_to` app. Anything needing WebSockets (Grafana Live, for
> example) will fail to upgrade rather than silently bypass the auth gate.

### Guard + standard NGINX (auth subrequest)
Set `reverse_proxy_authentication = true`. NGINX asks Guard about each request
with `auth_request`, and proxies to the app itself on a 200:
```nginx
server {
    listen 443 ssl;
    server_name grafana.example.com;

    ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    # Guard's authorisation subrequest. `internal` keeps it unreachable from outside.
    location = /guard-auth {
        internal;
        proxy_pass              http://guard:8000/guard/api/proxy/authentication;
        # A subrequest carries no body, and Guard only needs the cookies and Host.
        proxy_pass_request_body off;
        proxy_set_header        Content-Length "";
        # Guard resolves which [hostname.*] applies from Host. proxy_pass would
        # otherwise set it to the upstream name and no hostname would match.
        proxy_set_header        Host $host;
        proxy_set_header        X-Original-URI $request_uri;
    }

    location / {
        auth_request /guard-auth;
        # Guard answers 401 when the user is not authenticated or fails a policy.
        error_page 401 = @guard_login;

        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        proxy_pass http://grafana:3000;
    }

    location @guard_login {
        return 302 https://guard.example.com/guard/frontend/login?redirect=$scheme://$host$request_uri;
    }
}
```

Notes:
- Guard registers every method (GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS) on
  `/guard/api/proxy/authentication`, so it does not matter which method the
  subrequest uses.
- If you cannot preserve `Host`, send the full original URL instead and tell
  Guard to read it from that header:
  ```toml
  [reverse_proxy_authentication.config]
  header = "x-original-url"
  ```
  Guard accepts either a bare host or a full URL in that header.
- Unlike the `proxy_to` model, the app is still directly reachable on the
  network. Keep it on an internal network or bind it to localhost.

### Guard + NGINX Ingress Controller (Kubernetes)
> **The community `kubernetes/ingress-nginx` controller is retired.** Kubernetes
> SIG Network halted maintenance in **March 2026**; the repository is archived and
> read-only, and no further releases, bugfixes or CVE patches will be issued. Its
> `nginx.ingress.kubernetes.io/auth-url` annotations no longer have a maintained
> implementation. Migrate to F5's `nginxinc/kubernetes-ingress`, which is actively
> maintained, or to the Gateway API.

F5 NGINX Ingress Controller has no native external-auth annotation, so the
`auth_request` wiring goes in snippets. `server-snippets` defines the internal
auth location, `location-snippets` attaches it to the app route:
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: grafana
  annotations:
    nginx.org/server-snippets: |
      location = /guard-auth {
          internal;
          proxy_pass              http://guard.guard.svc.cluster.local:8000/guard/api/proxy/authentication;
          proxy_pass_request_body off;
          proxy_set_header        Content-Length "";
          proxy_set_header        Host $host;
      }
      location @guard_login {
          return 302 https://guard.example.com/guard/frontend/login?redirect=$scheme://$host$request_uri;
      }
    nginx.org/location-snippets: |
      auth_request /guard-auth;
      error_page 401 = @guard_login;
spec:
  ingressClassName: nginx
  rules:
    - host: grafana.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: grafana
                port:
                  number: 3000
  tls:
    - hosts:
        - grafana.example.com
      secretName: grafana-example-com-tls
```

> Snippets are **disabled by default** on this controller: start it with
> `-enable-snippets` (default `false`), or it will *reject* this Ingress outright
> rather than ignore the annotations.

Snippets are discouraged by F5 for anything long-lived. If you would rather not
depend on them, the `proxy_to` model above works unchanged in Kubernetes — point
an Ingress at Guard's Service, give Grafana a ClusterIP Service with no Ingress
of its own, and let Guard do the routing. That also keeps Grafana unreachable
except through Guard, which snippets-based `auth_request` does not.


# WireGuard
Guard can run a WireGuard server and enforce the same policies on tunnel traffic
that it enforces on HTTPS. See [`example/wireguard-config.toml`](example/wireguard-config.toml)
for a complete config, and [`docs/wireguard.md`](docs/wireguard.md) for the
design and roadmap.

Guard owns the whole lifecycle on its host — it generates and persists the
server key, writes the interface config, brings the interface up, and keeps the
live peer list matching its database. You do not run `wg` by hand. Guard must
run on the WireGuard host as root (or with `CAP_NET_ADMIN`), with
`wireguard-tools` installed.

```toml
[wireguard]
interface = "wg0"
peer_subnet = "10.8.0.0/24"
server_address = "10.8.0.1"
endpoint = "vpn.example.com:51820"
service_subnet = "10.9.0.0/24"
# Who may hold a tunnel. Re-checked periodically, not just at registration.
applied_policies = ["staff_only"]

[hostname.homeassistant]
active = true
host = "ha.example.com"
proxy_to = "https://10.0.1.5:8123"
# No public surface: 404 to anything that didn't arrive over the tunnel.
wireguard_only = true
authentication_methods = ["email"]
multistep_authentication_methods = false
applied_policies = ["staff_only"]
```

A device registers its WireGuard public key at `/guard/api/wireguard/register`,
signing the request with its Guard device key (RFC 9421) so the WireGuard key
cannot be swapped in transit. Guard then evaluates `applied_policies` for the
device's user before allocating a tunnel address — a valid device signature
proves *which* device is asking, not that it is allowed a tunnel.

Policy is re-evaluated every `reevaluation_interval_secs` (default 60) for every
registered peer, and a peer that no longer passes is removed from the live
interface. Revocation does not wait for the device to reconnect.

**There is no implicit default for `applied_policies`.** If neither
`[wireguard].applied_policies` nor `[device_authentication].applied_policies` is
set, every registration is denied. A tunnel reaches past the HTTPS layer, so it
is never granted because a config section was forgotten.

### Requirements and limits
- **Enable reverse-path filtering**: `sysctl -w net.ipv4.conf.all.rp_filter=1`.
  Guard decides whether a request arrived over the tunnel from its source
  address; without `rp_filter` the kernel accepts packets forging a source
  inside the peer subnet. Guard logs an error at startup if it finds this off.
- **`wireguard_only` cannot be enforced through `reverse_proxy_authentication`.**
  In that flow Guard only ever sees the reverse proxy's connection, never the
  client's. Guard refuses to start if you combine them rather than letting the
  hostname stay publicly reachable while looking protected.
- Clients receive the same `AllowedIPs` (`peer_subnet` + `service_subnet`)
  regardless of what they may reach, so access changes never require pushing new
  client config. Peer-to-peer traffic is not forwarded.
- Currently HTTPS only: `[hostname.*]` entries are reachable over the tunnel,
  but non-HTTP services (SSH, SMB, printing) need the service-IP proxy described
  in [`docs/wireguard.md`](docs/wireguard.md), which is not built yet.

### Tunnel DNS
Guard runs a resolver on its tunnel address and answers authoritatively for
every active `[hostname.*]`, so a peer asking for `ha.example.com` reaches Guard
over the tunnel rather than going out to public DNS.

```toml
[wireguard]
dns_server = true                        # default when [wireguard] is set
dns_upstream = ["1.1.1.1", "9.9.9.9"]    # where unknown names go
```

`dns_upstream` matters more than it looks. `wg-quick`'s `DNS=` replaces the
client's resolver outright, so a resolver that refused every name it did not own
would leave peers unable to resolve anything at all while connected. Guard
therefore only advertises itself to clients when an upstream is configured —
without one it still runs and still answers for Guard's own names, but clients
are told nothing and keep their existing DNS.

The resolver is not reachable from the internet, enforced three ways:

- It binds `server_address` specifically, never `0.0.0.0`, so only traffic
  destined for the tunnel gateway reaches it.
- Guard **refuses to start it** if `server_address` is publicly routable, so
  mistyping it (or confusing it with `endpoint`) cannot turn Guard into an open
  forwarding resolver, which would be a DNS amplification source.
- Queries whose source is outside `peer_subnet` are refused before any lookup
  happens, so a second route into that range on the host — a container network,
  another VPN — is not enough to use Guard as a resolver.

# Known issues
If you run into an issue, please check https://github.com/lighthouse-search/guard/issues.

# What's on the TODO list?
Before beta:
- SSO/SAML authentication. Guard being able to authentication users via those protocols, and be able to be the identity provider for those protocols. Such as if you want to authentication someone on a NAS/router via guard.
- Better error handling in requests.
- Some syntax improvements.
- Cleaning up where functions are stored and adding comments.
- Ability for Guard to be an app's authentication. Such as authenticating a user, and then proxying all requests, but adding a header identifying the user.
- Implement HCaptcha.
- Magiclink codes need to be hashed / encrypted in the DB.
- Adjustable magiclink expiry.
- Showing account email / ID on access-denied page. Which requires the /user/@me endpoints.

# Code guidelines
- Keep functions to <50 lines of code, with small exceptions, excluding code comments. If you go over 50 lines, you should consider if you're doing too much. Read-able code is very important.
- Do not add non-standard/not closely monitored cargo packages. Don't just add a cargo package because you want your terminal output to be colourful. Supply chain attacks exist, and we dont want that.
- Comment your code.

*Actual docs to come soon, this is a description*
