# @oracularhades/guard

Client library for the [Guard](../..) authentication server. TypeScript, no
runtime dependencies — it only needs `fetch` and WebCrypto.

## Usage

```ts
import { Guard } from "@oracularhades/guard";

// Unauthenticated endpoints — the whole pre-login flow.
const { data } = await Guard().metadata.get("example.com");

// With credentials, every request is signed (RFC 9421 HTTP Message Signatures).
const guard = Guard({ deviceid, privatekey });
const { device_id } = await guard.auth.authenticate(host, "email", { code, public_key });
```

`Guard(credentials)` enrols the credentials for this and all later calls;
`Guard()` reuses whatever was enrolled before, so it is safe to call anywhere.

### API

| Group      | Method                                                       |
| ---------- | ------------------------------------------------------------ |
| `metadata` | `get(hostname)`, `get_authentication_methods(hostname, opts)` |
| `auth`     | `request`, `authenticate`, `device_request`, `device_authenticate` |
| `oauth`    | `exchange_code`, `device_exchange_code`                      |

Device-authentication methods (`device_*`) take no hostname: the server resolves
the context from `[device_authentication]` and returns a one-time `setup_token`
for the desktop app, so the browser never handles a device key.

Signing primitives are also exported directly: `signRequestHeaders`,
`signStaticCredential` (the `guard_static_auth` cookie) and `signDataToken` (the
OAuth `code`).

Endpoints return the server's JSON. An error response (`{ error: true, ... }`)
is thrown rather than returned.

## Layout

```
src/
  index.ts           public surface — Guard(), signing, types
  types.ts           response shapes, mirroring server/src/structs.rs
  credentials.ts     the enrolled credentials
  request.ts         fetch + signing + error handling
  http-signature.ts  RFC 9421 signatures, RFC 9530 Content-Digest
  api-url.ts         where the Guard API lives
  params.ts          query-string encoding
  api/               one module per endpoint group
```

## Developing

```sh
npm install
npm run build      # emits dist/ with .d.ts
npm run typecheck
```

`web` consumes this package through `file:guard-npm` and builds it as
part of its own build, so there is nothing to do when working on the frontend.
