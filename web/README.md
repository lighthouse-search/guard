# Guard frontend

The login UI Guard serves: the login page, the magiclink/OAuth landing page, and
the desktop app's device-authorisation page. Next.js (Pages Router) in
TypeScript, exported as static files — Guard's Rust server serves them straight
from disk, so there is no Node runtime in the container.

## Layout

```
src/
  pages/        one file per route; the filename IS the URL
  screens/      whole-page compositions, one per route that needs logic
  components/   reusable pieces, each with its stylesheet beside it
  lib/          non-UI logic — crypto, cookies, storage, routing, API calls
  types.ts      shapes shared across the app
  styles/       global.css (Tailwind + the shared utility classes)
guard-npm/      the @oracularhades/guard client library (its own package)
```

Route names are load-bearing: the Rust server links to `/guard/frontend/login`
and `/guard/frontend/magiclink` directly (`authentication_misc.rs`,
`auth_method_request.rs`), and `basePath` in `next.config.ts` has to match where
the server mounts the export. Renaming a file in `src/pages/` changes a URL the
server already hardcodes.

Three names refer to this one thing, and only the first is a directory you can
rename freely:

| `web/`             | where the source lives                                   |
| `/guard/frontend/` | the URL it is served under — `basePath`, and in the Rust server and the README's nginx configs |
| `frontend/_static` | its position inside `guard.zip` and the container image, assembled by the makefile and CI |

Every stylesheet here is global CSS rather than CSS Modules, and the Pages
Router only allows global CSS to be imported from `_app.tsx` — so that is where
all of them are imported, in one list. A stylesheet sitting next to its
component only shows what it styles; it is not scoped to it.

## Developing

```sh
npm install
npm run dev        # https://localhost:8484/guard/frontend/login
npm run build      # static export into _static/
npm run typecheck
```

`npm run dev` and `npm run build` build `guard-npm` first — it ships TypeScript
and is consumed through `file:guard-npm`, so its `dist/` has to exist before
Next resolves it.

To work on the login pages without a Guard server running, uncomment
`NEXT_PUBLIC_DEV_MOCK=true` in `.env.development` (and the branding values
below it). That serves mock metadata and a single email authentication method;
see `src/lib/metadata.ts`.
