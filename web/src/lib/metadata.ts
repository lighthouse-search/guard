import { Guard } from "@oracularhades/guard";
import { getRoutingHost } from "@/lib/routing";
import type { AuthenticationMethod, LoginMetadata } from "@/types";

/**
 * Serve mock metadata instead of calling the API.
 *
 * Set NEXT_PUBLIC_DEV_MOCK=true (see .env.development) to develop the login
 * pages with `npm run dev` and no Guard server running. This lives here rather
 * than in the client library so the library stays pure transport with no
 * build-tool or environment coupling.
 */
const isDevMock = process.env.NEXT_PUBLIC_DEV_MOCK === "true";

function mockMetadata(): LoginMetadata {
  return {
    alias: process.env.NEXT_PUBLIC_DEV_ALIAS ?? null,
    public_description: process.env.NEXT_PUBLIC_DEV_PUBLIC_DESCRIPTION ?? null,
    logo: process.env.NEXT_PUBLIC_DEV_LOGO || null,
    image: process.env.NEXT_PUBLIC_DEV_IMAGE || null,
    motd_banner: process.env.NEXT_PUBLIC_DEV_MOTD_BANNER || null,
    domain_placeholder: process.env.NEXT_PUBLIC_DEV_DOMAIN_PLACEHOLDER ?? null,
    username_placeholder: process.env.NEXT_PUBLIC_DEV_USERNAME_PLACEHOLDER ?? null,
    background_colour: process.env.NEXT_PUBLIC_DEV_BACKGROUND_COLOUR || null,
    style: process.env.NEXT_PUBLIC_DEV_STYLE ?? "login_1",
  };
}

/**
 * Branding for the login page.
 *
 * Defaults to the host resolved from `?redirect=` — the host actually being
 * authenticated for. Device authentication passes the Guard instance's own host
 * instead, since it has no redirect target.
 */
export async function getMetadata(hostname?: string): Promise<LoginMetadata> {
  if (isDevMock) {
    return mockMetadata();
  }

  const response = await Guard().metadata.get(hostname ?? getRoutingHost().host);
  return response.data;
}

/** Which authentication methods to offer, for a host or for device auth. */
export type AuthenticationMethodsQuery = { device_authentication: true } | { hostname: string };

export async function getAuthenticationMethods(query: AuthenticationMethodsQuery): Promise<AuthenticationMethod[]> {
  if (isDevMock) {
    return [{ active: true, id: "email", alias: null, icon: null, method_type: "email", login_page: null }];
  }

  const response = "device_authentication" in query
    ? await Guard().metadata.get_authentication_methods(null, { device_authentication: true })
    : await Guard().metadata.get_authentication_methods(query.hostname);

  return response.data;
}
