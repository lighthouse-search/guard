import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { signDataToken } from "@oracularhades/guard";
import Base from "@/components/Base";
import Form from "@/components/Form";
import MetadataPanelFrame from "@/components/MetadataPanelFrame";
import { getAuthenticationMetadata } from "@/lib/cookies";
import { readCredentials } from "@/lib/session";

/**
 * Consent screen for Guard acting as an OAuth provider: a third-party app sends
 * the user here, and on approval we mint a signed `code` for it.
 *
 * PROTOTYPE: the client's registration below is hardcoded. It needs to come
 * from the server (by `client_id`) before this can be used for real — right now
 * the displayed app and the allow-lists validated against are fixed.
 */
interface OauthClient {
  client_id: string;
  branding: { client_name: string; icon_uri: string };
  grant_types: string[];
  redirect_uris: string[];
  response_types: string[];
  scope: string[];
}

const PROTOTYPE_CLIENT: OauthClient = {
  client_id: "https://bsky.social/oauth/client-metadata.json",
  branding: {
    client_name: "Bluesky Social",
    icon_uri: "https://cdn.bsky.app/img/avatar/plain/did:plc:z72i7hdynmk6r22z27h6tvur/bafkreihagr2cmvl2jt4mgx3sppwe2it3fwolkrbtjrhcnwjk4jdijhsoze@jpeg",
  },
  grant_types: ["authorization_code", "refresh_token"],
  redirect_uris: ["https://app.example.com/oauth/callback"],
  response_types: ["code"],
  scope: ["email_read", "authentication_method"],
};

/** Human-readable descriptions of the scopes a client can ask for. */
function permissionCopy(exampleAuthMethod: string) {
  return {
    user_information: {
      alias: "User information",
      description: "Know user information, like your first name, last name and profile picture.",
    },
    email: {
      alias: "Email address",
      description: "Know your email address",
    },
    authentication_method: {
      alias: "Authentication methods",
      description: `Know what authentication methods you've used (e.g. ${exampleAuthMethod})`,
    },
  };
}

export default function OauthAuthorise() {
  const shouldRun = useRef(true);
  const [exampleAuthMethod, setExampleAuthMethod] = useState("microsoft");
  const [error, setError] = useState<string | null>(null);

  const client = PROTOTYPE_CLIENT;

  useEffect(() => {
    if (!shouldRun.current) {
      return;
    }
    shouldRun.current = false;

    // Name a method the user has actually used, so the scope description is
    // concrete rather than a generic example.
    const authenticationMetadata = getAuthenticationMetadata();
    if (authenticationMetadata?.authentication_method) {
      setExampleAuthMethod(authenticationMetadata.authentication_method);
    }

    // Validate the request up front: nothing should render an "Authorise"
    // button for a request we would refuse. (This check existed but was never
    // called, so every request reached the button.)
    setError(validateRequest(client));
  }, [client]);

  async function authoriseRedirect() {
    const params = new URL(window.location.href).searchParams;

    const refusal = validateRequest(client);
    if (refusal) {
      setError(refusal);
      return;
    }

    const credentials = readCredentials();
    if (!credentials) {
      setError("You need to be logged in to authorise an application.");
      return;
    }

    const redirectUri = params.get("redirect_uri");
    if (!redirectUri) {
      setError("Invalid params.redirect_uri");
      return;
    }

    const code = await signDataToken(
      {
        device_id: credentials.deviceid,
        client_id: client.client_id,
        scope: params.get("scope"),
        redirect_uri: redirectUri,
        grant_type: params.get("grant_type"),
        // Must be unpredictable and unique per request: this is what stops a
        // code being replayed. (It used to be a timestamp plus
        // Math.floor(Math.random()), which is always exactly zero.)
        nonce: crypto.randomUUID(),
        created: Math.floor(Date.now() / 1000),
      },
      credentials.privatekey,
    );

    const target = new URL(redirectUri);
    target.searchParams.set("code", code);
    window.location.href = target.href;
  }

  const permissions = permissionCopy(exampleAuthMethod);
  const requestedPermissions = (["email", "authentication_method"] as const).map((scope) => {
    const permission = permissions[scope];
    return (
      <div key={scope}>
        <p className="font_size_16 bold">{permission.alias}</p>
        <p className="font_size_14">{permission.description}</p>
      </div>
    );
  });

  const clientUrl = new URL(client.client_id);

  return (
    <Base>
      <MetadataPanelFrame>
        <Form className="authorise">
          <div className="column row_gap_6">
            <div className="row column_gap_6">
              <img style={{ width: 40, height: 40 }} src={client.branding.icon_uri} alt="" />
              <div className="column">
                <Link href={`https://${clientUrl.hostname}`} className="client_link font_size_16 bold hover_underline">
                  <span className="greyText">{clientUrl.protocol}//</span>
                  {clientUrl.hostname}
                </Link>
                <p className="greyText font_size_14">
                  &quot;{client.branding.client_name}&quot; wants to access:
                </p>
              </div>
            </div>

            {error && <p className="FormStyle_1_div_error">{error}</p>}

            {!error && (
              <div className="column row_gap_6 scrollY">
                {requestedPermissions}
                <button className="font_size_14" onClick={() => void authoriseRedirect()}>Authorise</button>
              </div>
            )}
          </div>
        </Form>
      </MetadataPanelFrame>
    </Base>
  );
}

/**
 * Check the incoming request against what the client is registered for.
 * Returns a message to show the user, or null when the request is acceptable.
 */
function validateRequest(client: OauthClient): string | null {
  const params = new URL(window.location.href).searchParams;

  const scope = params.get("scope");
  if (!scope) {
    return "Invalid params.scope";
  }

  // `for...in` over an array yields indices, not values, so this used to compare
  // "0", "1", ... against the allowed scopes and therefore accepted anything.
  for (const requested of scope.split(" ")) {
    if (!client.scope.includes(requested)) {
      return "Invalid params.scope";
    }
  }

  if (!client.redirect_uris.includes(params.get("redirect_uri") ?? "")) {
    return "Invalid params.redirect_uri";
  }
  if (!client.grant_types.includes(params.get("grant_type") ?? "")) {
    return "Invalid params.grant_type";
  }
  if (!client.response_types.includes(params.get("response_type") ?? "")) {
    return "Invalid params.response_type";
  }

  return null;
}
