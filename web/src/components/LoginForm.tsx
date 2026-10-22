import { useEffect, useRef, useState } from "react";
import type { CSSProperties, ReactNode } from "react";
import { Guard } from "@oracularhades/guard";
import CheckYourEmail from "@/components/CheckYourEmail";
import LabelledInput from "@/components/LabelledInput";
import LoadingSpinner from "@/components/LoadingSpinner";
import LoginWithButton from "@/components/LoginWithButton";
import OrBar from "@/components/OrBar";
import { startAuth, startDeviceAuth } from "@/lib/auth-flow";
import { errorMessage } from "@/lib/errors";
import { getAuthenticationMethods } from "@/lib/metadata";
import { getRoutingHost } from "@/lib/routing";
import type { AuthenticationMethod, DeviceContext, LoginMetadata, RequestData } from "@/types";

interface LoginFormProps {
  metadata?: LoginMetadata | null;
  header?: ReactNode;
  description?: ReactNode;
  logoUrl?: string | null;
  /**
   * When set (the page was opened by the Guard desktop app), this same form
   * drives device authentication: methods come from `[device_authentication]`
   * and each one hands a one-time setup token back to the desktop rather than
   * logging the browser in.
   */
  device_context?: DeviceContext | null;
  className?: string;
  style?: CSSProperties;
}

/**
 * The login form: an email field when an email method is configured, plus a
 * button per configured OAuth provider.
 */
export default function LoginForm({
  metadata,
  header,
  description,
  logoUrl,
  device_context,
  className,
  style,
}: LoginFormProps) {
  const shouldRun = useRef(true);
  const [methods, setMethods] = useState<AuthenticationMethod[]>([]);
  const [email, setEmail] = useState("");
  const [sentMagiclink, setSentMagiclink] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!shouldRun.current) {
      return;
    }
    shouldRun.current = false;

    // Device auth has no client-supplied host (methods come from
    // [device_authentication]); a normal login resolves the host from ?redirect=.
    const query = device_context ? { device_authentication: true as const } : { hostname: getRoutingHost().host };

    getAuthenticationMethods(query)
      .then(setMethods)
      .catch((cause: unknown) => setError(errorMessage(cause)));
  }, [device_context]);

  async function startEmailAuthentication(authenticationMethod: string) {
    setLoading(true);
    setError(null);

    try {
      // Both flows carry `state` so the magiclink completion can match this
      // attempt; device auth additionally stashes the deeplink state and
      // loopback callback so it can hand the setup token to the desktop app.
      const attempt = device_context
        ? startDeviceAuth(authenticationMethod, device_context)
        : startAuth(authenticationMethod);

      const requestData: RequestData = { email, state: attempt.state };

      const response = device_context
        ? await Guard().auth.device_request(authenticationMethod, requestData)
        : await Guard().auth.request(getRoutingHost().host, authenticationMethod, requestData);

      if (response.ok) {
        setSentMagiclink(true);
        return;
      }
    } catch (cause: unknown) {
      setError(errorMessage(cause));
    }

    setLoading(false);
  }

  if (sentMagiclink) {
    return <CheckYourEmail />;
  }

  // An email method gets the inline field; everything else gets a button.
  const emailMethod = methods.find((method) => method.method_type === "email" && method.id) ?? null;
  const providerMethods = methods.filter((method) => method !== emailMethod && method.id);

  const emailPlaceholder = metadata
    ? `${metadata.username_placeholder}@${metadata.domain_placeholder}`
    : undefined;

  return (
    <div className={`FormStyle_1 ${className ?? ""}`} style={style}>
      {(header || description || logoUrl) && (
        <div className="column row_gap_4">
          {logoUrl && <img className="FormStyle_1_logo" src={logoUrl} alt="" />}
          {header && <h1 className="FormStyle_1_header">{header}</h1>}
          {description && <p className="FormStyle_1_description">{description}</p>}
        </div>
      )}

      {!loading && (
        <div className="FormStyle_1_div">
          {error && <p className="FormStyle_1_div_error">Error: {error}</p>}

          {emailMethod?.id && (
            <div className="FormStyle_1_div_email">
              <LabelledInput
                header="Email"
                placeholder={emailPlaceholder}
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter") {
                    void startEmailAuthentication(emailMethod.id as string);
                  }
                }}
                autoCapitalize="off"
              />
              <button
                className="FormStyle_1_div_login_button"
                onClick={() => void startEmailAuthentication(emailMethod.id as string)}
              >
                Login
              </button>
            </div>
          )}

          {emailMethod && providerMethods.length > 0 && <OrBar />}

          {providerMethods.map((method) => (
            <LoginWithButton key={method.id} authentication_method={method} device_context={device_context} />
          ))}
        </div>
      )}

      {loading && <LoadingSpinner speed="600ms" size={15} style={{ alignSelf: "center" }} />}

      {metadata?.form?.bottom_text && (
        <p style={{ fontSize: metadata.form.bottom_text_fontsize ?? undefined }} className="you_agree_to">
          {metadata.form.bottom_text}
        </p>
      )}
    </div>
  );
}

