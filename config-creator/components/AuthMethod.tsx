"use client";

import { useState } from "react";
import TagInput from "./TagInput";

export function generateClientSecretEnvVar(id: string): string {
  return id.toUpperCase().replace(/[^A-Z0-9]/g, "_") + "_CLIENT_SECRET";
}

export interface AuthMethodData {
  active?: boolean;
  method_type?: "email" | "oauth";
  // applied_policies is NOT a Guard AuthMethod field (commented out in
  // server/src/structs.rs). Guard ignores unknown config keys, so emitting it here
  // produced a line that silently enforced nothing. Policies apply per hostname.
  // applied_policies?: string[];
  should_create_new_users?: boolean;
  alias?: string;
  icon?: string;
  oauth_client_id?: string;
  oauth_client_secret_env?: string;
  oauth_client_token_endpoint?: string;
  oauth_client_user_info?: string;
  oauth_client_user_info_id?: string;
  oauth_client_api?: string;
}

const LABEL = "text-xs font-semibold text-zinc-500 dark:text-zinc-400 uppercase tracking-wide";
const INPUT = "rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-900 px-3 py-1.5 text-sm text-zinc-900 dark:text-zinc-100 placeholder:text-zinc-400 outline-none focus:ring-2 focus:ring-zinc-400";

export function AuthMethodFields({
  data,
  onChange,
  availablePolicies = [],
}: {
  data: AuthMethodData;
  onChange: (d: AuthMethodData) => void;
  availablePolicies?: string[];
}) {
  const isOAuth = data.method_type === "oauth";

  function update(partial: Partial<AuthMethodData>) {
    onChange({ ...data, ...partial });
  }

  return (
    <>
      <div className="flex flex-col gap-1.5">
        <label className={LABEL}>
          Type
        </label>
        <select
          value={data.method_type ?? "email"}
          onChange={(e) => update({ method_type: e.target.value as "email" | "oauth" })}
          className={INPUT}
        >
          <option value="email">Email (MagicLink)</option>
          <option value="oauth">OAuth</option>
        </select>
      </div>

      <div className="flex flex-col gap-1.5">
        <label className={LABEL}>
          Alias{" "}
          <span className="normal-case font-normal text-zinc-400 tracking-normal">(optional)</span>
        </label>
        <input
          value={data.alias ?? ""}
          onChange={(e) => update({ alias: e.target.value })}
          placeholder="Sign in with Google"
          className={INPUT}
        />
      </div>

      {isOAuth && (
        <div className="flex flex-col gap-3 p-3 rounded-lg bg-zinc-50 dark:bg-zinc-950 border border-zinc-100 dark:border-zinc-800">
          <p className="text-xs font-semibold text-zinc-500 uppercase tracking-wide">OAuth settings</p>

          <div className="flex flex-col gap-1.5">
            <label className={LABEL}>Client ID</label>
            <input
              value={data.oauth_client_id ?? ""}
              onChange={(e) => update({ oauth_client_id: e.target.value })}
              placeholder="your-client-id"
              className={`${INPUT}`}
            />
          </div>

          <div className="flex flex-col gap-1.5">
            <label className={LABEL}>Token endpoint</label>
            <input
              value={data.oauth_client_token_endpoint ?? ""}
              onChange={(e) => update({ oauth_client_token_endpoint: e.target.value })}
              placeholder="https://accounts.google.com/o/oauth2/token"
              className={`${INPUT}`}
            />
          </div>

          <div className="flex flex-col gap-1.5">
            <label className={LABEL}>User info endpoint</label>
            <input
              value={data.oauth_client_user_info ?? ""}
              onChange={(e) => update({ oauth_client_user_info: e.target.value })}
              placeholder="https://www.googleapis.com/oauth2/v1/userinfo"
              className={`${INPUT}`}
            />
          </div>

          <div className="flex flex-col gap-1.5">
            <div className="flex flex-col gap-0.5">
              <label className={LABEL}>
                User id claim{" "}
                <span className="normal-case font-normal text-zinc-400 tracking-normal">(optional)</span>
              </label>
              <p className="text-[11px] text-zinc-500 dark:text-zinc-400 leading-relaxed">Which field in the user info response holds the provider&apos;s stable user id. OpenID Connect endpoints (Microsoft&apos;s /oidc/userinfo, Google&apos;s v3 userinfo) return &quot;sub&quot;; provider-specific ones (GitHub /user, Microsoft Graph /v1.0/me) return &quot;id&quot;. Leave blank to try &quot;id&quot; then &quot;sub&quot;.</p>
            </div>
            <input
              value={data.oauth_client_user_info_id ?? ""}
              onChange={(e) => update({ oauth_client_user_info_id: e.target.value })}
              placeholder="sub"
              className={`${INPUT}`}
            />
          </div>
        </div>
      )}

      {/* <div className="flex flex-col gap-1.5">
        <div className="flex flex-col gap-0.5">
          <label className={LABEL}>Applied policies</label>
          <p className="text-[11px] text-zinc-500 dark:text-zinc-400 leading-relaxed">Only users who match these policies may authenticate with this method. E.g. when authenticating Google, ensure organisation is a company account. Applied policies serves as blanket authentication for a whole authentication method.</p>
        </div>
        <TagInput
          tags={data.applied_policies ?? []}
          onChange={(v) => update({ applied_policies: v })}
          placeholder="Select or type a policy…"
          suggestions={availablePolicies}
        />
      </div> */}

      <label className="flex items-center gap-3 cursor-pointer">
        <input
          type="checkbox"
          checked={data.should_create_new_users ?? false}
          onChange={(e) => update({ should_create_new_users: e.target.checked })}
          className="w-4 h-4 accent-zinc-700 dark:accent-zinc-400"
        />
        <div>
          <p className="text-sm font-medium text-zinc-700 dark:text-zinc-300">Create new users</p>
          <p className="text-xs text-zinc-400">Automatically register first-time users</p>
        </div>
      </label>
    </>
  );
}

interface Props {
  id: string;
  data: AuthMethodData;
  onChange: (id: string, data: AuthMethodData) => void;
  onRemove: (id: string) => void;
  availablePolicies?: string[];
}

export default function AuthMethodComponent({ id, data, onChange, onRemove, availablePolicies = [] }: Props) {
  const [expanded, setExpanded] = useState(true);

  return (
    <div className="rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 overflow-hidden">
      <div className="flex items-center gap-3 px-4 py-3">
        <button
          type="button"
          onClick={() => setExpanded(!expanded)}
          className="text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-200 text-[9px] transition-transform duration-150 shrink-0"
          style={{ transform: expanded ? "rotate(90deg)" : "rotate(0deg)" }}
          aria-label={expanded ? "Collapse" : "Expand"}
        >
          ▶
        </button>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-zinc-800 dark:text-zinc-200">{id}</span>
            <span className="text-xs bg-zinc-100 dark:bg-zinc-800 text-zinc-500 dark:text-zinc-400 px-1.5 py-0.5 rounded font-sans">
              {data.method_type ?? "email"}
            </span>
          </div>
          {data.alias && <span className="text-xs text-zinc-400">{data.alias}</span>}
        </div>

        <button
          type="button"
          onClick={() => onRemove(id)}
          className="text-zinc-300 hover:text-red-400 dark:text-zinc-600 dark:hover:text-red-500 transition-colors text-xl leading-none shrink-0"
          title="Remove method"
        >
          ×
        </button>
      </div>

      {expanded && (
        <div className="px-4 pb-4 flex flex-col gap-4 border-t border-zinc-100 dark:border-zinc-800 pt-4">
          <AuthMethodFields

            data={data}
            onChange={(d) => onChange(id, d)}
            availablePolicies={availablePolicies}
          />
        </div>
      )}
    </div>
  );
}
