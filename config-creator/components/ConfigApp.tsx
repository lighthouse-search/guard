"use client";

import { useState, useEffect } from "react";
import dynamic from "next/dynamic";
import TOML from "@iarna/toml";

// Disable SSR for the editor: react-simple-code-editor sets autoCapitalize="none"
// but browsers normalise it to "off", causing a React hydration mismatch.
const ConfigEditor = dynamic(() => import("./ConfigEditor"), { ssr: false });
import HostnameComponent, { HostnameData, HostnameFields } from "./Hostname";
import AuthMethodComponent, { AuthMethodData, AuthMethodFields, generateClientSecretEnvVar } from "./AuthMethod";
import PolicyComponent, { PolicyData, PolicyFields } from "./Policy";
import Input from "./Input";
import Dialog from "./Dialog";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faWindows, faGoogle, faGithub } from "@fortawesome/free-brands-svg-icons";
import { faKey, faEnvelope } from "@fortawesome/free-solid-svg-icons";

const DEFAULT_TOML = ``;

interface GuardConfig {
  features?: {
    request_proxy?: boolean;
    reverse_proxy_authentication?: boolean;
    oauth_server?: boolean;
    tls?: boolean;
  };
  reverse_proxy_authentication?: {
    config?: { header?: string };
  };
  frontend?: {
    metadata?: {
      instance_hostname?: string;
      alias?: string;
      public_description?: string;
      image?: string;
      domain_placeholder?: string;
      username_placeholder?: string;
    };
  };
  database?: {
    mysql?: {
      username?: string;
      password_env?: string;
      hostname?: string;
      port?: number;
      database?: string;
    };
  };
  smtp?: {
    host?: string;
    port?: number;
    username?: string;
    password_env?: string;
    from_alias?: string;
    from_header?: string;
    reply_to_address?: string;
  };
  sql?: {
    users_table?: string;
    devices_table?: string;
    magiclink_table?: string;
  };
  authentication_methods?: Record<string, AuthMethodData>;
  policies?: Record<string, PolicyData>;
  hostname?: Record<string, HostnameData>;
}

function parseToml(raw: string): GuardConfig | null {
  try {
    return TOML.parse(raw) as GuardConfig;
  } catch {
    return null;
  }
}

function Section({
  title,
  description,
  children,
}: {
  title: string;
  description?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-col gap-0.5">
        <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">{title}</h2>
        {description && (
          <p className="text-xs text-zinc-500 dark:text-zinc-400">{description}</p>
        )}
      </div>
      <div className="flex flex-col gap-3">{children}</div>
    </div>
  );
}

function CollapsibleSection({
  title,
  description,
  children,
  open,
  onOpenChange,
  required,
}: {
  title: string;
  description?: string;
  children: React.ReactNode;
  open: boolean;
  onOpenChange: (v: boolean) => void;
  required?: boolean;
}) {
  return (
    <div className="flex flex-col gap-0">
      <button
        type="button"
        onClick={() => onOpenChange(!open)}
        className={`flex items-center justify-between gap-3 text-left w-full px-4 py-3 border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 hover:bg-zinc-50 dark:hover:bg-zinc-800 transition-colors ${
          open ? "rounded-t-lg" : "rounded-lg"
        }`}
      >
        <div className="flex flex-col gap-0.5 flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">{title}</h2>
            {required === true && (
              <span className="text-[10px] px-1.5 py-0.5 rounded font-medium leading-none bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-400">
                Required for Email MagicLink
              </span>
            )}
            {required === false && (
              <span className="text-[10px] px-1.5 py-0.5 rounded font-medium leading-none bg-zinc-100 dark:bg-zinc-800 text-zinc-400 dark:text-zinc-500">
                Optional
              </span>
            )}
          </div>
          {description && (
            <p className="text-xs text-zinc-500 dark:text-zinc-400">{description}</p>
          )}
        </div>
        <span
          className="text-[9px] text-zinc-400 dark:text-zinc-500 shrink-0 transition-transform duration-150"
          style={{ transform: open ? "rotate(90deg)" : "rotate(0deg)" }}
        >
          ▶
        </span>
      </button>
      {open && (
        <div className="flex flex-col gap-3 px-4 py-4 border border-t-0 border-zinc-200 dark:border-zinc-800 rounded-b-lg bg-zinc-50 dark:bg-zinc-950">
          {children}
        </div>
      )}
    </div>
  );
}

function FeatureToggle({
  label,
  description,
  checked,
  onChange,
}: {
  label: string;
  description?: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    // Use div+onClick instead of label+button — label activates its child button
    // on click, causing a double-fire that makes the toggle revert immediately.
    <div
      role="switch"
      aria-checked={checked}
      onClick={() => onChange(!checked)}
      className="flex items-center justify-between gap-4 px-4 py-3 rounded-lg border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 cursor-pointer hover:border-zinc-300 dark:hover:border-zinc-700 transition-colors select-none"
    >
      <div>
        <p className="text-sm font-medium text-zinc-700 dark:text-zinc-300">{label}</p>
        {description && (
          <p className="text-xs text-zinc-400 mt-0.5">{description}</p>
        )}
      </div>
      <div
        className={`relative w-10 h-5 rounded-full transition-colors duration-200 shrink-0 ${
          checked ? "bg-zinc-600 dark:bg-zinc-400" : "bg-zinc-200 dark:bg-zinc-700"
        }`}
      >
        <span
          className={`absolute top-0.5 w-4 h-4 bg-white rounded-full shadow transition-transform duration-200 ${
            checked ? "translate-x-5" : "translate-x-0.5"
          }`}
        />
      </div>
    </div>
  );
}

interface QuickstartPreset {
  id: string;
  label: string;
  description: string;
  icon: React.ReactNode;
  authMethodId: string;
  authMethod: AuthMethodData;
}

const QUICKSTART_PRESETS: QuickstartPreset[] = [
  {
    id: "microsoft_entra",
    label: "Microsoft Entra",
    description: "Azure AD / Entra ID OAuth 2.0",
    icon: <FontAwesomeIcon icon={faWindows} className="w-5 h-5 text-[#0078D4]" />,
    authMethodId: "microsoft_entra",
    authMethod: {
      active: true,
      method_type: "oauth",
      alias: "Sign in with Microsoft",
      should_create_new_users: false,
      applied_policies: [],
      oauth_client_token_endpoint: "https://login.microsoftonline.com/{tenant-id}/oauth2/v2.0/token",
      oauth_client_user_info: "https://graph.microsoft.com/v1.0/me",
    },
  },
  {
    id: "google",
    label: "Google",
    description: "Google OAuth 2.0",
    icon: <FontAwesomeIcon icon={faGoogle} className="w-5 h-5 text-[#4285F4]" />,
    authMethodId: "google",
    authMethod: {
      active: true,
      method_type: "oauth",
      alias: "Sign in with Google",
      should_create_new_users: false,
      applied_policies: [],
      oauth_client_token_endpoint: "https://oauth2.googleapis.com/token",
      oauth_client_user_info: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
  },
  {
    id: "github",
    label: "GitHub",
    description: "GitHub OAuth Apps",
    icon: <FontAwesomeIcon icon={faGithub} className="w-5 h-5" />,
    authMethodId: "github",
    authMethod: {
      active: true,
      method_type: "oauth",
      alias: "Sign in with GitHub",
      should_create_new_users: false,
      applied_policies: [],
      oauth_client_token_endpoint: "https://github.com/login/oauth/access_token",
      oauth_client_user_info: "https://api.github.com/user",
    },
  },
  {
    id: "generic_oauth",
    label: "Generic OAuth",
    description: "Any OAuth 2.0 provider",
    icon: <FontAwesomeIcon icon={faKey} className="w-5 h-5" />,
    authMethodId: "oauth",
    authMethod: {
      active: true,
      method_type: "oauth",
      alias: "Sign in",
      should_create_new_users: false,
      applied_policies: [],
      oauth_client_token_endpoint: "",
      oauth_client_user_info: "",
    },
  },
  {
    id: "email",
    label: "Email MagicLink",
    description: "Passwordless one-time link",
    icon: <FontAwesomeIcon icon={faEnvelope} className="w-5 h-5" />,
    authMethodId: "email",
    authMethod: {
      active: true,
      method_type: "email",
      should_create_new_users: false,
      applied_policies: [],
    },
  },
];

// --- Script generation helpers ---

const GITHUB_REPO = "lighthouse-search/guard";

function collectEnvVars(cfg: GuardConfig): Array<{ varName: string; description: string }> {
  const vars: Array<{ varName: string; description: string }> = [];
  if (cfg.database?.mysql?.password_env) {
    vars.push({ varName: cfg.database.mysql.password_env, description: "MySQL password" });
  }
  if (cfg.smtp?.password_env) {
    vars.push({ varName: cfg.smtp.password_env, description: "SMTP password" });
  }
  for (const [id, method] of Object.entries(cfg.authentication_methods ?? {})) {
    if (method.method_type === "oauth") {
      vars.push({
        varName: method.oauth_client_secret_env || generateClientSecretEnvVar(id),
        description: `OAuth client secret for ${id}`,
      });
    }
  }
  return vars;
}

function generateBashScript(toml: string, envVars: Array<{ varName: string; description: string }>): string {
  const lines = ["#!/bin/bash", ""];
  if (envVars.length) {
    lines.push("# Set your environment variables");
    for (const { varName } of envVars) {
      lines.push(`export ${varName}="%YOUR ${varName} VALUE%"`);
    }
    lines.push("");
  }
  lines.push("# Guard configuration");
  lines.push("export guard_config=$(cat <<'GUARD_CONFIG_EOF'");
  lines.push(toml);
  lines.push("GUARD_CONFIG_EOF");
  lines.push(")");
  lines.push("");
  lines.push("# Detect OS and architecture, then download and run Guard");
  lines.push('OS=$(uname -s | tr \'[:upper:]\' \'[:lower:]\')');
  lines.push('ARCH=$(uname -m)');
  lines.push('case "$ARCH" in');
  lines.push('  x86_64) ARCH="amd64" ;;');
  lines.push('  aarch64|arm64) ARCH="arm64" ;;');
  lines.push('  *) echo "Unsupported architecture: $ARCH" && exit 1 ;;');
  lines.push("esac");
  lines.push('case "$OS" in');
  lines.push('  linux) OS_NAME="linux" ;;');
  lines.push('  darwin) OS_NAME="darwin" ;;');
  lines.push('  *) echo "Unsupported OS: $OS" && exit 1 ;;');
  lines.push("esac");
  lines.push(`curl -fsSL "https://github.com/${GITHUB_REPO}/releases/latest/download/guard-\${OS_NAME}-\${ARCH}" -o guard-server`);
  lines.push("chmod +x guard-server");
  lines.push("./guard-server");
  return lines.join("\n");
}

function generatePowerShellScript(toml: string, envVars: Array<{ varName: string; description: string }>): string {
  const lines: string[] = [];
  if (envVars.length) {
    lines.push("# Set your environment variables");
    for (const { varName } of envVars) {
      lines.push(`$env:${varName} = "%YOUR ${varName} VALUE%"`);
    }
    lines.push("");
  }
  lines.push("# Guard configuration");
  lines.push("$env:guard_config = @'");
  lines.push(toml);
  lines.push("'@");
  lines.push("");
  lines.push("# Download and run Guard");
  lines.push(`$url = "https://github.com/${GITHUB_REPO}/releases/latest/download/guard-windows-amd64.exe"`);
  lines.push('Invoke-WebRequest -Uri $url -OutFile "guard-server.exe"');
  lines.push(".\\guard-server.exe");
  return lines.join("\n");
}

// --- Main component ---

export default function ConfigApp() {
  const [tomlValue, setTomlValue] = useState(DEFAULT_TOML);
  const [config, setConfig] = useState<GuardConfig>(
    parseToml(DEFAULT_TOML) ?? {}
  );
  const [copied, setCopied] = useState(false);

  // Quickstart form state
  const [selectedPreset, setSelectedPreset] = useState<QuickstartPreset | null>(null);
  const [qsMethodId, setQsMethodId] = useState("");
  const [qsClientId, setQsClientId] = useState("");
  const [qsTokenEndpoint, setQsTokenEndpoint] = useState("");
  const [qsUserInfo, setQsUserInfo] = useState("");

  // Install script state
  const [scriptTab, setScriptTab] = useState<"bash" | "windows">("bash");
  const [scriptCopied, setScriptCopied] = useState(false);
  const [scriptDialogOpen, setScriptDialogOpen] = useState(false);

  // Collapsible section state
  const emailActive = Object.values(config.authentication_methods ?? {}).some(
    (m) => m.method_type === "email"
  );
  const [featuresOpen, setFeaturesOpen] = useState(true);
  const [stylingOpen, setStylingOpen] = useState(true);
  const [mysqlOpen, setMysqlOpen] = useState(emailActive);
  const [sqlTablesOpen, setSqlTablesOpen] = useState(emailActive);
  const [smtpOpen, setSmtpOpen] = useState(emailActive);
  const [policiesOpen, setPoliciesOpen] = useState(true);
  const [hostnamesOpen, setHostnamesOpen] = useState(true);
  const [authMethodsOpen, setAuthMethodsOpen] = useState(true);

  // Create-dialog state
  const BLANK_POLICY: PolicyData = { active: true, action: "allow", property: "email" };
  const BLANK_HOSTNAME: HostnameData = { active: true, hostname: "", authentication_methods: [], applied_policies: [], multistep_authentication_methods: false };
  const BLANK_METHOD: AuthMethodData = { active: true, method_type: "email", applied_policies: [], should_create_new_users: false };

  const [policyDialog, setPolicyDialog] = useState<{ open: boolean; id: string; data: PolicyData }>({ open: false, id: "", data: BLANK_POLICY });
  const [hostnameDialog, setHostnameDialog] = useState<{ open: boolean; id: string; data: HostnameData }>({ open: false, id: "", data: BLANK_HOSTNAME });
  const [methodDialog, setMethodDialog] = useState<{ open: boolean; id: string; data: AuthMethodData }>({ open: false, id: "", data: BLANK_METHOD });

  function commitPolicy() {
    const id = policyDialog.id.trim();
    if (!id) return;
    updateConfig({ ...config, policies: { ...config.policies, [id]: policyDialog.data } });
    setPolicyDialog({ open: false, id: "", data: BLANK_POLICY });
  }

  function commitHostname() {
    const id = hostnameDialog.id.trim();
    if (!id) return;
    updateConfig({ ...config, hostname: { ...config.hostname, [id]: hostnameDialog.data } });
    setHostnameDialog({ open: false, id: "", data: BLANK_HOSTNAME });
  }

  function commitMethod() {
    const id = methodDialog.id.trim();
    if (!id) return;
    const isOAuth = methodDialog.data.method_type === "oauth";
    updateConfig({
      ...config,
      authentication_methods: {
        ...config.authentication_methods,
        [id]: {
          ...methodDialog.data,
          ...(isOAuth && { oauth_client_secret_env: generateClientSecretEnvVar(id) }),
        },
      },
    });
    setMethodDialog({ open: false, id: "", data: BLANK_METHOD });
  }

  useEffect(() => {
    if (emailActive) {
      setMysqlOpen(true);
      setSqlTablesOpen(true);
      setSmtpOpen(true);
    }
  }, [emailActive]);

  function handleChange(value: string) {
    setTomlValue(value);
    const parsed = parseToml(value);
    if (parsed) setConfig(parsed);
  }

  function updateConfig(next: GuardConfig) {
    setConfig(next);
    // JSON round-trip strips the internal type metadata that @iarna/toml attaches
    // to parsed values — without this, stringify produces malformed section headers.
    const plain = JSON.parse(JSON.stringify(next));
    setTomlValue(TOML.stringify(plain));
  }

  function copyToml() {
    navigator.clipboard.writeText(tomlValue).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  // Hostname handlers
  function updateHostname(id: string, data: HostnameData) {
    updateConfig({ ...config, hostname: { ...config.hostname, [id]: data } });
  }
  function removeHostname(id: string) {
    const { [id]: _removed, ...rest } = config.hostname ?? {};
    updateConfig({ ...config, hostname: rest });
  }
  // Auth method handlers
  function updateAuthMethod(id: string, data: AuthMethodData) {
    updateConfig({
      ...config,
      authentication_methods: { ...config.authentication_methods, [id]: data },
    });
  }
  function removeAuthMethod(id: string) {
    const { [id]: _removed, ...rest } = config.authentication_methods ?? {};
    updateConfig({ ...config, authentication_methods: rest });
  }
  // Policy handlers
  function updatePolicy(id: string, data: PolicyData) {
    updateConfig({
      ...config,
      policies: { ...config.policies, [id]: data },
    });
  }
  function removePolicy(id: string) {
    const { [id]: _removed, ...rest } = config.policies ?? {};
    updateConfig({ ...config, policies: rest });
  }
  function openQuickstart(preset: QuickstartPreset) {
    if (selectedPreset?.id === preset.id) {
      setSelectedPreset(null);
      return;
    }
    setSelectedPreset(preset);
    setQsMethodId(preset.authMethodId);
    setQsClientId("");
    setQsTokenEndpoint(preset.authMethod.oauth_client_token_endpoint ?? "");
    setQsUserInfo(preset.authMethod.oauth_client_user_info ?? "");
  }

  function commitQuickstart() {
    if (!selectedPreset) return;
    const existingMethods = config.authentication_methods ?? {};
    let key = qsMethodId.trim() || selectedPreset.authMethodId;
    const base = key;
    let suffix = 2;
    while (existingMethods[key]) key = `${base}_${suffix++}`;
    const isOAuth = selectedPreset.authMethod.method_type === "oauth";
    updateConfig({
      ...config,
      authentication_methods: {
        ...existingMethods,
        [key]: {
          ...selectedPreset.authMethod,
          ...(isOAuth && {
            oauth_client_id: qsClientId || undefined,
            oauth_client_secret_env: generateClientSecretEnvVar(key),
            oauth_client_token_endpoint: qsTokenEndpoint || selectedPreset.authMethod.oauth_client_token_endpoint,
            oauth_client_user_info: qsUserInfo || selectedPreset.authMethod.oauth_client_user_info,
          }),
        },
      },
    });
    setSelectedPreset(null);
  }

  function copyScript() {
    const envVars = collectEnvVars(config);
    const text = scriptTab === "bash"
      ? generateBashScript(tomlValue, envVars)
      : generatePowerShellScript(tomlValue, envVars);
    navigator.clipboard.writeText(text).then(() => {
      setScriptCopied(true);
      setTimeout(() => setScriptCopied(false), 2000);
    });
  }

  const rpaEnabled = config.features?.reverse_proxy_authentication ?? false;

  return (
    <div className="flex bg-zinc-50 dark:bg-zinc-950 h-screen overflow-hidden font-sans">
      {/* Form panel */}
      <div className="flex flex-col w-full max-w-2xl border-r border-zinc-200 dark:border-zinc-800 shrink-0">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 shrink-0">
          <div>
            <h1 className="text-[18px] font-semibold text-zinc-900 dark:text-zinc-100">
              Guard config creator
            </h1>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={copyToml}
              className="px-3 py-1.5 rounded-md border border-zinc-200 dark:border-zinc-700 bg-white dark:bg-zinc-900 text-xs font-medium text-zinc-600 dark:text-zinc-300 hover:border-zinc-300 dark:hover:border-zinc-600 transition-colors"
            >
              {copied ? "Copied!" : "Copy TOML"}
            </button>
            <button
              type="button"
              onClick={() => setScriptDialogOpen(true)}
              className="px-3 py-1.5 rounded-md bg-zinc-800 dark:bg-zinc-200 text-xs font-medium text-white dark:text-zinc-900 hover:bg-zinc-700 dark:hover:bg-zinc-300 transition-colors"
            >
              Setup script
            </button>
          </div>
        </div>

        {/* Scrollable sections */}
        <div className="flex flex-col gap-8 p-6 overflow-y-auto">
          {/* Quickstart */}
          <Section
            title="Quickstart"
            description="Add a pre-configured authentication method to get started quickly"
          >
            <div className="grid grid-cols-2 gap-2">
              {QUICKSTART_PRESETS.map((preset) => {
                const active = selectedPreset?.id === preset.id;
                return (
                  <button
                    key={preset.id}
                    type="button"
                    onClick={() => openQuickstart(preset)}
                    className={`flex items-center gap-3 px-3 py-2.5 rounded-lg border transition-colors text-left ${
                      active
                        ? "border-zinc-400 dark:border-zinc-500 bg-zinc-100 dark:bg-zinc-800"
                        : "border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 hover:border-zinc-300 dark:hover:border-zinc-700 hover:bg-zinc-50 dark:hover:bg-zinc-800"
                    }`}
                  >
                    <span className="shrink-0 text-zinc-600 dark:text-zinc-400">
                      {preset.icon}
                    </span>
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-zinc-800 dark:text-zinc-200 truncate">
                        {preset.label}
                      </p>
                      <p className="text-xs text-zinc-400 truncate">{preset.description}</p>
                    </div>
                  </button>
                );
              })}
            </div>

            {selectedPreset && (
              <div className="flex flex-col gap-3 p-4 rounded-lg border border-zinc-200 dark:border-zinc-700 bg-zinc-50 dark:bg-zinc-950">
                <div className="flex items-center gap-2">
                  <span className="text-zinc-500 dark:text-zinc-400 shrink-0">{selectedPreset.icon}</span>
                  <p className="text-xs font-semibold text-zinc-600 dark:text-zinc-300 uppercase tracking-wide">
                    {selectedPreset.label} settings
                  </p>
                </div>

                <div className="flex flex-col gap-1.5">
                  <label className="text-xs font-semibold text-zinc-500 dark:text-zinc-400 uppercase tracking-wide">
                    Method ID
                  </label>
                  <input
                    value={qsMethodId}
                    onChange={(e) => setQsMethodId(e.target.value)}
                    placeholder={selectedPreset.authMethodId}
                    className="rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-900 px-3 py-1.5 text-sm text-zinc-900 dark:text-zinc-100 placeholder:text-zinc-400 outline-none focus:ring-2 focus:ring-zinc-400 font-mono"
                  />
                </div>

                {selectedPreset.authMethod.method_type === "oauth" && (
                  <>
                    <div className="flex flex-col gap-1.5">
                      <label className="text-xs font-semibold text-zinc-500 dark:text-zinc-400 uppercase tracking-wide">
                        Client ID
                      </label>
                      <input
                        value={qsClientId}
                        onChange={(e) => setQsClientId(e.target.value)}
                        placeholder="your-client-id"
                        className="rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-900 px-3 py-1.5 text-sm text-zinc-900 dark:text-zinc-100 placeholder:text-zinc-400 outline-none focus:ring-2 focus:ring-zinc-400 font-mono"
                      />
                    </div>

                    <div className="flex flex-col gap-1.5">
                      <label className="text-xs font-semibold text-zinc-500 dark:text-zinc-400 uppercase tracking-wide">
                        Client secret env var
                      </label>
                      <div className="rounded-md border border-zinc-200 dark:border-zinc-700 bg-white dark:bg-zinc-900 px-3 py-1.5 text-sm text-zinc-500 dark:text-zinc-400 font-mono select-all">
                        {generateClientSecretEnvVar(qsMethodId.trim() || selectedPreset.authMethodId)}
                      </div>
                      <p className="text-xs text-zinc-400">Auto-generated — set this env var to your OAuth client secret</p>
                    </div>

                    <div className="flex flex-col gap-1.5">
                      <label className="text-xs font-semibold text-zinc-500 dark:text-zinc-400 uppercase tracking-wide">
                        Token endpoint
                      </label>
                      <input
                        value={qsTokenEndpoint}
                        onChange={(e) => setQsTokenEndpoint(e.target.value)}
                        className="rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-900 px-3 py-1.5 text-sm text-zinc-900 dark:text-zinc-100 placeholder:text-zinc-400 outline-none focus:ring-2 focus:ring-zinc-400 font-mono"
                      />
                    </div>

                    <div className="flex flex-col gap-1.5">
                      <label className="text-xs font-semibold text-zinc-500 dark:text-zinc-400 uppercase tracking-wide">
                        User info endpoint
                      </label>
                      <input
                        value={qsUserInfo}
                        onChange={(e) => setQsUserInfo(e.target.value)}
                        className="rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-900 px-3 py-1.5 text-sm text-zinc-900 dark:text-zinc-100 placeholder:text-zinc-400 outline-none focus:ring-2 focus:ring-zinc-400 font-mono"
                      />
                    </div>
                  </>
                )}

                <div className="flex gap-2 pt-1">
                  <button
                    type="button"
                    onClick={commitQuickstart}
                    className="px-3 py-1.5 rounded-md bg-zinc-800 dark:bg-zinc-200 text-white dark:text-zinc-900 text-sm font-medium hover:bg-zinc-700 dark:hover:bg-zinc-300 transition-colors"
                  >
                    Add to config
                  </button>
                  <button
                    type="button"
                    onClick={() => setSelectedPreset(null)}
                    className="px-3 py-1.5 rounded-md border border-zinc-200 dark:border-zinc-700 text-sm text-zinc-600 dark:text-zinc-400 hover:border-zinc-300 dark:hover:border-zinc-600 transition-colors"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}
          </Section>

          {/* Features */}
          <CollapsibleSection title="Features" description="Enable or disable feature flags" open={featuresOpen} onOpenChange={setFeaturesOpen}>
            <FeatureToggle
              label="Proxy authentication"
              description="Guard will proxy reqeusts and enforce authentication."
              checked={config.features?.request_proxy ?? false}
              onChange={(v) =>
                updateConfig({
                  ...config,
                  features: { ...config.features, request_proxy: v },
                })
              }
            />
            <FeatureToggle
              label="Reverse proxy authentication"
              description="Authenticate requests forwarded from your reverse proxy (e.g NGINX auth-url)"
              checked={config.features?.reverse_proxy_authentication ?? false}
              onChange={(v) =>
                updateConfig({
                  ...config,
                  features: { ...config.features, reverse_proxy_authentication: v },
                })
              }
            />
            {rpaEnabled && (
              <div className="ml-4 pl-4 border-l-2 border-zinc-200 dark:border-zinc-700">
                <Input
                  header="Proxy header"
                  description="The original request URL will be lost. Reverse proxies include an original URL request header. Choose which header to use as a reference. **Do not use a user-controlled header**. The integrity of this header is vitally important as it chooses which authentication policies are checked."
                  placeholder="x-original-url"
                  value={config.reverse_proxy_authentication?.config?.header ?? ""}
                  onChange={(v: string) =>
                    updateConfig({
                      ...config,
                      reverse_proxy_authentication: {
                        config: { header: v },
                      },
                    })
                  }
                />
              </div>
            )}
            <FeatureToggle
              label="OAuth server"
              description="Enable OAuth Identity server, this is not required to authenticate with third-party Oauth Servers (e.g. Google)."
              checked={config.features?.oauth_server ?? false}
              onChange={(v) =>
                updateConfig({
                  ...config,
                  features: { ...config.features, oauth_server: v },
                })
              }
            />
            <FeatureToggle
              label="TLS"
              description="Setup TLS for Guard webserver"
              checked={config.features?.tls ?? false}
              onChange={(v) =>
                updateConfig({
                  ...config,
                  features: { ...config.features, tls: v },
                })
              }
            />
          </CollapsibleSection>

          {/* Global styling */}
          <CollapsibleSection
            title="Global styling"
            description="Customize the default login page appearance"
            open={stylingOpen}
            onOpenChange={setStylingOpen}
          >
            <Input
              optional
              header="Alias"
              placeholder="ACME Corp"
              value={config.frontend?.metadata?.alias ?? ""}
              onChange={(v: string) =>
                updateConfig({
                  ...config,
                  frontend: {
                    ...config.frontend,
                    metadata: { ...config.frontend?.metadata, alias: v },
                  },
                })
              }
            />
            <Input
              optional
              header="Public description"
              placeholder="You're accessing sensitive information. Please login."
              value={config.frontend?.metadata?.public_description ?? ""}
              onChange={(v: string) =>
                updateConfig({
                  ...config,
                  frontend: {
                    ...config.frontend,
                    metadata: {
                      ...config.frontend?.metadata,
                      public_description: v,
                    },
                  },
                })
              }
            />
            <Input
              optional
              header="Image URL"
              placeholder="https://example.com/background.jpg"
              value={config.frontend?.metadata?.image ?? ""}
              onChange={(v: string) =>
                updateConfig({
                  ...config,
                  frontend: {
                    ...config.frontend,
                    metadata: { ...config.frontend?.metadata, image: v },
                  },
                })
              }
            />
            <div className="grid grid-cols-2 gap-3">
              <Input
                optional
                header="Username placeholder"
                placeholder="john.doe"
                value={config.frontend?.metadata?.username_placeholder ?? ""}
                onChange={(v: string) =>
                  updateConfig({
                    ...config,
                    frontend: {
                      ...config.frontend,
                      metadata: {
                        ...config.frontend?.metadata,
                        username_placeholder: v,
                      },
                    },
                  })
                }
              />
              <Input
                optional
                header="Domain placeholder"
                placeholder="example.com"
                value={config.frontend?.metadata?.domain_placeholder ?? ""}
                onChange={(v: string) =>
                  updateConfig({
                    ...config,
                    frontend: {
                      ...config.frontend,
                      metadata: {
                        ...config.frontend?.metadata,
                        domain_placeholder: v,
                      },
                    },
                  })
                }
              />
            </div>
          </CollapsibleSection>

          {/* MySQL */}
          <CollapsibleSection
            title="MySQL"
            description="Connection settings for your MySQL / MariaDB instance"
            open={mysqlOpen}
            onOpenChange={setMysqlOpen}
            required={emailActive}
          >
            <Input
              optional
              header="Hostname"
              placeholder="sql.internal.example.com"
              value={config.database?.mysql?.hostname ?? ""}
              onChange={(v: string) =>
                updateConfig({
                  ...config,
                  database: {
                    ...config.database,
                    mysql: { ...config.database?.mysql, hostname: v },
                  },
                })
              }
            />
            <div className="grid grid-cols-2 gap-3">
              <Input
                optional
                header="Port"
                placeholder="3306"
                value={config.database?.mysql?.port ?? ""}
                onChange={(v: string) =>
                  updateConfig({
                    ...config,
                    database: {
                      ...config.database,
                      mysql: {
                        ...config.database?.mysql,
                        port: parseInt(v) || undefined,
                      },
                    },
                  })
                }
              />
              <Input
                optional
                header="Database"
                placeholder="guard"
                value={config.database?.mysql?.database ?? ""}
                onChange={(v: string) =>
                  updateConfig({
                    ...config,
                    database: {
                      ...config.database,
                      mysql: { ...config.database?.mysql, database: v },
                    },
                  })
                }
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <Input
                optional
                header="Username"
                placeholder="guard-user"
                value={config.database?.mysql?.username ?? ""}
                onChange={(v: string) =>
                  updateConfig({
                    ...config,
                    database: {
                      ...config.database,
                      mysql: { ...config.database?.mysql, username: v },
                    },
                  })
                }
              />
              <Input
                optional
                header="Password env var"
                placeholder="MYSQL_PASSWORD"
                value={config.database?.mysql?.password_env ?? ""}
                onChange={(v: string) =>
                  updateConfig({
                    ...config,
                    database: {
                      ...config.database,
                      mysql: { ...config.database?.mysql, password_env: v },
                    },
                  })
                }
              />
            </div>
          </CollapsibleSection>

          {/* SQL Tables */}
          <CollapsibleSection
            title="SQL tables"
            description="Customize table names (Guard uses these defaults)"
            open={sqlTablesOpen}
            onOpenChange={setSqlTablesOpen}
            required={emailActive}
          >
            <div className="grid grid-cols-3 gap-3">
              <Input
                optional
                header="Users"
                placeholder="users"
                value={config.sql?.users_table ?? ""}
                onChange={(v: string) =>
                  updateConfig({ ...config, sql: { ...config.sql, users_table: v } })
                }
              />
              <Input
                optional
                header="Devices"
                placeholder="devices"
                value={config.sql?.devices_table ?? ""}
                onChange={(v: string) =>
                  updateConfig({
                    ...config,
                    sql: { ...config.sql, devices_table: v },
                  })
                }
              />
              <Input
                optional
                header="Magiclinks"
                placeholder="magiclinks"
                value={config.sql?.magiclink_table ?? ""}
                onChange={(v: string) =>
                  updateConfig({
                    ...config,
                    sql: { ...config.sql, magiclink_table: v },
                  })
                }
              />
            </div>
          </CollapsibleSection>

          {/* SMTP */}
          <CollapsibleSection
            title="SMTP"
            description="Email delivery for MagicLinks"
            open={smtpOpen}
            onOpenChange={setSmtpOpen}
            required={emailActive}
          >
            <div className="grid grid-cols-2 gap-3">
              <Input
                optional
                header="Host"
                placeholder="smtp.sendgrid.net"
                value={config.smtp?.host ?? ""}
                onChange={(v: string) =>
                  updateConfig({ ...config, smtp: { ...config.smtp, host: v } })
                }
              />
              <Input
                optional
                header="Port"
                placeholder="587"
                value={config.smtp?.port ?? ""}
                onChange={(v: string) =>
                  updateConfig({
                    ...config,
                    smtp: { ...config.smtp, port: parseInt(v) || undefined },
                  })
                }
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <Input
                optional
                header="Username"
                placeholder="apikey"
                value={config.smtp?.username ?? ""}
                onChange={(v: string) =>
                  updateConfig({ ...config, smtp: { ...config.smtp, username: v } })
                }
              />
              <Input
                optional
                header="Password env var"
                placeholder="SMTP_PASSWORD"
                value={config.smtp?.password_env ?? ""}
                onChange={(v: string) =>
                  updateConfig({
                    ...config,
                    smtp: { ...config.smtp, password_env: v },
                  })
                }
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <Input
                optional
                header="Sender name"
                placeholder="Guard"
                value={config.smtp?.from_alias ?? ""}
                onChange={(v: string) =>
                  updateConfig({
                    ...config,
                    smtp: { ...config.smtp, from_alias: v },
                  })
                }
              />
              <Input
                optional
                header="Sender address"
                placeholder="noreply@example.com"
                value={config.smtp?.from_header ?? ""}
                onChange={(v: string) =>
                  updateConfig({
                    ...config,
                    smtp: { ...config.smtp, from_header: v },
                  })
                }
              />
            </div>
            <Input
              optional
              header="Reply-to address"
              placeholder="support@example.com"
              value={config.smtp?.reply_to_address ?? ""}
              onChange={(v: string) =>
                updateConfig({
                  ...config,
                  smtp: { ...config.smtp, reply_to_address: v },
                })
              }
            />
          </CollapsibleSection>

          {/* Policies */}
          <CollapsibleSection
            title="Policies"
            description="Define who is allowed or blocked from protected services"
            open={policiesOpen}
            onOpenChange={setPoliciesOpen}
          >
            {Object.entries(config.policies ?? {}).map(([id, data]) => (
              <PolicyComponent
                key={id}
                id={id}
                data={data}
                onChange={updatePolicy}
                onRemove={removePolicy}
              />
            ))}
            <button
              type="button"
              onClick={() => setPolicyDialog({ open: true, id: "", data: BLANK_POLICY })}
              className="flex items-center justify-center gap-1.5 w-full px-3 py-2 rounded-lg border border-dashed border-zinc-300 dark:border-zinc-700 text-sm text-zinc-500 dark:text-zinc-400 hover:border-zinc-400 dark:hover:border-zinc-600 hover:text-zinc-700 dark:hover:text-zinc-200 transition-colors"
            >
              + Add Policy
            </button>
          </CollapsibleSection>

          {/* Hostnames */}
          <CollapsibleSection
            title="Hostnames"
            description="Services protected by Guard — link each to auth methods and policies"
            open={hostnamesOpen}
            onOpenChange={setHostnamesOpen}
          >
            {Object.entries(config.hostname ?? {}).map(([id, data]) => (
              <HostnameComponent
                key={id}
                id={id}
                data={data}
                onChange={updateHostname}
                onRemove={removeHostname}
              />
            ))}
            <button
              type="button"
              onClick={() => setHostnameDialog({ open: true, id: "", data: BLANK_HOSTNAME })}
              className="flex items-center justify-center gap-1.5 w-full px-3 py-2 rounded-lg border border-dashed border-zinc-300 dark:border-zinc-700 text-sm text-zinc-500 dark:text-zinc-400 hover:border-zinc-400 dark:hover:border-zinc-600 hover:text-zinc-700 dark:hover:text-zinc-200 transition-colors"
            >
              + Add Hostname
            </button>
          </CollapsibleSection>

          {/* Authentication methods */}
          <CollapsibleSection
            title="Authentication methods"
            description="Configure how users can sign in"
            open={authMethodsOpen}
            onOpenChange={setAuthMethodsOpen}
          >
            {Object.entries(config.authentication_methods ?? {}).map(([id, data]) => (
              <AuthMethodComponent
                key={id}
                id={id}
                data={data}
                onChange={updateAuthMethod}
                onRemove={removeAuthMethod}
                availablePolicies={Object.keys(config.policies ?? {})}
              />
            ))}
            <button
              type="button"
              onClick={() => setMethodDialog({ open: true, id: "", data: BLANK_METHOD })}
              className="flex items-center justify-center gap-1.5 w-full px-3 py-2 rounded-lg border border-dashed border-zinc-300 dark:border-zinc-700 text-sm text-zinc-500 dark:text-zinc-400 hover:border-zinc-400 dark:hover:border-zinc-600 hover:text-zinc-700 dark:hover:text-zinc-200 transition-colors"
            >
              + Add Method
            </button>
          </CollapsibleSection>

          {/* Ready to run footer */}
          <div className="flex flex-col gap-3 pt-2">
            {/* <p className="text-m text-zinc-500 dark:text-zinc-400 text-left">Ready to run?</p> */}
            <button
              type="button"
              onClick={() => setScriptDialogOpen(true)}
              className="w-full px-4 py-2.5 rounded-lg bg-zinc-800 dark:bg-zinc-200 text-sm font-medium text-white dark:text-zinc-900 hover:bg-zinc-700 dark:hover:bg-zinc-300 transition-colors"
            >
              Continue
            </button>
          </div>

          {/* Bottom padding */}
          <div className="h-4" />
        </div>
      </div>

      {/* TOML editor */}
      <div className="flex-1 overflow-y-auto h-full min-w-0">
        <ConfigEditor value={tomlValue} onChange={handleChange} />
      </div>

      {/* Create Policy dialog */}
      {policyDialog.open && (
        <Dialog
          title="Create Policy"
          description="Define who is allowed or blocked from protected services."
          onClose={() => setPolicyDialog({ open: false, id: "", data: BLANK_POLICY })}
          onConfirm={commitPolicy}
          confirmDisabled={!policyDialog.id.trim()}
        >
          <div className="flex flex-col gap-1.5">
            <label className="text-xs font-semibold text-zinc-500 dark:text-zinc-400 uppercase tracking-wide">Policy ID</label>
            <input
              autoFocus
              value={policyDialog.id}
              onChange={(e) => setPolicyDialog((d) => ({ ...d, id: e.target.value }))}
              onKeyDown={(e) => { if (e.key === "Enter" && policyDialog.id.trim()) commitPolicy(); }}
              placeholder="e.g. staff_only"
              className="rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-900 px-3 py-1.5 text-sm text-zinc-900 dark:text-zinc-100 placeholder:text-zinc-400 outline-none focus:ring-2 focus:ring-zinc-400 font-mono"
            />
          </div>
          <PolicyFields
            data={policyDialog.data}
            onChange={(d) => setPolicyDialog((s) => ({ ...s, data: d }))}
          />
        </Dialog>
      )}

      {/* Create Hostname dialog */}
      {hostnameDialog.open && (
        <Dialog
          title="Create Hostname"
          description="Add a service protected by Guard."
          onClose={() => setHostnameDialog({ open: false, id: "", data: BLANK_HOSTNAME })}
          onConfirm={commitHostname}
          confirmDisabled={!hostnameDialog.id.trim()}
        >
          <div className="flex flex-col gap-1.5">
            <label className="text-xs font-semibold text-zinc-500 dark:text-zinc-400 uppercase tracking-wide">Config ID</label>
            <input
              autoFocus
              value={hostnameDialog.id}
              onChange={(e) => setHostnameDialog((d) => ({ ...d, id: e.target.value }))}
              placeholder="e.g. grafana"
              className="rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-900 px-3 py-1.5 text-sm text-zinc-900 dark:text-zinc-100 placeholder:text-zinc-400 outline-none focus:ring-2 focus:ring-zinc-400 font-mono"
            />
          </div>
          <HostnameFields
            data={hostnameDialog.data}
            onChange={(d) => setHostnameDialog((s) => ({ ...s, data: d }))}
            availableAuthMethods={Object.keys(config.authentication_methods ?? {})}
            availablePolicies={Object.keys(config.policies ?? {})}
          />
        </Dialog>
      )}

      {/* Create Method dialog */}
      {methodDialog.open && (
        <Dialog
          title="Create Authentication Method"
          description="Configure how users can sign in."
          onClose={() => setMethodDialog({ open: false, id: "", data: BLANK_METHOD })}
          onConfirm={commitMethod}
          confirmDisabled={!methodDialog.id.trim()}
        >
          <div className="flex flex-col gap-1.5">
            <label className="text-xs font-semibold text-zinc-500 dark:text-zinc-400 uppercase tracking-wide">Method ID</label>
            <input
              autoFocus
              value={methodDialog.id}
              onChange={(e) => setMethodDialog((d) => ({ ...d, id: e.target.value }))}
              placeholder="e.g. google"
              className="rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-900 px-3 py-1.5 text-sm text-zinc-900 dark:text-zinc-100 placeholder:text-zinc-400 outline-none focus:ring-2 focus:ring-zinc-400 font-mono"
            />
          </div>
          <AuthMethodFields
            methodId={methodDialog.id}
            data={methodDialog.data}
            onChange={(d) => setMethodDialog((s) => ({ ...s, data: d }))}
            availablePolicies={Object.keys(config.policies ?? {})}
          />
        </Dialog>
      )}

      {/* Setup script dialog */}
      {scriptDialogOpen && (() => {
        const envVars = collectEnvVars(config);
        const script = scriptTab === "bash"
          ? generateBashScript(tomlValue, envVars)
          : generatePowerShellScript(tomlValue, envVars);
        return (
          <Dialog
            title="Setup script"
            description="Sets your environment variables, saves your config, and downloads the Guard binary."
            onClose={() => setScriptDialogOpen(false)}
            onConfirm={() => setScriptDialogOpen(false)}
            confirmLabel="Done"
          >
            {/* Tabs */}
            <div className="flex gap-1 p-1 rounded-lg bg-zinc-100 dark:bg-zinc-800 w-fit">
              {(["bash", "windows"] as const).map((tab) => (
                <button
                  key={tab}
                  type="button"
                  onClick={() => setScriptTab(tab)}
                  className={`px-3 py-1 rounded-md text-xs font-medium transition-colors ${
                    scriptTab === tab
                      ? "bg-white dark:bg-zinc-900 text-zinc-900 dark:text-zinc-100 shadow-sm"
                      : "text-zinc-500 dark:text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-200"
                  }`}
                >
                  {tab === "bash" ? "Bash (Linux & macOS)" : "Windows (PowerShell)"}
                </button>
              ))}
            </div>

            {/* Script block */}
            <div className="rounded-lg border border-zinc-200 dark:border-zinc-700 bg-zinc-950 overflow-hidden">
              <div className="flex items-center justify-between px-4 py-2 border-b border-zinc-800">
                <span className="text-xs text-zinc-500 font-mono">
                  {scriptTab === "bash" ? "install.sh" : "install.ps1"}
                </span>
                <div className="flex items-center gap-3">
                  <button
                    type="button"
                    onClick={() => {
                      const filename = scriptTab === "bash" ? "install.sh" : "install.ps1";
                      const blob = new Blob([script], { type: "text/plain" });
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement("a");
                      a.href = url;
                      a.download = filename;
                      a.click();
                      URL.revokeObjectURL(url);
                    }}
                    className="text-xs text-zinc-400 hover:text-zinc-200 transition-colors"
                  >
                    Download
                  </button>
                  <button
                    type="button"
                    onClick={copyScript}
                    className="text-xs text-zinc-400 hover:text-zinc-200 transition-colors"
                  >
                    {scriptCopied ? "Copied!" : "Copy"}
                  </button>
                </div>
              </div>
              <pre className="p-4 text-xs text-zinc-300 font-mono overflow-x-auto whitespace-pre leading-relaxed max-h-72 overflow-y-auto">
                {script}
              </pre>
            </div>

            {envVars.length > 0 && (
              <p className="text-xs text-zinc-400">
                Replace <span className="font-mono text-zinc-300">%YOUR … VALUE%</span> with your actual secrets before running.
              </p>
            )}
          </Dialog>
        );
      })()}
    </div>
  );
}
