"use client";

import { useState } from "react";
import dynamic from "next/dynamic";
import TOML from "@iarna/toml";

// Disable SSR for the editor: react-simple-code-editor sets autoCapitalize="none"
// but browsers normalise it to "off", causing a React hydration mismatch.
const ConfigEditor = dynamic(() => import("./ConfigEditor"), { ssr: false });
import HostnameComponent, { HostnameData } from "./Hostname";
import AuthMethodComponent, { AuthMethodData } from "./AuthMethod";
import PolicyComponent, { PolicyData } from "./Policy";
import Input from "./Input";

const DEFAULT_TOML = `[features]
reverse_proxy_authentication = true

[reverse_proxy_authentication.config]
header = "x-original-url"

[frontend.metadata]
instance_hostname = "guard.example.com"
alias = "ACME"
public_description = "You're accessing sensitive information. Please login."
image = "https://images.unsplash.com/photo-1565799557186-1abfed8a31e5?q=80&w=3087&auto=format&fit=crop&ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D"
domain_placeholder = "example.com"
username_placeholder = "username"

[database.mysql]
username = "example-user"
password_env = "example_user_mysql_password"
hostname = "internal-mariadb-main-service.sql.svc.cluster.local"
port = 3306
database = "guard"

[smtp]
host = "smtp.sendgrid.net"
port = 587
username = "apikey"
from_alias = "Guard"
from_header = "noreply@paperplane.example.com"
reply_to_address = "noreply@paperplane.example.com"
password_env = "smtp_password"

[authentication_methods.email]
active = true
method_type = "email"
applied_policies = ["staff_only"]
should_create_new_users = false

[sql]
users_table = "users"
devices_table = "devices"
magiclink_table = "magiclinks"

[policies.staff_only]
active = true
action = "allow"
property = "email"
ends_with = "@example.com"

[hostname.sydney]
active = true
hostname = "sydney.example.com"
alias = "Sydney"
authentication_methods = ["email"]
multistep_authentication_methods = false
applied_policies = ["staff_only"]`;

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

function AddEntryRow({
  label,
  placeholder,
  onAdd,
}: {
  label: string;
  placeholder?: string;
  onAdd: (id: string) => void;
}) {
  const [id, setId] = useState("");

  function submit() {
    const trimmed = id.trim();
    if (trimmed) {
      onAdd(trimmed);
      setId("");
    }
  }

  return (
    <div className="flex gap-2">
      <input
        value={id}
        onChange={(e) => setId(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter") submit();
        }}
        placeholder={placeholder ?? `ID for new ${label.toLowerCase()}`}
        className="flex-1 rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-900 px-3 py-1.5 text-sm text-zinc-900 dark:text-zinc-100 placeholder:text-zinc-400 outline-none focus:ring-2 focus:ring-zinc-400 font-mono"
      />
      <button
        type="button"
        onClick={submit}
        className="px-3 py-1.5 rounded-md bg-zinc-800 dark:bg-zinc-200 text-white dark:text-zinc-900 text-sm font-medium hover:bg-zinc-700 dark:hover:bg-zinc-300 transition-colors shrink-0"
      >
        Add {label}
      </button>
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
    icon: (
      <svg viewBox="0 0 24 24" className="w-5 h-5" fill="none">
        <path d="M11.5 2L2 8.5v7L11.5 22l9.5-6.5v-7L11.5 2z" fill="#0078D4" />
        <path d="M11.5 2v20M2 8.5l9.5 6 9.5-6" stroke="white" strokeWidth="1" strokeOpacity="0.4" fill="none" />
      </svg>
    ),
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
    icon: (
      <svg viewBox="0 0 24 24" className="w-5 h-5" fill="none">
        <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
        <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
        <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z" fill="#FBBC05"/>
        <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
      </svg>
    ),
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
    icon: (
      <svg viewBox="0 0 24 24" className="w-5 h-5" fill="currentColor">
        <path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"/>
      </svg>
    ),
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
    id: "email",
    label: "Email magic link",
    description: "Passwordless one-time link",
    icon: (
      <svg viewBox="0 0 24 24" className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth="1.75">
        <rect x="2" y="4" width="20" height="16" rx="2"/>
        <path d="M2 7l10 7 10-7"/>
      </svg>
    ),
    authMethodId: "email",
    authMethod: {
      active: true,
      method_type: "email",
      should_create_new_users: false,
      applied_policies: [],
    },
  },
];

export default function ConfigApp() {
  const [tomlValue, setTomlValue] = useState(DEFAULT_TOML);
  const [config, setConfig] = useState<GuardConfig>(
    parseToml(DEFAULT_TOML) ?? {}
  );
  const [copied, setCopied] = useState(false);

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
  function addHostname(id: string) {
    if (config.hostname?.[id]) return;
    updateConfig({
      ...config,
      hostname: {
        ...config.hostname,
        [id]: {
          active: true,
          hostname: "",
          authentication_methods: [],
          applied_policies: [],
          multistep_authentication_methods: false,
        },
      },
    });
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
  function addAuthMethod(id: string) {
    if (config.authentication_methods?.[id]) return;
    updateConfig({
      ...config,
      authentication_methods: {
        ...config.authentication_methods,
        [id]: { active: true, method_type: "email", applied_policies: [], should_create_new_users: false },
      },
    });
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
  function addPolicy(id: string) {
    if (config.policies?.[id]) return;
    updateConfig({
      ...config,
      policies: {
        ...config.policies,
        [id]: { active: true, action: "allow", property: "email" },
      },
    });
  }

  function applyQuickstart(preset: QuickstartPreset) {
    const existingMethods = config.authentication_methods ?? {};
    // Generate a unique key if the id already exists
    let key = preset.authMethodId;
    let suffix = 2;
    while (existingMethods[key]) {
      key = `${preset.authMethodId}_${suffix++}`;
    }
    updateConfig({
      ...config,
      authentication_methods: {
        ...existingMethods,
        [key]: preset.authMethod,
      },
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
          <button
            type="button"
            onClick={copyToml}
            className="px-3 py-1.5 rounded-md border border-zinc-200 dark:border-zinc-700 bg-white dark:bg-zinc-900 text-xs font-medium text-zinc-600 dark:text-zinc-300 hover:border-zinc-300 dark:hover:border-zinc-600 transition-colors"
          >
            {copied ? "Copied!" : "Copy TOML"}
          </button>
        </div>

        {/* Scrollable sections */}
        <div className="flex flex-col gap-8 p-6 overflow-y-auto">
          {/* Quickstart */}
          <Section
            title="Quickstart"
            description="Add a pre-configured authentication method to get started quickly"
          >
            <div className="grid grid-cols-2 gap-2">
              {QUICKSTART_PRESETS.map((preset) => (
                <button
                  key={preset.id}
                  type="button"
                  onClick={() => applyQuickstart(preset)}
                  className="flex items-center gap-3 px-3 py-2.5 rounded-lg border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 hover:border-zinc-300 dark:hover:border-zinc-700 hover:bg-zinc-50 dark:hover:bg-zinc-800 transition-colors text-left"
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
              ))}
            </div>
          </Section>

          {/* Features */}
          <Section title="Features" description="Enable or disable feature flags">
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
              description="Expose an OAuth 2.0 server endpoint"
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
          </Section>

          {/* Global styling */}
          <Section
            title="Global styling"
            description="Customize the default login page appearance"
          >
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
          </Section>

          {/* MySQL */}
          <Section
            title="MySQL"
            description="Connection settings for your MySQL / MariaDB instance"
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
          </Section>

          {/* SQL Tables */}
          <Section
            title="SQL tables"
            description="Customize table names (Guard uses these defaults)"
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
          </Section>

          {/* SMTP */}
          <Section title="SMTP" description="Email delivery for magic links">
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
          </Section>

          {/* Authentication methods */}
          <Section
            title="Authentication methods"
            description="Configure how users can sign in"
          >
            {Object.entries(config.authentication_methods ?? {}).map(([id, data]) => (
              <AuthMethodComponent
                key={id}
                id={id}
                data={data}
                onChange={updateAuthMethod}
                onRemove={removeAuthMethod}
              />
            ))}
            <AddEntryRow
              label="Method"
              placeholder="e.g. email, oauth_google"
              onAdd={addAuthMethod}
            />
          </Section>

          {/* Policies */}
          <Section
            title="Policies"
            description="Define who is allowed or blocked from protected services"
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
            <AddEntryRow
              label="Policy"
              placeholder="e.g. staff_only, block_external"
              onAdd={addPolicy}
            />
          </Section>

          {/* Hostnames */}
          <Section
            title="Hostnames"
            description="Services protected by Guard — link each to auth methods and policies"
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
            <AddEntryRow
              label="Hostname"
              placeholder="e.g. sydney, grafana, gitlab"
              onAdd={addHostname}
            />
          </Section>

          {/* Bottom padding */}
          <div className="h-4" />
        </div>
      </div>

      {/* TOML editor */}
      <div className="flex-1 overflow-y-auto h-full min-w-0">
        <ConfigEditor value={tomlValue} onChange={handleChange} />
      </div>
    </div>
  );
}
