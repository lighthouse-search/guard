"use client";

import { useState } from "react";
import TOML from "@iarna/toml";
import ConfigEditor from "./ConfigEditor";
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
    <label className="flex items-center justify-between gap-4 px-4 py-3 rounded-lg border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 cursor-pointer hover:border-zinc-300 dark:hover:border-zinc-700 transition-colors">
      <div>
        <p className="text-sm font-medium text-zinc-700 dark:text-zinc-300">{label}</p>
        {description && (
          <p className="text-xs text-zinc-400 mt-0.5">{description}</p>
        )}
      </div>
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        onClick={(e) => {
          e.preventDefault();
          onChange(!checked);
        }}
        className={`relative w-10 h-5 rounded-full transition-colors duration-200 shrink-0 focus:outline-none focus:ring-2 focus:ring-zinc-400 ${
          checked ? "bg-zinc-700 dark:bg-zinc-400" : "bg-zinc-200 dark:bg-zinc-700"
        }`}
      >
        <span
          className={`absolute top-0.5 w-4 h-4 bg-white rounded-full shadow transition-transform duration-200 ${
            checked ? "translate-x-5" : "translate-x-0.5"
          }`}
        />
      </button>
    </label>
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
    setTomlValue(TOML.stringify(next as any));
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
          {/* Features */}
          <Section title="Features" description="Enable or disable feature flags">
            <FeatureToggle
              label="Proxy authentication"
              description="Guard will proxy reqeusts and enforce authentication."
              checked={config.features?.reverse_proxy_authentication ?? false}
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
