"use client";

import { useState } from "react";
import TOML from "@iarna/toml";
import ConfigEditor from "./ConfigEditor";
import HostnameComponent from "./Hostname";
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
ends_with = "@oracularhades.com"

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
}

function parseToml(raw: string): GuardConfig | null {
  try {
    return TOML.parse(raw) as GuardConfig;
  } catch {
    return null;
  }
}

export default function ConfigApp() {
  const [tomlValue, setTomlValue] = useState(DEFAULT_TOML);
  const [config, setConfig] = useState<GuardConfig>(
    parseToml(DEFAULT_TOML) ?? {}
  );

  const hostnameUl = [0, 1, 2, 3].map((_: any, index: number) => (
    <HostnameComponent key={index} />
  ));

  function handleChange(value: string) {
    setTomlValue(value);
    setConfig(parseToml(value) ?? {});
  }

  function updateConfig(next: GuardConfig) {
    setConfig(next);
    setTomlValue(TOML.stringify(next as any));
  }

  return (
    <div className="flex justify-between bg-zinc-50 font-sans dark:bg-black overflow-y-hidden h-screen">
      <div className="flex flex-col w-full p-4 gap-y-10 overflow-y-scroll">
        <h1 className="text-[20px] font-bold">Guard configuration creator</h1>

        <div className="flex flex-col gap-y-4">
          <h2>Features</h2>
          <Input type="checkbox" header="Request proxy" value={config.features?.request_proxy ?? false} onChange={(v: boolean) => updateConfig({ ...config, features: { ...config.features, request_proxy: v } })} />
          <Input type="checkbox" header="Reverse proxy authentication" value={config.features?.reverse_proxy_authentication ?? false} onChange={(v: boolean) => updateConfig({ ...config, features: { ...config.features, reverse_proxy_authentication: v } })} />
          <Input type="checkbox" header="OAuth server" value={config.features?.oauth_server ?? false} onChange={(v: boolean) => updateConfig({ ...config, features: { ...config.features, oauth_server: v } })} />
          <Input type="checkbox" header="TLS" value={config.features?.tls ?? false} onChange={(v: boolean) => updateConfig({ ...config, features: { ...config.features, tls: v } })} />
        </div>

        <div className="flex flex-col gap-y-4">
          <h2>Global styling</h2>
          <Input optional={true} header="Image" placeholder="https://example.com/company-logo-512px.png" value={config.frontend?.metadata?.image ?? ""} onChange={(v: string) => updateConfig({ ...config, frontend: { ...config.frontend, metadata: { ...config.frontend?.metadata, image: v } } })} />
          <Input optional={true} header="Alias" placeholder="e.g. Grafana, Gitlab, Bitwarden or [company name]" value={config.frontend?.metadata?.alias ?? ""} onChange={(v: string) => updateConfig({ ...config, frontend: { ...config.frontend, metadata: { ...config.frontend?.metadata, alias: v } } })} />
          <Input optional={true} header="Public description" placeholder="You're accessing sensitive information. Please login." value={config.frontend?.metadata?.public_description ?? ""} onChange={(v: string) => updateConfig({ ...config, frontend: { ...config.frontend, metadata: { ...config.frontend?.metadata, public_description: v } } })} />
          <Input optional={true} header="Username placeholder" placeholder="john.doe" value={config.frontend?.metadata?.username_placeholder ?? ""} onChange={(v: string) => updateConfig({ ...config, frontend: { ...config.frontend, metadata: { ...config.frontend?.metadata, username_placeholder: v } } })} />
          <Input optional={true} header="Domain placeholder" placeholder="example.com" value={config.frontend?.metadata?.domain_placeholder ?? ""} onChange={(v: string) => updateConfig({ ...config, frontend: { ...config.frontend, metadata: { ...config.frontend?.metadata, domain_placeholder: v } } })} />
        </div>

        <div className="flex flex-col gap-y-4">
          <h2>MySQL</h2>
          <Input optional={true} header="Hostname" placeholder="sql.internal.example.com" value={config.database?.mysql?.hostname ?? ""} onChange={(v: string) => updateConfig({ ...config, database: { ...config.database, mysql: { ...config.database?.mysql, hostname: v } } })} />
          <Input optional={true} header="Port" placeholder="3306" value={config.database?.mysql?.port ?? ""} onChange={(v: string) => updateConfig({ ...config, database: { ...config.database, mysql: { ...config.database?.mysql, port: parseInt(v) || undefined } } })} />
          <Input optional={true} header="Username" placeholder="user" value={config.database?.mysql?.username ?? ""} onChange={(v: string) => updateConfig({ ...config, database: { ...config.database, mysql: { ...config.database?.mysql, username: v } } })} />
          <Input optional={true} header="Password environment variable" placeholder="user_mysql_password" value={config.database?.mysql?.password_env ?? ""} onChange={(v: string) => updateConfig({ ...config, database: { ...config.database, mysql: { ...config.database?.mysql, password_env: v } } })} />
          <Input optional={true} header="Database" placeholder="guard" value={config.database?.mysql?.database ?? ""} onChange={(v: string) => updateConfig({ ...config, database: { ...config.database, mysql: { ...config.database?.mysql, database: v } } })} />
        </div>

        <div className="flex flex-col gap-y-4">
          <h2>SQL</h2>
          <Input optional={true} header="Users" placeholder="users" value={config.sql?.users_table ?? ""} onChange={(v: string) => updateConfig({ ...config, sql: { ...config.sql, users_table: v } })} />
          <Input optional={true} header="Devices" placeholder="devices" value={config.sql?.devices_table ?? ""} onChange={(v: string) => updateConfig({ ...config, sql: { ...config.sql, devices_table: v } })} />
          <Input optional={true} header="Magiclinks" placeholder="magiclinks" value={config.sql?.magiclink_table ?? ""} onChange={(v: string) => updateConfig({ ...config, sql: { ...config.sql, magiclink_table: v } })} />
        </div>

        <div className="flex flex-col gap-y-4">
          <h2>SMTP</h2>
          <Input optional={true} header="Host" placeholder="smtp.example.com" value={config.smtp?.host ?? ""} onChange={(v: string) => updateConfig({ ...config, smtp: { ...config.smtp, host: v } })} />
          <Input optional={true} header="Port" placeholder="587" value={config.smtp?.port ?? ""} onChange={(v: string) => updateConfig({ ...config, smtp: { ...config.smtp, port: parseInt(v) || undefined } })} />
          <Input optional={true} header="Username" placeholder="apikey" value={config.smtp?.username ?? ""} onChange={(v: string) => updateConfig({ ...config, smtp: { ...config.smtp, username: v } })} />
          <Input optional={true} header="Password environment variable" placeholder="user_mysql_password" value={config.smtp?.password_env ?? ""} onChange={(v: string) => updateConfig({ ...config, smtp: { ...config.smtp, password_env: v } })} />
          <Input optional={true} header="Sender name" placeholder="Guard" value={config.smtp?.from_alias ?? ""} onChange={(v: string) => updateConfig({ ...config, smtp: { ...config.smtp, from_alias: v } })} />
          <Input optional={true} header="Sender address" placeholder="noreply@example.com" value={config.smtp?.from_header ?? ""} onChange={(v: string) => updateConfig({ ...config, smtp: { ...config.smtp, from_header: v } })} />
          <Input optional={true} header="Reply-to address" placeholder="support@example.com" value={config.smtp?.reply_to_address ?? ""} onChange={(v: string) => updateConfig({ ...config, smtp: { ...config.smtp, reply_to_address: v } })} />
        </div>

        <div className="flex flex-col gap-y-4">
          <h2>Hostnames</h2>
          {hostnameUl}
          <button>Add hostname</button>
        </div>
      </div>

      <div className="overflow-y-auto h-full w-1/2 shrink-0">
        <ConfigEditor value={tomlValue} onChange={handleChange} />
      </div>
    </div>
  );
}
