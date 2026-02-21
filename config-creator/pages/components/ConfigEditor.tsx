"use client";

import { useState } from "react";
import Editor from "react-simple-code-editor";
import Prism from "prismjs";
import "prismjs/components/prism-toml";
import "prismjs/themes/prism-tomorrow.css";

const DEFAULT_CONFIG = `[features]
reverse_proxy_authentication = true

[reverse_proxy_authentication.config]
header = "x-original-url"

[frontend.metadata]
instance_hostname = "guard.example.com"
alias = "ACME"
public_description = "You're accessing sensitive information. Please login."
image = "https://images.unsplash.com/photo-1565799557186-1abfed8a31e5?q=80&w=3087&auto=format&fit=crop&ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D"
domain_placeholder="example.com"
username_placeholder="username"

[database.mysql]
username = "example-user"
password_env = "example_user_mysql_password"
hostname = "internal-mariadb-main-service.sql.svc.cluster.local"
port = 3306
database = "guard"

[smtp]
host="smtp.sendgrid.net"
port=587
username="apikey"
from_alias="Guard"
from_header="noreply@paperplane.example.com"
reply_to_address="noreply@paperplane.example.com"
password_env="smtp_password"

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

export default function ConfigEditor() {
  const [code, setCode] = useState(DEFAULT_CONFIG);

  return (
    <Editor
      value={code}
      onValueChange={setCode}
      highlight={(code) => Prism.highlight(code, Prism.languages.toml, "toml")}
      padding={24}
      style={{
        fontFamily: '"Fira Code", "Fira Mono", "Cascadia Code", monospace',
        fontSize: 13,
        backgroundColor: "var(--editor-bg)",
        color: "var(--editor-fg)",
        overflowX: "auto",
        minHeight: "400px",
        width: "100%"
      }}
    />
  );
}
