*Guard is not yet ready for full production use*

# Why
Reverse-proxy authentication sucks. It's usually some NGINX configuration snippet that redirects out to OAuth/Saml, with some hack-job HTML, and an if statement if this person is authorized. Or having to program authentication into individual authentication APIs. It sucks to maintain, not to mention with proper security (such as not using bearer tokens).

# Security
Guard is built off [Hades-auth](https://github.com/oracularhades/hades-auth) and [Dashboard-builder](https://github.com/oracularhades/dashboard-builder). Guard uses hades-auth static_auth, which is a signed JWT, stored in cookies, signed with a private key generated on the user's device. It's pratically impossible to bruteforce a signed JWT, which matches a valid deviceid, certainly without setting off alarm bells, and is much more secure than session tokens.

Note: Yes, hades-auth is all about completely signed requests, but that can't be done with Guard, because the static_auth key has to be stored in cookies.

# Example
Guard allows you to create great, styled, authentication with simple configuration.
<img width="1440" alt="Screenshot 2024-04-27 at 12 38 15 AM" src="https://github.com/oracularhades/guard/assets/91714073/6ab7e3eb-11dd-4066-8f71-34caa00f5920">

```
[features]
proxy_authentication = true

[proxy_authentication.config]
header = "x-original-url"

[frontend.metadata]
instance_hostname = "guard.motionfans.com"
alias = "MotionFans"
public_description = "We need to verify your identity, please login"
image = "https://images.unsplash.com/photo-1565799557186-1abfed8a31e5?q=80&w=3087&auto=format&fit=crop&ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D"
email_domain_placeholder="example.com"
example_username_placeholder="username"

[database.mysql]
username = "example-user"
password = "my_cool_secret"
hostname = "internal-mariadb-main-service.sql.svc.cluster.local"
port = 3306
database = "guard"

[smtp]
host="smtp.sendgrid.net"
port=587
username="apikey"
from_alias="Guard"
from_header="noreply@paperplane.motionfans.com"
reply_to_address="noreply@paperplane.motionfans.com"
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

[hostname.anythingyouwant]
active = true
hostname = "sydney.motionfans.com"
alias = "Sydney"
authentication_methods = ["email"]
multistep_authentication_methods = false
applied_policies = ["staff_only"]
```
#Whats left to do?
- Saml/Oauth authentication. Guard being able to authentication users via those protocols, and be able to be the identity provider for those protocols. Such as if you want to authentication someone on a NAS/router via guard.
- Better error handling in requests.
- Some syntax improvements.
- Cleaning up where functions are stored and adding comments.
- Suggestions! I'm happy to add what people need. However, Guard will not have clutter or barely used features. It's important to minimize the attack surface. Code we have is code we have to maintain, Guard needs to be highly secure.

# Code guidelines
- Keep functions to <50 lines of code, with small exceptions, excluding code comments. If you go over 50 lines, you should consider if you're doing too much. Read-able code is very important.
- Do not add non-standard/not closely monitored cargo packages. Don't just add a cargo package because you want your terminal output to be colourful. Supply chain attacks exist, and we dont want that.
- Comment your code.

*Actual docs to come soon, this is a description*
