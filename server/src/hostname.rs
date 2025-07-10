use crate::{global::get_authentication_method, structs::*, CONFIG_VALUE};
use url::Url;

pub async fn hostname_auth_exit_flow(host: String, authentication_method: AuthMethod) -> Option<GuardedHostnamePub> {
    let hostname_result = get_hostname(host).await;
    if hostname_result.is_err() == true {
        return None;
    }
    let hostname = hostname_result.expect("Invalid or missing hostname.");
    
    // get hostname and put it in here, and then return the hostname in the request.
    let is_valid_authmethod: bool = is_valid_authentication_method_for_hostname(hostname.clone(), authentication_method.clone()).await.expect("is_valid_authentication_method_for_hostname failed");
    if is_valid_authmethod == true {
        return Some(hostname.into());
    } else {
        return None;
    }
}

pub fn prepend_hostname_to_cookie(cookie_name: &str) -> String {
    let frontend_metadata: FrontendMetadata = CONFIG_VALUE.frontend.clone().and_then(|f| f.metadata).expect("Failed to get config.frontend.metadata");
    let cookie_name = format!("{}_{}", frontend_metadata.instance_hostname.unwrap(), cookie_name).to_string();
    return cookie_name;
}

pub async fn list_hostnames(only_active: bool) -> Vec<GuardedHostname> {
    let hostnames_hashmap = CONFIG_VALUE.hostname.clone().unwrap();
    

    let mut hostnames: Vec<GuardedHostname> = Vec::new();

    for (key, value) in hostnames_hashmap.iter() {
        let parts: Vec<&str> = key.split('.').collect();
        if parts.len() == 1 {
            let hostname: GuardedHostname = value.clone().try_into().expect("lmao");
            if only_active == true {
                // We care if hostnames are active.
                if hostname.active == true {
                    // Hostname is active, we can return it.
                    hostnames.push(hostname);
                }
            } else if only_active == false {
                // We don't care if hostnames are active or not.
                hostnames.push(hostname);
            }
        }
    }

    return hostnames;
}

pub async fn get_active_hostnames() -> Vec<GuardedHostname> {
    let hostnames: Vec<GuardedHostname> = list_hostnames(true).await;
    
    let mut active_hostnames: Vec<GuardedHostname> = Vec::new();
    for value in hostnames {
        if value.active == true {
            let method: GuardedHostname = value;
            active_hostnames.push(method);
        }
    }

    active_hostnames
}

pub async fn get_hostname_authentication_methods(hostname: GuardedHostname, only_active: bool) -> Vec<AuthMethod> {
    let mut authentication_methods: Vec<AuthMethod> = Vec::new();

    for authentication_method_id in hostname.authentication_methods {
        let authentication_method = get_authentication_method(authentication_method_id.clone(), false).await.expect("Missing");
        if only_active == true && authentication_method.active == true {
            authentication_methods.push(authentication_method.clone());
        }
        if only_active == false {
            authentication_methods.push(authentication_method.clone());
        }
    }

    authentication_methods
}

pub async fn is_valid_authentication_method_for_hostname(hostname: GuardedHostname, authentication_method: AuthMethod) -> Result<bool, String> {
    // FUTURE: In ths future. multistep_authentication_methods should be implemented.
    let mut is_valid_hostname_authentication_method: bool = false;
    let hostname_authentication_methods = get_hostname_authentication_methods(hostname, true).await;
    for hostname_authentication_method in hostname_authentication_methods {
        if authentication_method.id == hostname_authentication_method.id {
            // Matches, is valid.
            is_valid_hostname_authentication_method = true;
        }
    }

    if is_valid_hostname_authentication_method != true {
        return Err("The user is attempting to authenticate with a hostname that does not support the provided authentication method.".into());
    }

    Ok(is_valid_hostname_authentication_method)
}

pub async fn get_hostname(hostname: String) -> Result<GuardedHostname, String> {
    let hostnames = get_active_hostnames().await;
    
    let mut hostname_output: Option<GuardedHostname> = None;
    for value in hostnames {
        log::info!("{} {}", value.host, hostname);
        if value.host == hostname {
            hostname_output = Some(value);
        }
    }

    if hostname_output.is_none() {
        return Err("Invalid hostname.".into());
    }

    return Ok(hostname_output.unwrap());
}

pub fn url_to_domain_port(host_unparsed: String) -> Result<String, String> {
    // Parse URL through parser to get host.
    let host = Url::parse(&host_unparsed).unwrap(); // Future: Handle bad value here, otherwise it will just error.

    // Set the result as output_host. This streamlines the value.
    let mut output_host = host.host_str().unwrap().to_string();

    // Sometimes, the header has a port set (e.g example.com:1234, instead of example.com). Guard allows having the same hostnames with different ports, we need to add that information if the port is not 443, otherwise the hostname won't be found.
    if host.port().is_none() == false {
        if host.port().unwrap() != 443 {
            output_host = format!("{}:{}", host.host_str().unwrap().to_string(), host.port().unwrap())
        }
    }

    return Ok(output_host);
}

// Bad name. But this function returns get_hostname alongside parsed URL strings (domain port) and the original_url.
pub async fn get_current_valid_hostname(headers: &Headers, header_to_use: Option<String>) -> Option<GetCurrentValidHostnameStruct> {
    let mut header: String = "host".to_string();
    if header_to_use.is_none() == false {
        header = header_to_use.unwrap();
    }

    let headers_cloned = headers.headers_map.clone();
    if headers_cloned.get(&header).is_none() == true {
        log::info!("Missing header: {}", header);
        return None;
    }

    let mut host_unparsed = headers_cloned.get(&header).unwrap().to_owned();
    // host_unparsed.contains("://") == false, could pick up something in the pathname, but this isn't for security's sake, this is for error handling sake. The URL parser validates the URL.
    if host_unparsed.starts_with("https://") == false && host_unparsed.starts_with("http://") == false && host_unparsed.contains("://") == false {
        // Add HTTPS to protocol in URL, since none was specified (which is always going to happen in "host" headers).
        host_unparsed = format!("https://{}", host_unparsed);
    }

    let domain_port = url_to_domain_port(host_unparsed.clone()).expect("Failed to get output_host");
    let hostname = get_hostname(domain_port.clone()).await;

    if hostname.is_ok() == true {
        // domain_port is a valid hostname.
        return Some(GetCurrentValidHostnameStruct {
            hostname: hostname.unwrap(),
            domain_port: domain_port,
            original_url: host_unparsed
        });
    } else {
        log::info!("Invalid hostname");
        return None;
    }
}