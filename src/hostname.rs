use crate::global::{get_hostname, is_valid_authentication_method_for_hostname};
use crate::structs::*;

pub async fn hostname_auth_exit_flow(host: String, authentication_method: AuthMethod) -> Option<Guarded_Hostname_Pub> {
    let hostname_result = get_hostname(host).await;
    if (hostname_result.is_none() == true) {
        return None;
    }
    let hostname = hostname_result.expect("Invalid or missing hostname.");
    
    // get hostname and put it in here, and then return the hostname in the request.
    let is_valid_authmethod: bool = is_valid_authentication_method_for_hostname(hostname.clone(), authentication_method.clone()).await.expect("is_valid_authentication_method_for_hostname failed");
    if (is_valid_authmethod == true) {
        return Some(hostname.into());
    } else {
        return None;
    }
}