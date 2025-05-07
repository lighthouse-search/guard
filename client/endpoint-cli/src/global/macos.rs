use security_framework::os::macos::keychain::SecKeychain;
use security_framework::os::macos::keychain_item::SecKeychainItem;
use security_framework::item::ItemClass;

pub fn store_password(service: &str, account: &str, password: &str) {
    let keychain = SecKeychain::default().unwrap();
    keychain.set_generic_password(service, account, password.as_bytes()).unwrap();
}

pub fn retrieve_password(service: &str, account: &str) -> Option<String> {
    let keychain = SecKeychain::default().unwrap();

    match keychain.find_generic_password(service, account) {
        Ok((password, _item)) => Some(String::from_utf8(password.to_vec()).unwrap()),
        Err(_) => None,
    }
}