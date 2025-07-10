diesel::table! {
    guard_user (email) {
        id -> Text,
        email -> Text
    }
}

diesel::table! {
    guard_devices (id) {
        id -> Text,
        user_id -> Text,
        authentication_method -> Text,
        collateral -> Nullable<Text>,
        public_key -> Text,
        created -> Nullable<BigInt>
    }
}

diesel::table! {
    magiclinks (code) {
        user_id -> Text,
        code -> Text,
        ip -> Text,
        authentication_method -> Text,
        created -> Nullable<BigInt>
    }
}

diesel::table! {
    bearer_token (access_token_hash) {
        access_token_hash -> Text,
        access_token_salt -> Text,
        refresh_token_hash -> Text,
        refresh_token_salt -> Text,
        user_id -> Text,
        application_clientid -> Text,
        nonce -> Text,
        created -> Nullable<BigInt>
    }
}