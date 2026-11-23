//! VideoVault Support: settings built into this build, so it needs no config file.
//!
//! This is the only place the VideoVault build differs from RustDesk in behaviour.
//! It replaces the signed `custom.txt` that RustDesk's custom clients read, and it
//! ignores any such file, so nobody can point this build at another server.
//!
//! VideoVault Connect starts this program with `--server`; the editor sees only the
//! prompt that asks them to accept a support session.
//!
//! Session password: when Connect starts `--server` with `VV_SUPPORT_SECRET` set (at least
//! 16 characters), the editor's one Allow in Connect is the consent for the whole support
//! session. Staff log in with that secret instead of an Accept click per connection, the
//! secret stays the temporary password until the process ends (it is never rotated), and
//! the connection manager window stays hidden so closing it cannot end the session; Stop
//! in Connect (it ends this process) is the only end. Without the variable, or with a
//! shorter value, every connection waits for the editor's click exactly as before.
//!
//! The same file also builds the staff viewer (`VV_STAFF_VIEWER=1` at build time): outgoing
//! only, its own app name and config folder, and the staff token from `VV_STAFF_TOKEN`.

use hbb_common::{config, password_security};
use std::sync::{OnceLock, RwLock};

/// Set at build time (`VV_STAFF_VIEWER=1`) for the staff viewer: the same program with
/// outgoing-only settings. Nothing secret is baked in; the staff token is read at launch.
const STAFF_VIEWER: bool = match option_env!("VV_STAFF_VIEWER") {
    // Matching on a str is not allowed in a const, so compare the bytes.
    Some(v) => v.len() == 1 && v.as_bytes()[0] == b'1',
    None => false,
};

pub const APP_NAME: &str = if STAFF_VIEWER {
    "VideoVault Staff Viewer"
} else {
    "VideoVault Support"
};

/// Our rendezvous server's public key (hbbs id_ed25519.pub on RnD).
const SERVER_KEY: &str = "HhlnxcUsOir9FObFW2GBwNcu0DYIyNX+vkFAJMNByYQ=";

/// Fixed settings. The user cannot change these.
const OVERRIDE: &[(&str, &str)] = &[
    // Reach our server only through the Cloudflare tunnel (WebSocket over TLS).
    ("custom-rendezvous-server", "rd-id.videovault.tech"),
    ("relay-server", "rd-relay.videovault.tech"),
    ("api-server", "https://rd-id.videovault.tech"),
    ("key", SERVER_KEY),
    ("allow-websocket", "Y"),
    // No RustDesk tray, update checks or self-updates.
    ("hide-tray", "Y"),
    ("enable-check-update", "N"),
    ("allow-auto-update", "N"),
    ("allow-remote-config-modification", "N"),
    // Nothing to configure for the editor.
    ("hide-server-settings", "Y"),
    ("hide-proxy-settings", "Y"),
    ("hide-network-settings", "Y"),
    ("hide-security-settings", "Y"),
    ("hide-help-cards", "Y"),
    ("disable-change-id", "Y"),
    // No direct IP access: every connection goes through our rendezvous server,
    // which checks the staff token. RustDesk already defaults this off (option2bool
    // treats an empty value as N); forcing it here also overrides a local config file.
    ("direct-server", "N"),
];

/// Environment variable Connect sets when it starts `--server` for one support session.
const SUPPORT_SECRET_ENV: &str = "VV_SUPPORT_SECRET";
/// A shorter value is ignored, so a mistake cannot turn on an easily guessed password.
const SUPPORT_SECRET_MIN_CHARS: usize = 16;

/// The session secret this process runs with, if any. Set only by `apply_with`.
static ACTIVE_SECRET: RwLock<Option<String>> = RwLock::new(None);

/// Keeps only a value that is long enough to serve as the session password.
fn valid_secret(raw: Option<String>) -> Option<String> {
    raw.filter(|s| s.chars().count() >= SUPPORT_SECRET_MIN_CHARS)
}

/// Support sessions: terminal allowed. With a session secret, staff log in with it
/// (approve-mode password); without one, the editor accepts every session by click.
/// Only the temporary password is used, so no permanent password can open the box.
fn incoming_settings(session_password: bool) -> [(&'static str, &'static str); 3] {
    [
        ("enable-terminal", "Y"),
        (
            "approve-mode",
            if session_password { "password" } else { "click" },
        ),
        ("verification-method", "use-temporary-password"),
    ]
}

/// Reads `VV_SUPPORT_SECRET` once per process and removes it from the environment, so the
/// shells and other programs this process starts (terminal sessions, the connection
/// manager) never inherit it. Only this process checks passwords (src/server/connection.rs
/// runs in the `--server` process), so no child needs it.
fn support_secret_from_env() -> Option<String> {
    static SECRET: OnceLock<Option<String>> = OnceLock::new();
    SECRET
        .get_or_init(|| {
            let raw = std::env::var_os(SUPPORT_SECRET_ENV);
            if raw.is_some() {
                std::env::remove_var(SUPPORT_SECRET_ENV);
            }
            valid_secret(raw.and_then(|v| v.into_string().ok()))
        })
        .clone()
}

/// True while this process runs a support session opened with Connect's secret.
pub fn session_password_active() -> bool {
    ACTIVE_SECRET.read().unwrap().is_some()
}

/// Use instead of `password_security::update_temporary_password`. With a session secret
/// the temporary password stays the secret (RustDesk would otherwise make a new one after
/// every login and after 10 wrong attempts, which would lock staff out of the session).
pub fn update_temporary_password() {
    if let Some(secret) = ACTIVE_SECRET.read().unwrap().clone() {
        *password_security::TEMPORARY_PASSWORD.write().unwrap() = secret;
        return;
    }
    password_security::update_temporary_password();
}

pub fn apply() {
    let secret = if STAFF_VIEWER {
        None
    } else {
        support_secret_from_env()
    };
    apply_with(secret);
}

fn apply_with(secret: Option<String>) {
    *config::APP_NAME.write().unwrap() = APP_NAME.to_owned();
    // Support build: incoming only, no way to connect out to anyone.
    // Staff viewer: outgoing only, no way to be connected to.
    config::HARD_SETTINGS.write().unwrap().insert(
        "conn-type".to_owned(),
        if STAFF_VIEWER { "outgoing" } else { "incoming" }.to_owned(),
    );
    // The staff viewer sends this in every connection request; our rendezvous server
    // refuses staff-locked peers without it. Memory only, never written to a file.
    let staff_token = if STAFF_VIEWER {
        std::env::var("VV_STAFF_TOKEN").ok().filter(|t| !t.is_empty())
    } else {
        None
    };
    let mut server = config::OVERWRITE_SETTINGS.write().unwrap();
    let mut local = config::OVERWRITE_LOCAL_SETTINGS.write().unwrap();
    let mut builtin = config::BUILTIN_SETTINGS.write().unwrap();
    let incoming = incoming_settings(secret.is_some());
    let extra: &[(&str, &str)] = if STAFF_VIEWER { &[] } else { &incoming };
    for (k, v) in OVERRIDE.iter().chain(extra.iter()) {
        // Same spread as RustDesk's custom client loader, so every reader sees it.
        server.insert(k.to_string(), v.to_string());
        local.insert(k.to_string(), v.to_string());
        builtin.insert(k.to_string(), v.to_string());
    }
    if let Some(token) = staff_token {
        // The client reads the rendezvous token from LocalConfig `access_token`.
        local.insert("access_token".to_owned(), token);
    }
    // Release the settings locks first: the temporary password's first use generates a
    // random one, which reads these settings.
    drop((server, local, builtin));
    let had_secret = ACTIVE_SECRET.read().unwrap().is_some();
    *ACTIVE_SECRET.write().unwrap() = secret.clone();
    match secret {
        Some(secret) => {
            *password_security::TEMPORARY_PASSWORD.write().unwrap() = secret;
            // Never the secret itself.
            hbb_common::log::info!("VideoVault support: session password on");
        }
        // Only reached in tests: production reads the variable once per process.
        None if had_secret => password_security::update_temporary_password(),
        None => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_or_missing_secret_is_ignored() {
        assert_eq!(valid_secret(None), None);
        assert_eq!(valid_secret(Some(String::new())), None);
        assert_eq!(valid_secret(Some("a".repeat(15))), None);
        // Counted in characters, not bytes: 15 two-byte characters are still too short.
        assert_eq!(valid_secret(Some("\u{e9}".repeat(15))), None);
    }

    #[test]
    fn secret_of_16_or_more_characters_is_kept() {
        let s = "0123456789abcdef".to_owned();
        assert_eq!(valid_secret(Some(s.clone())), Some(s));
        let long = "x".repeat(64);
        assert_eq!(valid_secret(Some(long.clone())), Some(long));
    }

    #[test]
    fn approve_mode_follows_the_secret() {
        let get = |on: bool, key: &str| {
            incoming_settings(on)
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| *v)
        };
        assert_eq!(get(false, "approve-mode"), Some("click"));
        assert_eq!(get(true, "approve-mode"), Some("password"));
        for on in [false, true] {
            assert_eq!(
                get(on, "verification-method"),
                Some("use-temporary-password")
            );
            assert_eq!(get(on, "enable-terminal"), Some("Y"));
        }
    }

    /// Changes the environment and process-wide settings, so everything that depends on
    /// them is in this one test (the other tests touch neither).
    #[test]
    fn secret_from_env_then_apply_with_and_without_it() {
        use password_security::{approve_mode, temporary_password, ApproveMode};
        let secret = "vv-test-secret-0123456789".to_owned();

        std::env::set_var(SUPPORT_SECRET_ENV, &secret);
        assert_eq!(support_secret_from_env(), Some(secret.clone()));
        assert!(
            std::env::var_os(SUPPORT_SECRET_ENV).is_none(),
            "removed, so child processes do not inherit it"
        );
        std::env::set_var(SUPPORT_SECRET_ENV, "another-secret-0123456789");
        assert_eq!(support_secret_from_env(), Some(secret.clone()), "read once per process");
        std::env::remove_var(SUPPORT_SECRET_ENV);

        apply_with(Some(secret.clone()));
        assert!(session_password_active());
        assert_eq!(approve_mode(), ApproveMode::Password);
        assert_eq!(
            config::Config::get_option("verification-method"),
            "use-temporary-password"
        );
        assert_eq!(temporary_password(), secret);
        // A login, or 10 wrong attempts, would rotate it; the secret must stay.
        update_temporary_password();
        update_temporary_password();
        assert_eq!(temporary_password(), secret);

        apply_with(None);
        assert!(!session_password_active());
        assert_eq!(approve_mode(), ApproveMode::Click);
        let random = temporary_password();
        assert_ne!(random, secret);
        update_temporary_password();
        assert_ne!(temporary_password(), random, "without a secret it rotates as before");
    }
}
