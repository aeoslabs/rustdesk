//! VideoVault Support: settings built into this build, so it needs no config file.
//!
//! This is the only place the VideoVault build differs from RustDesk in behaviour.
//! It replaces the signed `custom.txt` that RustDesk's custom clients read, and it
//! ignores any such file, so nobody can point this build at another server.
//!
//! VideoVault Connect starts this program with `--server`; the editor sees only the
//! prompt that asks them to accept a support session.

use hbb_common::config;

pub const APP_NAME: &str = "VideoVault Support";

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
    // Support sessions: terminal allowed, every session accepted by the editor.
    ("enable-terminal", "Y"),
    ("approve-mode", "click"),
    ("verification-method", "use-temporary-password"),
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
];

pub fn apply() {
    *config::APP_NAME.write().unwrap() = APP_NAME.to_owned();
    // Incoming only: no way to connect out to anyone from this build.
    config::HARD_SETTINGS
        .write()
        .unwrap()
        .insert("conn-type".to_owned(), "incoming".to_owned());
    let mut server = config::OVERWRITE_SETTINGS.write().unwrap();
    let mut local = config::OVERWRITE_LOCAL_SETTINGS.write().unwrap();
    let mut builtin = config::BUILTIN_SETTINGS.write().unwrap();
    for (k, v) in OVERRIDE {
        // Same spread as RustDesk's custom client loader, so every reader sees it.
        server.insert(k.to_string(), v.to_string());
        local.insert(k.to_string(), v.to_string());
        builtin.insert(k.to_string(), v.to_string());
    }
}
