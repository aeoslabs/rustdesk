//! VideoVault Support: settings built into this build, so it needs no config file.
//!
//! This is the only place the VideoVault build differs from RustDesk in behaviour.
//! It replaces the signed `custom.txt` that RustDesk's custom clients read, and it
//! ignores any such file, so nobody can point this build at another server.
//!
//! VideoVault Connect starts this program with `--server`; the editor sees only the
//! prompt that asks them to accept a support session.
//!
//! The same file also builds the staff viewer (`VV_STAFF_VIEWER=1` at build time): outgoing
//! only, its own app name and config folder, and the staff token from `VV_STAFF_TOKEN`.

use hbb_common::config;

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

/// Support sessions: terminal allowed, every session accepted by the editor.
const INCOMING_ONLY: &[(&str, &str)] = &[
    ("enable-terminal", "Y"),
    ("approve-mode", "click"),
    ("verification-method", "use-temporary-password"),
];

pub fn apply() {
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
    let extra: &[(&str, &str)] = if STAFF_VIEWER { &[] } else { INCOMING_ONLY };
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
}
