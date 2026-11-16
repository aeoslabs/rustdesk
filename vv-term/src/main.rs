// vv-term: a headless RustDesk terminal client.
//
// Connects to a RustDesk peer through a rendezvous server (hbbs) and relay (hbbr),
// logs in with conn type Terminal, opens a shell, runs one command, prints its output
// and exits with the command's exit status. It reuses RustDesk's own protocol and
// handshake (src/client.rs, src/server/connection.rs, src/server/terminal_service.rs)
// and depends only on hbb_common, so it builds without the full rustdesk crate.
//
// Licence: AGPL-3.0, like the rest of this repository.

mod protos {
    include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));
}

use hbb_common::{
    anyhow::{anyhow, bail, Context},
    compress::decompress,
    config::{RELAY_PORT, RENDEZVOUS_PORT},
    protobuf::Message as _,
    rendezvous_proto::{
        punch_hole_response, rendezvous_message, ConnType, IdPk, NatType, PunchHoleRequest,
        RendezvousMessage, RequestRelay,
    },
    sha2::{Digest, Sha256},
    socket_client::{connect_tcp, connect_tcp_local},
    sodiumoxide::crypto::{box_, secretbox, sign},
    tcp::{kx_version_for, KxTranscript},
    tokio, AddrMangle, ResultType, Stream,
};
use protos::message::{
    login_request, message, misc, terminal_action, terminal_response, LoginRequest, Message,
    OpenTerminal, PublicKey, Terminal, TerminalAction, TerminalData,
};
use hbb_common::log;
use std::time::{Duration, Instant};

const CONNECT_TIMEOUT: u64 = 18_000;
const READ_TIMEOUT: u64 = 18_000;
// Version we announce to the peer; features are gated on it.
const PEER_VERSION: &str = "1.5.3";
// Through the Cloudflare tunnel; raw TCP 21116/21117 is not reachable that way.
const DEFAULT_SERVER: &str = "wss://rd-id.videovault.tech/ws/id";

struct Args {
    id: String,
    password: String,
    server: String,
    relay: Option<String>,
    key: String,
    command: String,
    timeout: u64,
    verbose: bool,
    relay_only: bool,
    accept_timeout: u64,
    shell: String,
}

fn usage() -> ! {
    eprintln!(
        "usage: vv-term --id <ID> [--password <PW>] [--server <host[:port]|wss://url>] [--relay <host[:port]|wss://url>]\n\
         \x20              --key <hbbs public key> [--timeout <secs>] [--accept-timeout <secs>]\n\
         \x20              [--shell auto|posix|powershell|cmd] [--relay-only] [-v] -- <command>"
    );
    std::process::exit(2);
}

fn parse_args() -> Args {
    let mut a = Args {
        id: String::new(),
        password: String::new(),
        server: DEFAULT_SERVER.to_owned(),
        relay: None,
        key: std::env::var("VV_TERM_KEY").unwrap_or_default(),
        command: String::new(),
        timeout: 120,
        verbose: false,
        relay_only: false,
        accept_timeout: 120,
        shell: "auto".to_owned(),
    };
    if let Ok(p) = std::env::var("VV_TERM_PASSWORD") {
        a.password = p;
    }
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--id" => a.id = it.next().unwrap_or_else(|| usage()),
            "--password" => a.password = it.next().unwrap_or_else(|| usage()),
            "--server" => a.server = it.next().unwrap_or_else(|| usage()),
            "--relay" => a.relay = Some(it.next().unwrap_or_else(|| usage())),
            "--key" => a.key = it.next().unwrap_or_else(|| usage()),
            "--timeout" => {
                a.timeout = it
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| usage())
            }
            "-v" | "--verbose" => a.verbose = true,
            "--relay-only" => a.relay_only = true,
            "--accept-timeout" => {
                a.accept_timeout = it
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| usage())
            }
            "--shell" => {
                a.shell = it.next().unwrap_or_else(|| usage());
                if !["auto", "posix", "powershell", "cmd"].contains(&a.shell.as_str()) {
                    usage();
                }
            }
            "--" => {
                a.command = it.collect::<Vec<_>>().join(" ");
                break;
            }
            _ => usage(),
        }
    }
    // An empty password is allowed: the editor then accepts the session by click.
    if a.id.is_empty() || a.key.is_empty() || a.command.is_empty() {
        usage();
    }
    a
}

fn with_port(addr: &str, port: i32) -> String {
    if addr.starts_with("ws://") || addr.starts_with("wss://") {
        return addr.to_owned();
    }
    // host:port, [v6]:port, or a bare v6 address
    let has_port = if addr.starts_with('[') {
        addr.contains("]:")
    } else {
        addr.matches(':').count() == 1
    };
    if has_port {
        addr.to_owned()
    } else {
        format!("{}:{}", addr, port)
    }
}

/// Next rendezvous message, skipping the server's key exchange offers (as RustDesk does).
async fn next_rendezvous(conn: &mut Stream, ms: u64) -> Option<RendezvousMessage> {
    for _ in 0..2 {
        if let Some(Ok(bytes)) = conn.next_timeout(ms).await {
            if let Ok(m) = RendezvousMessage::parse_from_bytes(&bytes) {
                if matches!(m.union, Some(rendezvous_message::Union::KeyExchange(_))) {
                    continue;
                }
                return Some(m);
            }
        }
        break;
    }
    None
}

fn punch_failure(ph: &hbb_common::rendezvous_proto::PunchHoleResponse) -> hbb_common::anyhow::Error {
    if !ph.other_failure.is_empty() {
        return anyhow!(ph.other_failure.clone());
    }
    match ph.failure.enum_value() {
        Ok(punch_hole_response::Failure::ID_NOT_EXIST) => anyhow!("ID does not exist"),
        Ok(punch_hole_response::Failure::OFFLINE) => anyhow!("Remote desktop is offline"),
        Ok(punch_hole_response::Failure::LICENSE_MISMATCH) => anyhow!("Key mismatch"),
        Ok(punch_hole_response::Failure::LICENSE_OVERUSE) => anyhow!("Key overuse"),
        _ => anyhow!("other punch hole failure"),
    }
}

/// The relay to dial. When we reach hbbs over WebSocket, the relay hbbs names
/// (a bare host such as `rd-relay.videovault.tech`) is reached the same way, at
/// `/ws/relay` on that host, as RustDesk's own check_ws does.
fn relay_endpoint(server: &str, relay: &str) -> String {
    if relay.starts_with("ws://") || relay.starts_with("wss://") {
        return relay.to_owned();
    }
    let scheme = if server.starts_with("wss://") {
        "wss"
    } else if server.starts_with("ws://") {
        "ws"
    } else {
        return with_port(relay, RELAY_PORT);
    };
    let host = if relay.starts_with('[') {
        relay.split(']').next().unwrap_or(relay).to_owned() + "]"
    } else {
        relay.split(':').next().unwrap_or(relay).to_owned()
    };
    format!("{}://{}/ws/relay", scheme, host)
}

/// Connect to the relay and pair with the peer's half by uuid.
async fn create_relay(a: &Args, uuid: String, relay_server: &str) -> ResultType<Stream> {
    let relay = a.relay.clone().unwrap_or_else(|| relay_server.to_owned());
    if relay.is_empty() {
        bail!("rendezvous server gave no relay server and --relay is not set");
    }
    let relay = relay_endpoint(&a.server, &relay);
    log::info!("relay {} uuid {}", relay, uuid);
    let mut conn = connect_tcp(relay.as_str(), CONNECT_TIMEOUT)
        .await
        .with_context(|| format!("Failed to connect to relay server {}", relay))?;
    let mut m = RendezvousMessage::new();
    m.set_request_relay(RequestRelay {
        licence_key: a.key.clone(),
        id: a.id.clone(),
        uuid,
        conn_type: ConnType::TERMINAL.into(),
        ..Default::default()
    });
    conn.send(&m).await?;
    Ok(conn)
}

/// Ask hbbs to set up a relay with the peer (used when a direct connection fails).
async fn request_relay(a: &Args, relay_server: &str) -> ResultType<Stream> {
    let server = with_port(&a.server, RENDEZVOUS_PORT);
    for i in 1..=3 {
        let mut socket = connect_tcp(server.as_str(), CONNECT_TIMEOUT).await?;
        let uuid = hbb_common::uuid::Uuid::new_v4().to_string();
        log::info!("#{} request relay, uuid {}", i, uuid);
        let mut m = RendezvousMessage::new();
        m.set_request_relay(RequestRelay {
            id: a.id.clone(),
            uuid: uuid.clone(),
            relay_server: relay_server.to_owned(),
            secure: true,
            ..Default::default()
        });
        socket.send(&m).await?;
        if let Some(m) = next_rendezvous(&mut socket, CONNECT_TIMEOUT).await {
            if let Some(rendezvous_message::Union::RelayResponse(rs)) = m.union {
                if !rs.refuse_reason.is_empty() {
                    bail!(rs.refuse_reason);
                }
                return create_relay(a, uuid, relay_server).await;
            }
        }
    }
    bail!("Timeout requesting relay")
}

/// Punch hole via hbbs. Returns the connected stream and the signed id/pk from hbbs.
async fn rendezvous(a: &Args) -> ResultType<(Stream, Vec<u8>)> {
    let server = with_port(&a.server, RENDEZVOUS_PORT);
    log::info!("rendezvous {}", server);
    let mut socket = connect_tcp(server.as_str(), CONNECT_TIMEOUT)
        .await
        .with_context(|| format!("Failed to connect to rendezvous server {}", server))?;
    let mut m = RendezvousMessage::new();
    m.set_punch_hole_request(PunchHoleRequest {
        id: a.id.clone(),
        nat_type: NatType::SYMMETRIC.into(),
        licence_key: a.key.clone(),
        conn_type: ConnType::TERMINAL.into(),
        version: PEER_VERSION.to_owned(),
        force_relay: true,
        ..Default::default()
    });
    for i in 1..=3u64 {
        log::info!("#{} punch request for {}", i, a.id);
        socket.send(&m).await?;
        let deadline = Instant::now() + Duration::from_millis(i * 3000);
        loop {
            let left = deadline.saturating_duration_since(Instant::now()).as_millis() as u64;
            if left == 0 {
                break;
            }
            let Some(msg) = next_rendezvous(&mut socket, left.max(1)).await else {
                break;
            };
            match msg.union {
                Some(rendezvous_message::Union::PunchHoleResponse(ph)) => {
                    if ph.socket_addr.is_empty() {
                        return Err(punch_failure(&ph));
                    }
                    let signed = ph.pk.to_vec();
                    let peer_addr = AddrMangle::decode(&ph.socket_addr);
                    log::info!(
                        "punch response: peer {} local {} relay {}",
                        peer_addr,
                        ph.is_local(),
                        ph.relay_server
                    );
                    let direct = if a.relay_only {
                        Err(anyhow!("--relay-only"))
                    } else {
                        connect_tcp_local(peer_addr, None, 3000).await
                    };
                    match direct {
                        Ok(conn) => {
                            log::info!("direct connection to {}", peer_addr);
                            return Ok((conn, signed));
                        }
                        Err(e) => {
                            log::info!("direct failed ({}), using relay", e);
                            let conn = request_relay(a, &ph.relay_server).await?;
                            return Ok((conn, signed));
                        }
                    }
                }
                Some(rendezvous_message::Union::RelayResponse(rr)) => {
                    let signed = rr.pk().to_vec();
                    if rr.uuid.is_empty() {
                        bail!("relay response without uuid");
                    }
                    let conn = create_relay(a, rr.uuid.clone(), &rr.relay_server).await?;
                    return Ok((conn, signed));
                }
                _ => {}
            }
        }
    }
    bail!("Timeout connecting to peer via rendezvous server")
}

/// RustDesk's secure_connection: verify the peer's key (signed by hbbs) and agree a stream key.
async fn secure_connection(a: &Args, signed_id_pk: &[u8], conn: &mut Stream) -> ResultType<()> {
    let rs_pk = hbb_common::base64::Engine::decode(
        &hbb_common::base64::engine::general_purpose::STANDARD,
        a.key.trim(),
    )
    .ok()
    .filter(|v| v.len() == 32)
    .ok_or_else(|| anyhow!("--key is not a valid hbbs public key"))?;
    let rs_pk = sign::PublicKey(rs_pk.try_into().unwrap());
    if signed_id_pk.is_empty() {
        bail!("rendezvous server did not send the peer's signed key (wrong --key?)");
    }
    let idpk = IdPk::parse_from_bytes(
        &sign::verify(signed_id_pk, &rs_pk).map_err(|_| anyhow!("hbbs signature mismatch"))?,
    )?;
    if idpk.id != a.id || idpk.pk.len() != 32 {
        bail!("hbbs returned a key for another id");
    }
    let peer_sign_pk = sign::PublicKey(idpk.pk[..].try_into().unwrap());

    let bytes = conn
        .next_timeout(READ_TIMEOUT)
        .await
        .ok_or_else(|| anyhow!("Reset by the peer"))??;
    let msg = Message::parse_from_bytes(&bytes)?;
    let Some(message::Union::SignedId(si)) = msg.union else {
        bail!("Handshake failed: expected SignedId");
    };
    let inner = IdPk::parse_from_bytes(
        &sign::verify(&si.id, &peer_sign_pk).map_err(|_| anyhow!("peer signature mismatch"))?,
    )?;
    if inner.id != a.id || inner.pk.len() != 32 {
        bail!("Handshake failed: peer id mismatch");
    }
    let their_pk_b: [u8; 32] = inner.pk[..].try_into().unwrap();
    // create_symmetric_key_msg
    let (our_pk_b, our_sk_b) = box_::gen_keypair();
    let key = secretbox::gen_key();
    let nonce = box_::Nonce([0u8; box_::NONCEBYTES]);
    let sealed = box_::seal(&key.0, &nonce, &box_::PublicKey(their_pk_b), &our_sk_b);
    let asymmetric_value: hbb_common::bytes::Bytes = Vec::from(our_pk_b.0).into();
    let picked = kx_version_for(inner.kx_version);
    let mut out = Message::new();
    out.set_public_key(PublicKey {
        asymmetric_value: asymmetric_value.clone(),
        symmetric_value: sealed.into(),
        kx_version: picked,
        ..Default::default()
    });
    conn.send(&out).await?;
    conn.set_negotiated_key(
        key,
        true,
        &KxTranscript {
            initiator_pk: &asymmetric_value,
            responder_pk: &their_pk_b,
            advertised: inner.kx_version,
            picked,
        },
    )?;
    log::info!("connection secured (kx v{})", picked);
    Ok(())
}

fn sha256(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(a);
    h.update(b);
    h.finalize().to_vec()
}

fn terminal_msg(action: terminal_action::Union) -> Message {
    let mut ta = TerminalAction::new();
    ta.union = Some(action);
    let mut m = Message::new();
    m.set_terminal_action(ta);
    m
}

const LOGIN_MSG_NO_PASSWORD_ACCESS: &str = "No Password Access";
/// Exit status when the editor does not accept the session in time.
const EXIT_NOT_ACCEPTED: i32 = 125;

#[derive(Clone, Copy, PartialEq, Debug)]
enum Shell {
    Posix,
    PowerShell,
    Cmd,
}

struct Markers {
    start: String,
    end: String,
}

fn b64(data: &[u8]) -> String {
    use hbb_common::base64::Engine;
    hbb_common::base64::engine::general_purpose::STANDARD.encode(data)
}

fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

/// The line sent to the shell, and the markers that frame the command's output.
/// The markers never appear literally in the line, so the terminal's echo of the
/// line is never mistaken for output.
fn shell_line(shell: Shell, cmd: &str, token: &str) -> (String, Markers) {
    let markers = Markers {
        start: format!("__VVSTART_{}__", token),
        end: format!("__VVEND_{}_", token),
    };
    let line = match shell {
        // Subshell, so `exit` ends only the command, not the terminal.
        Shell::Posix => format!(
            "stty -echo 2>/dev/null; printf '\\n%s%s\\n' '__VVSTART' '_{t}__'; ( {cmd}\n) 2>&1; printf '\\n%s%s_%s__\\n' '__VVEND' '_{t}' \"$?\"\n",
            t = token,
            cmd = cmd
        ),
        // A powershell.exe invocation works the same from pwsh, Windows PowerShell or
        // cmd. The command runs in a child powershell.exe, so `exit` ends only the
        // command and $LASTEXITCODE carries its status.
        Shell::PowerShell => {
            let script = format!(
                "$ProgressPreference='SilentlyContinue'\n\
                 try {{ [Console]::OutputEncoding=[Text.Encoding]::UTF8 }} catch {{}}\n\
                 Write-Output ('__VVSTART'+'_{t}__')\n\
                 $s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{c}'))\n\
                 $e=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($s))\n\
                 & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $e 2>&1 | ForEach-Object {{ \"$_\" }}\n\
                 $c=$LASTEXITCODE; if ($null -eq $c) {{ $c=0 }}\n\
                 Write-Output ('__VVEND'+'_{t}_'+$c+'__')\n",
                t = token,
                c = b64(cmd.as_bytes())
            );
            format!(
                "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {}\r",
                b64(&utf16le(&script))
            )
        }
        // Fallback when there is no powershell.exe. Carets split the markers in the
        // echoed line; cmd removes them when it runs the line. !errorlevel! is read
        // after the command runs (delayed expansion).
        Shell::Cmd => format!(
            "cmd.exe /d /v:on /c \"echo __VV^START_{t}__& ({cmd}) 2>&1 & echo __VV^END_{t}_!errorlevel!__\"\r",
            t = token,
            cmd = cmd
        ),
    };
    (line, markers)
}

/// Drop terminal control sequences (colours, cursor moves, titles) from output.
fn strip_ansi(s: &str) -> String {
    lazy_ansi()
        .replace_all(s, "")
        .replace("\r\n", "\n")
        .replace('\r', "")
}

fn lazy_ansi() -> &'static hbb_common::regex::Regex {
    static RE: std::sync::OnceLock<hbb_common::regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        hbb_common::regex::Regex::new(
            r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(\x07|\x1b\\)|\x1b[()][0-9A-Za-z]|\x1b[=>78DEHMc]",
        )
        .unwrap()
    })
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let a = parse_args();
    let level = if a.verbose { "info" } else { "warn" };
    hbb_common::env_logger::Builder::from_env(
        hbb_common::env_logger::Env::default().default_filter_or(level),
    )
    .target(hbb_common::env_logger::Target::Stderr)
    .init();
    let _ = hbb_common::sodiumoxide::init();
    // --timeout covers connecting and the command; waiting for the editor's click
    // has its own --accept-timeout on top.
    let total = Duration::from_secs(a.timeout + a.accept_timeout);
    let code = match tokio::time::timeout(total, run(&a)).await {
        Ok(Ok(code)) => code,
        Ok(Err(e)) => {
            eprintln!("vv-term: {:#}", e);
            255
        }
        Err(_) => {
            eprintln!("vv-term: timed out after {}s", total.as_secs());
            124
        }
    };
    std::process::exit(code);
}

async fn send_command(
    conn: &mut Stream,
    terminal_id: i32,
    shell: Shell,
    a: &Args,
    token: &str,
) -> ResultType<Markers> {
    log::info!("sending command ({:?})", shell);
    let (line, markers) = shell_line(shell, &a.command, token);
    conn.send(&terminal_msg(terminal_action::Union::Data(TerminalData {
        terminal_id,
        data: line.into_bytes().into(),
        ..Default::default()
    })))
    .await?;
    Ok(markers)
}

async fn run(a: &Args) -> ResultType<i32> {
    let (mut conn, signed) = rendezvous(a).await?;
    secure_connection(a, &signed, &mut conn).await?;

    let token = format!("{:08x}", hbb_common::rand::random::<u32>());
    let mut platform = String::new();
    let mut shell = Shell::Posix;
    let mut terminal_id = 0;
    let mut markers: Option<Markers> = None;
    let mut cmd_fallback_tried = false;
    let mut waiting_since: Option<Instant> = None;
    let mut buf: Vec<u8> = Vec::new();
    let mut printed_to = 0usize; // index into the cleaned text after the start marker
    let mut started = false;

    loop {
        if let Some(t) = waiting_since {
            if t.elapsed() > Duration::from_secs(a.accept_timeout) {
                eprintln!(
                    "vv-term: the editor did not accept the session within {}s",
                    a.accept_timeout
                );
                return Ok(EXIT_NOT_ACCEPTED);
            }
        }
        let bytes = match tokio::time::timeout(Duration::from_secs(1), conn.next()).await {
            Err(_) => continue, // tick: re-check the accept deadline
            Ok(Some(Ok(b))) => b,
            Ok(Some(Err(e))) => bail!("connection error: {}", e),
            Ok(None) => {
                if waiting_since.is_some() {
                    bail!("the editor declined the session");
                }
                bail!("connection closed by peer")
            }
        };
        let msg = match Message::parse_from_bytes(&bytes) {
            Ok(m) => m,
            Err(_) => continue,
        };
        match msg.union {
            Some(message::Union::Hash(hash)) => {
                log::info!("login challenge received");
                let password = if a.password.is_empty() {
                    Vec::new()
                } else {
                    let p1 = sha256(a.password.as_bytes(), hash.salt.as_bytes());
                    sha256(&p1, hash.challenge.as_bytes())
                };
                let mut lr = LoginRequest {
                    username: a.id.clone(),
                    password: password.into(),
                    my_id: "vv-term".to_owned(),
                    my_name: "VideoVault Support".to_owned(),
                    my_platform: std::env::consts::OS.to_owned(),
                    session_id: hbb_common::rand::random(),
                    version: PEER_VERSION.to_owned(),
                    ..Default::default()
                };
                lr.union = Some(login_request::Union::Terminal(Terminal::new()));
                let mut m = Message::new();
                m.set_login_request(lr);
                conn.send(&m).await?;
            }
            Some(message::Union::LoginResponse(lr)) => match lr.union {
                Some(protos::message::login_response::Union::Error(e)) => {
                    if e == LOGIN_MSG_NO_PASSWORD_ACCESS {
                        if waiting_since.is_none() {
                            eprintln!(
                                "vv-term: waiting for the editor to accept (up to {}s)",
                                a.accept_timeout
                            );
                            waiting_since = Some(Instant::now());
                        }
                        continue;
                    }
                    bail!("login failed: {}", e)
                }
                Some(protos::message::login_response::Union::PeerInfo(pi)) => {
                    if waiting_since.take().is_some() {
                        eprintln!("vv-term: the editor accepted");
                    }
                    log::info!(
                        "logged in: {}@{} ({} {})",
                        pi.username,
                        pi.hostname,
                        pi.platform,
                        pi.version
                    );
                    platform = pi.platform.clone();
                    shell = match a.shell.as_str() {
                        "posix" => Shell::Posix,
                        "powershell" => Shell::PowerShell,
                        "cmd" => Shell::Cmd,
                        _ if platform == "Windows" => Shell::PowerShell,
                        _ => Shell::Posix,
                    };
                    conn.send(&terminal_msg(terminal_action::Union::Open(OpenTerminal {
                        terminal_id: 0,
                        rows: 50,
                        cols: 250,
                        ..Default::default()
                    })))
                    .await?;
                }
                None => {}
            },
            Some(message::Union::TestDelay(t)) => {
                // echo latency probes back, as the RustDesk client does
                let mut m = Message::new();
                m.set_test_delay(t);
                conn.send(&m).await?;
            }
            Some(message::Union::Misc(m)) => {
                if let Some(misc::Union::CloseReason(r)) = m.union {
                    if waiting_since.is_some() {
                        bail!("the editor declined the session: {}", r);
                    }
                    bail!("peer closed the session: {}", r);
                }
            }
            Some(message::Union::TerminalResponse(tr)) => match tr.union {
                Some(terminal_response::Union::Opened(o)) => {
                    if !o.success {
                        bail!("could not open terminal: {}", o.message);
                    }
                    log::info!("terminal opened on {}, pid {}", platform, o.pid);
                    terminal_id = o.terminal_id;
                    markers =
                        Some(send_command(&mut conn, terminal_id, shell, a, &token).await?);
                }
                Some(terminal_response::Union::Data(d)) => {
                    let data = if d.compressed {
                        decompress(&d.data)
                    } else {
                        d.data.to_vec()
                    };
                    buf.extend_from_slice(&data);
                    let Some(mk) = markers.as_ref() else {
                        continue;
                    };
                    let text = strip_ansi(&String::from_utf8_lossy(&buf));
                    if !started {
                        // No powershell.exe on this Windows peer: fall back to cmd once.
                        if shell == Shell::PowerShell
                            && !cmd_fallback_tried
                            && a.shell == "auto"
                            && (text.contains("'powershell.exe' is not recognized")
                                || text.contains("powershell.exe: command not found"))
                        {
                            cmd_fallback_tried = true;
                            shell = Shell::Cmd;
                            buf.clear();
                            markers = Some(
                                send_command(&mut conn, terminal_id, shell, a, &token).await?,
                            );
                            continue;
                        }
                        if let Some(p) = text.find(&mk.start) {
                            started = true;
                            let mut i = p + mk.start.len();
                            let rest = &text[i..];
                            i += rest.len() - rest.trim_start_matches(['\r', '\n', ' ']).len();
                            printed_to = i;
                        }
                    }
                    if started {
                        if printed_to > text.len() {
                            printed_to = text.len();
                        }
                        if let Some(p) = text[printed_to..].find(&mk.end) {
                            let out = &text[printed_to..printed_to + p];
                            print!("{}", out.trim_end_matches(['\n', ' ']));
                            println!();
                            let tail = &text[printed_to + p + mk.end.len()..];
                            let status: i32 = tail
                                .split("__")
                                .next()
                                .and_then(|s| s.trim().parse().ok())
                                .unwrap_or(255);
                            conn.send(&terminal_msg(terminal_action::Union::Close(
                                protos::message::CloseTerminal {
                                    terminal_id: d.terminal_id,
                                    ..Default::default()
                                },
                            )))
                            .await
                            .ok();
                            return Ok(status);
                        }
                        // stream what we have, holding back a possible partial end marker
                        let safe = text.len().saturating_sub(mk.end.len() + 8);
                        if safe > printed_to {
                            let mut cut = safe;
                            while !text.is_char_boundary(cut) {
                                cut -= 1;
                            }
                            print!("{}", &text[printed_to..cut]);
                            printed_to = cut;
                        }
                    }
                }
                Some(terminal_response::Union::Closed(c)) => {
                    bail!("terminal closed before the command finished (exit {})", c.exit_code)
                }
                Some(terminal_response::Union::Error(e)) => bail!("terminal error: {}", e.message),
                None => {}
            },
            _ => {}
        }
    }
}
