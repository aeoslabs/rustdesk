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
}

fn usage() -> ! {
    eprintln!(
        "usage: vv-term --id <ID> --password <PW> [--server <host[:port]>] [--relay <host[:port]>]\n\
         \x20              --key <hbbs public key> [--timeout <secs>] [--relay-only] [-v] -- <command>"
    );
    std::process::exit(2);
}

fn parse_args() -> Args {
    let mut a = Args {
        id: String::new(),
        password: String::new(),
        server: "rd-id.videovault.tech".to_owned(),
        relay: None,
        key: std::env::var("VV_TERM_KEY").unwrap_or_default(),
        command: String::new(),
        timeout: 120,
        verbose: false,
        relay_only: false,
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
            "--" => {
                a.command = it.collect::<Vec<_>>().join(" ");
                break;
            }
            _ => usage(),
        }
    }
    if a.id.is_empty() || a.password.is_empty() || a.key.is_empty() || a.command.is_empty() {
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

/// Connect to the relay and pair with the peer's half by uuid.
async fn create_relay(a: &Args, uuid: String, relay_server: &str) -> ResultType<Stream> {
    let relay = a.relay.clone().unwrap_or_else(|| relay_server.to_owned());
    if relay.is_empty() {
        bail!("rendezvous server gave no relay server and --relay is not set");
    }
    let relay = with_port(&relay, RELAY_PORT);
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

struct Markers {
    start: String,
    end: String,
}

/// The line sent to the shell. The command runs in a subshell so `exit` ends only
/// the command, not the terminal. Markers are split with quotes so the echoed input
/// never contains them; only the shell's own output does.
fn shell_line(cmd: &str, token: &str) -> (String, Markers) {
    let line = format!(
        "stty -echo 2>/dev/null; printf '\\n%s%s\\n' '__VVSTART' '_{t}__'; ( {cmd}\n) 2>&1; printf '\\n%s%s_%s__\\n' '__VVEND' '_{t}' \"$?\"\n",
        t = token,
        cmd = cmd
    );
    (
        line,
        Markers {
            start: format!("__VVSTART_{}__", token),
            end: format!("__VVEND_{}_", token),
        },
    )
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
    let code = match tokio::time::timeout(Duration::from_secs(a.timeout), run(&a)).await {
        Ok(Ok(code)) => code,
        Ok(Err(e)) => {
            eprintln!("vv-term: {:#}", e);
            255
        }
        Err(_) => {
            eprintln!("vv-term: timed out after {}s", a.timeout);
            124
        }
    };
    std::process::exit(code);
}

async fn run(a: &Args) -> ResultType<i32> {
    let (mut conn, signed) = rendezvous(a).await?;
    secure_connection(a, &signed, &mut conn).await?;

    let token = format!("{:08x}", hbb_common::rand::random::<u32>());
    let (line, markers) = shell_line(&a.command, &token);
    let mut buf: Vec<u8> = Vec::new();
    let mut printed_to = 0usize; // index into buf after the start marker
    let mut started = false;

    loop {
        let bytes = match conn.next_timeout(60_000).await {
            Some(Ok(b)) => b,
            Some(Err(e)) => bail!("connection error: {}", e),
            None => bail!("connection closed by peer"),
        };
        let msg = match Message::parse_from_bytes(&bytes) {
            Ok(m) => m,
            Err(_) => continue,
        };
        match msg.union {
            Some(message::Union::Hash(hash)) => {
                log::info!("login challenge received");
                let p1 = sha256(a.password.as_bytes(), hash.salt.as_bytes());
                let p2 = sha256(&p1, hash.challenge.as_bytes());
                let mut lr = LoginRequest {
                    username: a.id.clone(),
                    password: p2.into(),
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
                    bail!("login failed: {}", e)
                }
                Some(protos::message::login_response::Union::PeerInfo(pi)) => {
                    log::info!(
                        "logged in: {}@{} ({} {})",
                        pi.username,
                        pi.hostname,
                        pi.platform,
                        pi.version
                    );
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
                    bail!("peer closed the session: {}", r);
                }
            }
            Some(message::Union::TerminalResponse(tr)) => match tr.union {
                Some(terminal_response::Union::Opened(o)) => {
                    if !o.success {
                        bail!("could not open terminal: {}", o.message);
                    }
                    log::info!("terminal opened, pid {}", o.pid);
                    conn.send(&terminal_msg(terminal_action::Union::Data(TerminalData {
                        terminal_id: o.terminal_id,
                        data: line.clone().into_bytes().into(),
                        ..Default::default()
                    })))
                    .await?;
                }
                Some(terminal_response::Union::Data(d)) => {
                    let data = if d.compressed {
                        decompress(&d.data)
                    } else {
                        d.data.to_vec()
                    };
                    buf.extend_from_slice(&data);
                    let text = String::from_utf8_lossy(&buf).into_owned();
                    if !started {
                        if let Some(p) = text.find(&markers.start) {
                            started = true;
                            // skip marker and its line ending
                            let mut i = p + markers.start.len();
                            let rest = &text[i..];
                            i += rest.len() - rest.trim_start_matches(['\r', '\n']).len();
                            printed_to = i;
                        }
                    }
                    if started {
                        if let Some(p) = text[printed_to..].find(&markers.end) {
                            let out = &text[printed_to..printed_to + p];
                            print!("{}", out.replace("\r\n", "\n").trim_end_matches('\n'));
                            println!();
                            let tail = &text[printed_to + p + markers.end.len()..];
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
                        let safe = text.len().saturating_sub(markers.end.len() + 8);
                        if safe > printed_to {
                            let mut cut = safe;
                            while !text.is_char_boundary(cut) {
                                cut -= 1;
                            }
                            print!("{}", text[printed_to..cut].replace("\r\n", "\n"));
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
