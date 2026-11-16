# vv-term

A headless RustDesk terminal client. It connects to a RustDesk peer through a
rendezvous server (hbbs) and relay (hbbr), logs in with connection type Terminal,
opens a shell on the peer, runs one command, prints the output and exits with
the command's exit status.

It reuses RustDesk's own protocol and handshake (`src/client.rs`,
`src/server/connection.rs`, `src/server/terminal_service.rs`) and depends only on
`libs/hbb_common`. The peer-to-peer messages are generated from
`libs/base/protos/message.proto`. It does not link the full `rustdesk` crate, so
it builds in a few minutes on a small Linux box.

## Usage

```sh
vv-term --id <ID> [--password <PW>] \
  [--server <host[:port]|wss://url>] [--relay <host[:port]|wss://url>] \
  --key <hbbs public key> [--timeout <secs>] [--accept-timeout <secs>] \
  [--shell auto|posix|powershell|cmd] [--relay-only] [-v] -- <command>
```

- `--server`: rendezvous server. Default `wss://rd-id.videovault.tech/ws/id`, our
  hbbs through the Cloudflare tunnel. A plain `host[:port]` uses raw TCP 21116.
- `--relay`: use this relay instead of the one hbbs names. When `--server` is a
  WebSocket URL, the relay hbbs names is reached the same way, at
  `wss://<relay host>/ws/relay`.
- `--key`: the hbbs public key (`id_ed25519.pub`). Also read from `VV_TERM_KEY`.
- `--password`: the peer's password. Also read from `VV_TERM_PASSWORD`, which
  keeps it out of the process list. Leave it out when the editor accepts each
  session by click.
- `--accept-timeout`: how long to wait for the editor's click (default 120 s).
- `--shell`: how to wrap the command. `auto` picks PowerShell for Windows peers
  (falling back to cmd when `powershell.exe` is missing) and POSIX otherwise.
- `--relay-only`: skip the direct connection attempt.
- The peer must allow the terminal (`enable-terminal = 'Y'`).

The command's stderr is merged into stdout. On POSIX peers it runs in a subshell
of the login shell; on Windows in a child `powershell.exe` (or `cmd.exe /c`), so
`exit` ends only the command. Exit status: the command's own, 125 when the editor
does not accept in time, 124 on timeout, 255 for a connection or login error.

## Limits (spike)

- The Windows wrappers are untested on a real Windows peer.
- The cmd fallback breaks on commands containing double quotes.
- No 2FA or trusted-device login.

## Build

```sh
cd vv-term && cargo build --release -j 2
```

Licence: AGPL-3.0, like the rest of this repository.
