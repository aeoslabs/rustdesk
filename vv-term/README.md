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
vv-term --id <ID> --password <PW> \
  [--server <host[:port]>] [--relay <host[:port]>] \
  --key <hbbs public key> [--timeout <secs>] [--relay-only] [-v] -- <command>
```

- `--server`: rendezvous server, default `rd-id.videovault.tech` (port 21116).
  A `ws://` or `wss://` URL is also accepted.
- `--relay`: use this relay instead of the one the rendezvous server names.
- `--key`: the hbbs public key (`id_ed25519.pub`). Also read from `VV_TERM_KEY`.
- `--password`: the peer's password. Also read from `VV_TERM_PASSWORD`, which
  keeps it out of the process list.
- `--relay-only`: skip the direct connection attempt.
- The peer must allow the terminal (`enable-terminal = 'Y'`).

The command runs in a subshell of the peer's login shell, with stderr merged
into stdout. Exit status: the command's own, 255 for a connection or login
error, 124 on timeout.

## Limits (spike)

- POSIX shells only (Linux, macOS). Windows peers open cmd or PowerShell and
  need a different command wrapper.
- No 2FA or trusted-device login, and no click-to-accept flow yet.

## Build

```sh
cd vv-term && cargo build --release -j 2
```

Licence: AGPL-3.0, like the rest of this repository.
