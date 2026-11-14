# sshremote-relay

The relay behind remote access by ID in [SSH Remote](https://github.com/thinkbigx/sshremote).
A computer with remote access on keeps a line open here under its 9-digit ID; a viewer asks for
that ID, the relay asks the computer to call back, and from then on copies the bytes of the pair
both ways. Both sides seal everything after their first line (SPAKE2 on the password, then
ChaCha20-Poly1305), so the relay never sees a password, a picture or a key press.

    sshremote-relay [--listen 0.0.0.0:7071] [--store /var/lib/sshremote-relay/ids.json]

`--store` keeps which token owns each ID, so an ID stays its computer's across restarts.

## Protocol

One line from the client, then raw bytes. Behind a web server the same lines can follow an HTTP
upgrade (`GET /relay` with `Upgrade: sshremote-relay`; the client's address in `X-Real-IP`).

| Line | Sent by | Answer |
|---|---|---|
| `listen ID TOKEN` | a computer, kept open | `ok`, or `taken` (another token owns the ID); later, per viewer, `from NONCE ADDRESS` (where the relay sees it from) and `call NONCE` |
| `accept ID NONCE` | the computer, on a new connection | `ok`, then the viewer's bytes |
| `viewer ID` | a viewer | `ok`, then the computer's bytes; or `offline` |
| `status ID` | anyone | `online` or `offline` |
| `secure E` | a computer, before `listen` | `secure E' S`, then a sealed line (below) |

A computer seals its line to the relay (1.3 and later), so nobody in between reads its token or
writes the lines it acts on: it sends a fresh X25519 key `E`; the relay answers with its own
fresh key `E'` and its lasting key `S` (hex), and the keys of each direction come from HKDF-SHA256
over both exchanges (`E` with `S`, and `E` with `E'`). Every line after that, `listen` first, goes
as a frame: two bytes of length, then the words sealed with ChaCha20-Poly1305 (the nonce counts
the frames). The computer checks `S` against the key it knows the relay by: the one SSH Remote
ships with for its public relay, or the one it kept from its first visit to any other. The
lasting key is made in `--key FILE` (by default `relay.key` beside the store) the first time and
must stay: computers that kept it refuse a relay that shows another.

On UDP at the same port the relay answers one question, so two computers behind routers can
find a straight path to each other (NAT hole punching): `sshremote-addr 1 NONCE`, padded with
spaces to at least 64 bytes, is answered with `sshremote-addr 1 NONCE ADDRESS:PORT`, where it saw
the question come from. The answer is never larger than the question, and each address gets 20
a second. The two sides swap what they were told inside their sealed stream and move to the
straight path once it works; the relay then carries nothing more for them. Open UDP on the
port too (a relay without it still works, always in the middle).

Limits per address (an IPv6 /64): open connections, lines a minute, calls to one ID a minute,
new IDs a day; an ID is kept only once its computer has stayed a minute, and is released after
180 days unseen. A pair with nothing either way for two minutes is closed.

## Running it as a service

    sudo install -m 755 target/release/sshremote-relay /usr/local/bin/
    sudo systemctl edit --full --force sshremote-relay

with

    [Service]
    ExecStart=/usr/local/bin/sshremote-relay --listen 0.0.0.0:7071 --store /var/lib/sshremote-relay/ids.json
    DynamicUser=yes
    StateDirectory=sshremote-relay
    Restart=always

When only ports 80 and 443 reach the server, let the web server pass `/relay` to it (SSH Remote
falls back to port 80 by itself).
