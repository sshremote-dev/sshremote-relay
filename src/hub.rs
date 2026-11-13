//! The relay: computers wait under their remote access ID, viewers call them by it, and each
//! paired session's bytes are copied both ways. Everything past the first line is sealed end to
//! end by the two sides; the relay reads none of it. The protocol is in README.md.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// Seconds since 1970.
fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn random(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    getrandom::getrandom(&mut b).expect("system random source");
    b
}

/// An ID: 6 to 12 digits.
fn valid_id(id: &str) -> bool {
    (6..=12).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_digit())
}

use std::collections::HashMap;
use std::net::{IpAddr, TcpListener};
use std::sync::mpsc;
use std::time::Instant;

/// Connections one address (an IPv6 /64) may hold at once once it has said what it wants,
/// and before that (a slow first line); lines it may send a minute, and status questions.
const PER_ADDRESS: usize = 32;
const HELLO_PER_ADDRESS: usize = 16;
const TRIES_A_MINUTE: u32 = 60;
const STATUS_A_MINUTE: u32 = 600;
/// Calls to one ID a minute, and calls waiting for it at once.
const CALLS_A_MINUTE: u32 = 60;
const CALLS_FROM_ONE_A_MINUTE: u32 = 5;
const CALLS_WAITING: usize = 4;
/// New IDs one address may take a day; an ID is kept only after its agent stayed a minute.
const NEW_IDS_A_DAY: u32 = 50;
const SETTLE: Duration = Duration::from_secs(60);
/// Connections in all, so a flood cannot take the machine's threads.
const ALL: usize = 4000;
/// The first line (and an HTTP upgrade's headers) must come within this.
const HELLO: Duration = Duration::from_secs(10);
/// A paired session with nothing either way for this long is over (sessions ping every second).
const IDLE: Duration = Duration::from_secs(120);
/// IDs not seen for this long go back to the pool.
const KEEP_ID: u64 = 180 * 24 * 3600;


/// The part of an address that limits count by: all of IPv4, the /64 of IPv6.
fn key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => {
            let mut s = v6.segments();
            s[4..].fill(0);
            IpAddr::V6(std::net::Ipv6Addr::from(s))
        }
        v4 => v4,
    }
}

fn hash(token: &str) -> String {
    use sha2::Digest;
    hex(&sha2::Sha256::digest(token.as_bytes()))
}

/// A count in a window of time: whether one more is within `max`.
fn within<K: std::hash::Hash + Eq>(map: &mut HashMap<K, (Instant, u32)>, k: K, window: Duration, max: u32) -> bool {
    let e = map.entry(k).or_insert((Instant::now(), 0));
    if e.0.elapsed() > window {
        *e = (Instant::now(), 0);
    }
    e.1 += 1;
    e.1 <= max
}

fn up(map: &mut HashMap<IpAddr, usize>, k: IpAddr, max: usize) -> bool {
    let n = map.entry(k).or_insert(0);
    if *n >= max {
        return false;
    }
    *n += 1;
    true
}

fn down(map: &mut HashMap<IpAddr, usize>, k: IpAddr) {
    if let Some(n) = map.get_mut(&k) {
        *n = n.saturating_sub(1);
        if *n == 0 {
            map.remove(&k);
        }
    }
}

#[derive(Default)]
pub struct Hub {
    /// ID → the token's hash and when it was last seen, kept on disk so an ID stays its owner's.
    owners: HashMap<String, (String, u64)>,
    dirty: bool,
    /// ID → its listening line's number, a way to call the agent, and its token's hash (which
    /// holds the ID while it is not yet kept).
    agents: HashMap<String, (u64, mpsc::Sender<(String, IpAddr)>, String)>,
    next: u64,
    /// NONCE → the viewer waiting for that call to be answered.
    calls: HashMap<String, mpsc::Sender<TcpStream>>,
    /// Calls by ID in the current minute, and waiting now.
    calls_by_id: HashMap<String, (Instant, u32)>,
    calls_by_source: HashMap<(String, IpAddr), (Instant, u32)>,
    waiting_by_id: HashMap<String, usize>,
    /// Lines and status questions by address in the current minute; new IDs by address today.
    tries: HashMap<IpAddr, (Instant, u32)>,
    statuses: HashMap<IpAddr, (Instant, u32)>,
    new_ids: HashMap<IpAddr, (Instant, u32)>,
    /// Connections held by address: before their first line, and after it.
    hello: HashMap<IpAddr, usize>,
    held: HashMap<IpAddr, usize>,
    all: usize,
}

impl Hub {
    /// The owners kept in `store`; a file that is there but cannot be read stops the relay
    /// rather than handing every ID to whoever asks first.
    pub fn new(store: Option<&std::path::Path>) -> Result<Hub, String> {
        let mut h = Hub::default();
        if let Some(f) = store.filter(|f| f.exists()) {
            let text = std::fs::read_to_string(f).map_err(|e| format!("{}: {e}", f.display()))?;
            let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| format!("{}: {e}", f.display()))?;
            for (id, o) in v.as_object().into_iter().flatten() {
                match o {
                    // The first version kept only the hash.
                    serde_json::Value::String(h0) => {
                        h.owners.insert(id.clone(), (h0.clone(), now()));
                    }
                    o => {
                        if let (Some(hh), Some(t)) = (o.get(0).and_then(|x| x.as_str()), o.get(1).and_then(|x| x.as_u64())) {
                            h.owners.insert(id.clone(), (hh.to_string(), t));
                        }
                    }
                }
            }
        }
        Ok(h)
    }

    /// Whether a token may use an ID now: its owner's, or one nobody holds.
    fn may_use(&self, id: &str, token: &str) -> bool {
        let h = hash(token);
        match self.owners.get(id) {
            Some((o, _)) => *o == h,
            None => self.agents.get(id).is_none_or(|(_, _, a)| *a == h),
        }
    }

    /// The ID kept as this token's, or its last-seen time brought up to date.
    fn keep(&mut self, id: &str, token: &str) {
        self.owners.insert(id.to_string(), (hash(token), now()));
        self.dirty = true;
    }

    /// Forgets what has gone stale: minutes of tries, IDs long unseen.
    fn prune(&mut self) {
        let minute = Duration::from_secs(60);
        self.tries.retain(|_, (t, _)| t.elapsed() < minute);
        self.statuses.retain(|_, (t, _)| t.elapsed() < minute);
        self.calls_by_id.retain(|_, (t, _)| t.elapsed() < minute);
        self.calls_by_source.retain(|_, (t, _)| t.elapsed() < minute);
        self.new_ids.retain(|_, (t, _)| t.elapsed() < Duration::from_secs(24 * 3600));
        let cut = now().saturating_sub(KEEP_ID);
        let before = self.owners.len();
        self.owners.retain(|_, (_, seen)| *seen >= cut);
        self.dirty |= self.owners.len() != before;
    }
}

type Shared = Arc<Mutex<Hub>>;

fn lock(hub: &Shared) -> std::sync::MutexGuard<'_, Hub> {
    hub.lock().unwrap_or_else(|e| e.into_inner())
}

/// The start of a "where do you see me from" question on UDP, and of its answer.
const REFLECT: &[u8] = b"sshremote-addr 1 ";
/// Questions one address may ask a second.
const REFLECTS_A_SECOND: u32 = 20;

/// The answer to a UDP question `q` from `from`: the address and port it came from, which is
/// where the other side of a session can reach that socket through its router (NAT hole
/// punching). Never larger than the question, so the relay cannot amplify a flood.
pub fn reflect_answer(q: &[u8], from: std::net::SocketAddr) -> Option<Vec<u8>> {
    let rest = q.strip_prefix(REFLECT)?;
    let nonce: String = std::str::from_utf8(rest).ok()?.split_whitespace().next()?.chars().take(32).collect();
    let a = format!("{}{nonce} {from}", String::from_utf8_lossy(REFLECT)).into_bytes();
    (a.len() <= q.len()).then_some(a)
}

/// Answers UDP questions on the relay's port, a few a second from each address.
fn reflect(listen: &str) {
    let sock = match std::net::UdpSocket::bind(listen) {
        Ok(s) => s,
        Err(e) => return eprintln!("no UDP on {listen} ({e}): sessions stay on the relay"),
    };
    let mut buf = [0u8; 512];
    let mut asked: HashMap<IpAddr, (Instant, u32)> = HashMap::new();
    let mut pruned = Instant::now();
    loop {
        let Ok((n, from)) = sock.recv_from(&mut buf) else { continue };
        if pruned.elapsed() > Duration::from_secs(60) {
            asked.retain(|_, (t, _)| t.elapsed() < Duration::from_secs(1));
            pruned = Instant::now();
        }
        if !within(&mut asked, key(from.ip()), Duration::from_secs(1), REFLECTS_A_SECOND) {
            continue;
        }
        if let Some(a) = reflect_answer(&buf[..n], from) {
            let _ = sock.send_to(&a, from);
        }
    }
}

/// Runs the relay until the listener fails.
pub fn serve(listen: &str, store: Option<&str>) -> Result<(), String> {
    let store = store.map(PathBuf::from);
    let hub: Shared = Arc::new(Mutex::new(Hub::new(store.as_deref())?));
    let listener = TcpListener::bind(listen).map_err(|e| format!("{listen}: {e}"))?;
    println!("sshremote relay listening on {listen} (TCP, and UDP for where computers are seen from)");
    {
        let listen = listen.to_string();
        thread::spawn(move || reflect(&listen));
    }
    // Every 30 s: stale entries out, and the owners written (outside the lock, whole or not at all).
    {
        let hub = hub.clone();
        thread::spawn(move || {
            loop {
                thread::sleep(Duration::from_secs(30));
                let snapshot = {
                    let mut h = lock(&hub);
                    h.prune();
                    if !std::mem::take(&mut h.dirty) {
                        continue;
                    }
                    let map: serde_json::Map<String, serde_json::Value> = h.owners.iter().map(|(id, (hh, t))| (id.clone(), serde_json::json!([hh, t]))).collect();
                    serde_json::Value::Object(map).to_string()
                };
                if let Some(f) = &store {
                    let tmp = f.with_extension("new");
                    let done = std::fs::File::create(&tmp).and_then(|mut o| {
                        o.write_all(snapshot.as_bytes())?;
                        o.sync_all()
                    });
                    let done = done.and_then(|_| std::fs::rename(&tmp, f));
                    // The folder too, so the rename itself survives a power cut.
                    #[cfg(unix)]
                    if let Some(d) = f.parent().and_then(|d| std::fs::File::open(d).ok()) {
                        let _ = d.sync_all();
                    }
                    if done.is_err() {
                        lock(&hub).dirty = true;
                    }
                }
            }
        });
    }
    for s in listener.incoming().flatten() {
        let Ok(peer) = s.peer_addr().map(|a| a.ip()) else { continue };
        {
            // A web server on this machine speaks for many: its clients are counted once it
            // names them.
            let mut h = lock(&hub);
            if h.all >= ALL || (!peer.is_loopback() && !up(&mut h.hello, key(peer), HELLO_PER_ADDRESS)) {
                continue;
            }
            h.all += 1;
        }
        let hub = hub.clone();
        thread::spawn(move || {
            struct All(Shared);
            impl Drop for All {
                fn drop(&mut self) {
                    lock(&self.0).all -= 1;
                }
            }
            let _all = All(hub.clone());
            connection(&hub, s, peer);
        });
    }
    Ok(())
}

/// Reads one line within `deadline`, byte by byte (what follows belongs to the handshake).
fn hello_line(s: &mut TcpStream, deadline: Instant) -> Option<String> {
    let mut raw = Vec::new();
    let mut b = [0u8; 1];
    while raw.len() < 1024 {
        let left = deadline.checked_duration_since(Instant::now())?;
        s.set_read_timeout(Some(left.max(Duration::from_millis(1)))).ok()?;
        match s.read(&mut b) {
            Ok(1) if b[0] == 10 => {
                let l = String::from_utf8_lossy(&raw).to_string();
                return Some(l.trim_end_matches('\r').to_string());
            }
            Ok(1) => raw.push(b[0]),
            _ => return None,
        }
    }
    None
}

/// What a connection asks, read within [`HELLO`]: the line and the address it counts for.
fn hello(hub: &Shared, s: &mut TcpStream, peer: IpAddr, counted: &mut Option<IpAddr>) -> Option<(String, IpAddr)> {
    let deadline = Instant::now() + HELLO;
    let mut first = hello_line(s, deadline)?;
    let mut ip = peer;
    // Through a web server: an HTTP upgrade, then the same lines. Only a web server on this
    // machine may say where its client is, and it must.
    if first.starts_with("GET ") {
        let mut real = None;
        for _ in 0..32 {
            let h = hello_line(s, deadline)?;
            if h.trim().is_empty() {
                break;
            }
            if let Some((k, v)) = h.split_once(':')
                && k.trim().eq_ignore_ascii_case("x-real-ip")
            {
                real = v.trim().parse::<IpAddr>().ok();
            }
        }
        if peer.is_loopback() {
            ip = real?;
            // Counted as its own address from here, as a direct connection is from the start.
            if !up(&mut lock(hub).hello, key(ip), HELLO_PER_ADDRESS) {
                return None;
            }
            *counted = Some(ip);
        }
        s.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: sshremote-relay\r\nConnection: Upgrade\r\n\r\n").ok()?;
        first = hello_line(s, deadline)?;
    }
    let _ = s.set_read_timeout(None);
    Some((first, ip))
}

fn connection(hub: &Shared, mut s: TcpStream, peer: IpAddr) {
    let mut counted = None;
    let asked = hello(hub, &mut s, peer, &mut counted);
    {
        let mut h = lock(hub);
        if !peer.is_loopback() {
            down(&mut h.hello, key(peer));
        }
        if let Some(c) = counted {
            down(&mut h.hello, key(c));
        }
    }
    let Some((first, ip)) = asked else { return };
    let words: Vec<String> = first.split_whitespace().map(str::to_string).collect();
    let words: Vec<&str> = words.iter().map(String::as_str).collect();
    match words.as_slice() {
        // `accept` answers a call the relay made, with an unguessable nonce of its own: it
        // counts against nothing, or a queue of calls could keep the agent from answering.
        ["accept", id, nonce] if valid_id(id) && nonce.len() <= 64 => {
            let waiting = lock(hub).calls.remove(*nonce);
            if let Some(v) = waiting {
                let _ = v.send(s);
            }
            return;
        }
        // Status questions come from every open window every few seconds: a budget of their own.
        ["status", id] if valid_id(id) => {
            let (ok, on) = {
                let mut h = lock(hub);
                (within(&mut h.statuses, key(ip), Duration::from_secs(60), STATUS_A_MINUTE), h.agents.contains_key(*id))
            };
            let _ = writeln!(s, "{}", if !ok { "too many attempts; wait a minute" } else if on { "online" } else { "offline" });
            return;
        }
        _ => {}
    }
    {
        let mut h = lock(hub);
        if !within(&mut h.tries, key(ip), Duration::from_secs(60), TRIES_A_MINUTE) || !up(&mut h.held, key(ip), PER_ADDRESS) {
            drop(h);
            let _ = writeln!(s, "too many attempts; wait a minute");
            return;
        }
    }
    struct Held(Shared, IpAddr);
    impl Drop for Held {
        fn drop(&mut self) {
            down(&mut lock(&self.0).held, key(self.1));
        }
    }
    let _held = Held(hub.clone(), ip);
    match words.as_slice() {
        ["listen", id, token] if valid_id(id) && (16..=128).contains(&token.len()) => listen(hub, s, id, token, ip),
        ["viewer", id] if valid_id(id) => viewer(hub, s, id, ip),
        _ => {}
    }
}

/// An agent's line: calls passed on, pings, and the line given up when it goes quiet or a
/// newer line for the same ID replaces it. An ID nobody held becomes this token's once its
/// agent has stayed a minute, a few new ones an address a day.
fn listen(hub: &Shared, mut s: TcpStream, id: &str, token: &str, ip: IpAddr) {
    let (tx, rx) = mpsc::channel::<(String, IpAddr)>();
    let (number, mut kept) = {
        let mut h = lock(hub);
        if !h.may_use(id, token) {
            drop(h);
            let _ = writeln!(s, "taken");
            return;
        }
        // New IDs are counted when kept; an address past its day's allowance waits.
        let known = h.owners.contains_key(id);
        if !known && h.new_ids.get(&key(ip)).is_some_and(|(t, n)| t.elapsed() < Duration::from_secs(24 * 3600) && *n >= NEW_IDS_A_DAY) {
            drop(h);
            let _ = writeln!(s, "busy: too many new IDs from this address today");
            return;
        }
        h.next += 1;
        let n = h.next;
        h.agents.insert(id.to_string(), (n, tx, hash(token)));
        (n, None::<Instant>)
    };
    let since = Instant::now();
    if writeln!(s, "ok").is_ok() && s.set_read_timeout(Some(Duration::from_millis(200))).is_ok() {
        let mut heard = Instant::now();
        let mut pinged = Instant::now();
        let mut buf = [0u8; 64];
        'line: loop {
            // Kept (or seen again) after a minute, then every hour while it stays.
            if since.elapsed() > SETTLE && kept.is_none_or(|t| t.elapsed() > Duration::from_secs(3600)) {
                let mut h = lock(hub);
                if !h.may_use(id, token) {
                    break;
                }
                if !h.owners.contains_key(id) {
                    within(&mut h.new_ids, key(ip), Duration::from_secs(24 * 3600), u32::MAX);
                }
                h.keep(id, token);
                kept = Some(Instant::now());
            }
            loop {
                match rx.try_recv() {
                    // Where the viewer is, for a computer that takes only some addresses;
                    // agents that do not know the line pass it by.
                    Ok((nonce, from)) => {
                        if writeln!(s, "from {nonce} {}\ncall {nonce}", from.to_canonical()).is_err() {
                            break 'line;
                        }
                    }
                    Err(mpsc::TryRecvError::Empty) => break,
                    // Replaced by a newer line for this ID.
                    Err(mpsc::TryRecvError::Disconnected) => break 'line,
                }
            }
            if pinged.elapsed() > Duration::from_secs(30) {
                if writeln!(s, "ping").is_err() {
                    break;
                }
                pinged = Instant::now();
            }
            match s.read(&mut buf) {
                Ok(0) => break,
                Ok(_) => heard = Instant::now(),
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                    if heard.elapsed() > Duration::from_secs(75) {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    }
    let mut h = lock(hub);
    if h.agents.get(id).is_some_and(|(n, _, _)| *n == number) {
        h.agents.remove(id);
    }
}

/// A viewer: its call passed to the agent, and the agent's answering connection paired with it.
fn viewer(hub: &Shared, mut s: TcpStream, id: &str, ip: IpAddr) {
    let agent = lock(hub).agents.get(id).map(|(_, t, _)| t.clone());
    let Some(agent) = agent else {
        let _ = writeln!(s, "offline");
        return;
    };
    let nonce = hex(&random(16));
    let (tx, rx) = mpsc::channel();
    {
        let mut h = lock(hub);
        let waiting = h.waiting_by_id.get(id).copied().unwrap_or(0);
        // A few calls a minute from any one address, so one cannot keep the owner out alone.
        let minute = Duration::from_secs(60);
        if h.calls.len() >= 10_000
            || waiting >= CALLS_WAITING
            || !within(&mut h.calls_by_source, (id.to_string(), key(ip)), minute, CALLS_FROM_ONE_A_MINUTE)
            || !within(&mut h.calls_by_id, id.to_string(), minute, CALLS_A_MINUTE)
        {
            drop(h);
            let _ = writeln!(s, "too many attempts; wait a minute");
            return;
        }
        h.calls.insert(nonce.clone(), tx);
        *h.waiting_by_id.entry(id.to_string()).or_insert(0) += 1;
    }
    let answered = if agent.send((nonce.clone(), ip)).is_ok() { rx.recv_timeout(Duration::from_secs(20)).ok() } else { None };
    {
        let mut h = lock(hub);
        h.calls.remove(&nonce);
        if let Some(n) = h.waiting_by_id.get_mut(id) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                h.waiting_by_id.remove(id);
            }
        }
    }
    let Some(mut a) = answered else {
        let _ = writeln!(s, "the computer did not answer");
        return;
    };
    if writeln!(a, "ok").is_ok() && writeln!(s, "ok").is_ok() {
        splice(a, s);
    }
}

/// Copies bytes both ways until either side ends or both go quiet for [`IDLE`].
pub fn splice(a: TcpStream, b: TcpStream) {
    let _ = a.set_read_timeout(Some(IDLE));
    let _ = b.set_read_timeout(Some(IDLE));
    let (Ok(mut a2), Ok(mut b2)) = (a.try_clone(), b.try_clone()) else { return };
    let (mut a, mut b) = (a, b);
    let t = thread::spawn(move || {
        let _ = io::copy(&mut a2, &mut b2);
        let _ = a2.shutdown(std::net::Shutdown::Both);
        let _ = b2.shutdown(std::net::Shutdown::Both);
    });
    let _ = io::copy(&mut b, &mut a);
    let _ = a.shutdown(std::net::Shutdown::Both);
    let _ = b.shutdown(std::net::Shutdown::Both);
    let _ = t.join();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One line, byte by byte, as the app reads it.
    fn line(s: &mut TcpStream) -> std::io::Result<String> {
        let mut out = Vec::new();
        let mut b = [0u8; 1];
        while out.len() < 256 {
            if s.read(&mut b)? == 0 {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            if b[0] == b'\n' {
                break;
            }
            out.push(b[0]);
        }
        Ok(String::from_utf8_lossy(&out).trim().to_string())
    }

    fn online(id: &str, relay: &str) -> Result<bool, String> {
        let mut s = TcpStream::connect(relay).map_err(|e| e.to_string())?;
        s.set_read_timeout(Some(Duration::from_secs(5))).ok();
        writeln!(s, "status {id}").map_err(|e| e.to_string())?;
        match line(&mut s).map_err(|e| e.to_string())?.as_str() {
            "online" => Ok(true),
            "offline" => Ok(false),
            other => Err(other.to_string()),
        }
    }

    /// The relay's side: an ID claimed by its token, its status, a viewer's call answered by a
    /// new connection, bytes both ways, and the ID refused to another token.
    #[test]
    fn the_relay_pairs_by_id() {
        let port = 20000 + (std::process::id() % 20000) as u16;
        let addr = format!("127.0.0.1:{port}");
        let a2 = addr.clone();
        thread::spawn(move || serve(&a2, None));
        thread::sleep(Duration::from_millis(300));
        let id = "987654321";
        let token = "0123456789abcdef0123";
        let mut agent = TcpStream::connect(&addr).unwrap();
        agent.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        writeln!(agent, "listen {id} {token}").unwrap();
        assert_eq!(line(&mut agent).unwrap(), "ok");
        assert!(online(id, &addr).unwrap(), "online once listening");
        assert!(!online("111222333", &addr).unwrap());
        // The same through a web server's HTTP upgrade, as port 80 brings it.
        let mut up = TcpStream::connect(&addr).unwrap();
        up.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        write!(up, "GET /relay HTTP/1.1\r\nHost: x\r\nUpgrade: sshremote-relay\r\nConnection: Upgrade\r\nX-Real-IP: 10.1.2.3\r\n\r\nstatus {id}\n").unwrap();
        assert!(line(&mut up).unwrap().contains(" 101"), "from a web server with its client's address");
        while !line(&mut up).unwrap().is_empty() {}
        assert_eq!(line(&mut up).unwrap(), "online");
        let mut thief = TcpStream::connect(&addr).unwrap();
        thief.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        writeln!(thief, "listen {id} ffffffffffffffffffff").unwrap();
        assert_eq!(line(&mut thief).unwrap(), "taken");
        let a3 = addr.clone();
        let viewer = thread::spawn(move || {
            let mut v = TcpStream::connect(&a3).unwrap();
            v.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            writeln!(v, "viewer {id}").unwrap();
            assert_eq!(line(&mut v).unwrap(), "ok");
            v.write_all(b"ping!").unwrap();
            let mut got = [0u8; 5];
            v.read_exact(&mut got).unwrap();
            got
        });
        let from = line(&mut agent).unwrap();
        let call = line(&mut agent).unwrap();
        let nonce = call.strip_prefix("call ").expect("a call").to_string();
        assert_eq!(from, format!("from {nonce} 127.0.0.1"), "where the viewer is, before its call");
        let mut a = TcpStream::connect(&addr).unwrap();
        a.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        writeln!(a, "accept {id} {nonce}").unwrap();
        assert_eq!(line(&mut a).unwrap(), "ok");
        let mut got = [0u8; 5];
        a.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"ping!");
        a.write_all(b"pong!").unwrap();
        assert_eq!(&viewer.join().unwrap(), b"pong!");
        // The retired one-off protocol is answered with nothing.
        let mut old = TcpStream::connect(&addr).unwrap();
        old.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        writeln!(old, "agent {id}").unwrap();
        assert!(line(&mut old).is_err());
        // Once its line ends the ID is offline again.
        drop(agent);
        thread::sleep(Duration::from_millis(600));
        assert!(!online(id, &addr).unwrap());
        // On UDP at the same port: where a socket is seen from, for a question at least as long
        // as the answer.
        let u = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        u.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut q = b"sshremote-addr 1 0123456789abcdef".to_vec();
        q.resize(96, b' ');
        u.send_to(&q, &addr).unwrap();
        let mut b = [0u8; 256];
        let (n, _) = u.recv_from(&mut b).unwrap();
        assert_eq!(String::from_utf8_lossy(&b[..n]), format!("sshremote-addr 1 0123456789abcdef {}", u.local_addr().unwrap()));
        assert_eq!(reflect_answer(b"sshremote-addr 1 0123456789abcdef", u.local_addr().unwrap()), None, "never larger");
    }
}
