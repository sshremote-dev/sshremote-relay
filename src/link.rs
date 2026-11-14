//! A computer's line to the relay, sealed: the computer says `secure E` (a fresh X25519 key),
//! the relay answers `secure E' S` (its own fresh key and its lasting one), and from then on each
//! side's words go in frames of ChaCha20-Poly1305 under keys drawn (HKDF-SHA256) from both
//! exchanges. Only the holder of S can read the computer's token or write the lines a computer
//! acts on (`from`, `call`); a computer that knows S (it keeps it from the first time, or ships
//! with the public relay's) sees through anyone in between. The same code is in the app.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use curve25519_dalek::montgomery::MontgomeryPoint;
use hkdf::Hkdf;
use sha2::Sha256;

/// The longest frame's words.
pub const MOST: usize = 16 << 10;

/// A key pair: the secret (kept here), and the public half to send.
pub fn keypair(secret: [u8; 32]) -> ([u8; 32], [u8; 32]) {
    (secret, MontgomeryPoint::mul_base_clamped(secret).to_bytes())
}

fn dh(secret: &[u8; 32], public: &[u8; 32]) -> Option<[u8; 32]> {
    let shared = MontgomeryPoint(*public).mul_clamped(*secret).to_bytes();
    // A point of small order makes it known to anyone: refused.
    (shared != [0; 32]).then_some(shared)
}

pub fn unhex(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// One direction's sealing: a key and the count of frames so far (each frame's nonce).
pub struct Way {
    aead: ChaCha20Poly1305,
    count: u64,
}

impl Way {
    fn new(key: &[u8]) -> Way {
        Way { aead: ChaCha20Poly1305::new(Key::from_slice(key)), count: 0 }
    }

    fn nonce(&mut self) -> Nonce {
        let mut n = [0u8; 12];
        n[..8].copy_from_slice(&self.count.to_le_bytes());
        self.count += 1;
        *Nonce::from_slice(&n)
    }

    /// `words` as a frame: its length (2 bytes), then them sealed.
    pub fn seal(&mut self, words: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for part in words.chunks(MOST).chain(words.is_empty().then_some(&[][..])) {
            let nonce = self.nonce();
            let sealed = self.aead.encrypt(&nonce, part).expect("sealing in memory");
            out.extend_from_slice(&(sealed.len() as u16).to_be_bytes());
            out.extend_from_slice(&sealed);
        }
        out
    }

    /// The next frame's words from the front of `raw`, once it is all there; an error for one
    /// that was not sealed by the other side (the line is then given up).
    pub fn open(&mut self, raw: &mut Vec<u8>) -> Result<Option<Vec<u8>>, ()> {
        if raw.len() < 2 {
            return Ok(None);
        }
        let len = u16::from_be_bytes([raw[0], raw[1]]) as usize;
        if len < 16 || len > MOST + 16 {
            return Err(());
        }
        if raw.len() < 2 + len {
            return Ok(None);
        }
        let frame: Vec<u8> = raw.drain(..2 + len).skip(2).collect();
        let nonce = self.nonce();
        self.aead.decrypt(&nonce, frame.as_slice()).map(Some).map_err(|_| ())
    }
}

/// Both directions of a sealed line.
pub struct Sealed {
    pub out: Way,
    pub inn: Way,
}

/// Keys from both exchanges: the computer's fresh key with the relay's lasting one, and with
/// its fresh one. `relay`: this side is the relay.
fn sealed(dh1: [u8; 32], dh2: [u8; 32], e_agent: &[u8; 32], e_relay: &[u8; 32], s_relay: &[u8; 32], relay: bool) -> Sealed {
    let hk = Hkdf::<Sha256>::new(Some(b"sshremote relay link 1"), &[dh1, dh2].concat());
    let mut okm = [0u8; 64];
    hk.expand(&[&e_agent[..], &e_relay[..], &s_relay[..]].concat(), &mut okm).expect("64 bytes");
    let (to_relay, to_agent) = okm.split_at(32);
    if relay {
        Sealed { out: Way::new(to_agent), inn: Way::new(to_relay) }
    } else {
        Sealed { out: Way::new(to_relay), inn: Way::new(to_agent) }
    }
}

/// The relay's side: the computer's fresh key `e_agent` and the relay's lasting pair; the line
/// to answer with, and the sealing.
pub fn answer(e_agent: &[u8; 32], lasting: &([u8; 32], [u8; 32]), fresh: [u8; 32]) -> Option<(String, Sealed)> {
    let (e_secret, e_relay) = keypair(fresh);
    let dh1 = dh(&lasting.0, e_agent)?;
    let dh2 = dh(&e_secret, e_agent)?;
    let line = format!("secure {} {}", hex(&e_relay), hex(&lasting.1));
    Some((line, sealed(dh1, dh2, e_agent, &e_relay, &lasting.1, true)))
}

/// The computer's side: its fresh pair and the relay's answer (its fresh and lasting keys).
pub fn finish(mine: &([u8; 32], [u8; 32]), e_relay: &[u8; 32], s_relay: &[u8; 32]) -> Option<Sealed> {
    let dh1 = dh(&mine.0, s_relay)?;
    let dh2 = dh(&mine.0, e_relay)?;
    Some(sealed(dh1, dh2, &mine.1, e_relay, s_relay, false))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_sides_seal_alike_and_a_forger_is_refused() {
        let lasting = keypair([7; 32]);
        let agent = keypair([9; 32]);
        let (line, mut relay) = answer(&agent.1, &lasting, [5; 32]).unwrap();
        let words: Vec<&str> = line.split(' ').collect();
        let (e_relay, s_relay) = (unhex(words[1]).unwrap(), unhex(words[2]).unwrap());
        assert_eq!(s_relay, lasting.1);
        let mut comp = finish(&agent, &e_relay, &s_relay).unwrap();
        // Several frames, in order, and a long one in parts.
        let mut raw = comp.out.seal(b"listen 123456 token");
        raw.extend(comp.out.seal(&vec![b'x'; MOST + 10]));
        assert_eq!(relay.inn.open(&mut raw).unwrap().unwrap(), b"listen 123456 token");
        assert_eq!(relay.inn.open(&mut raw).unwrap().unwrap().len(), MOST);
        assert_eq!(relay.inn.open(&mut raw).unwrap().unwrap().len(), 10);
        let mut back = relay.out.seal(b"ok\n");
        assert_eq!(comp.inn.open(&mut back).unwrap().unwrap(), b"ok\n");
        // Half a frame waits; a changed byte is refused.
        let mut part = relay.out.seal(b"ping\n");
        let rest = part.split_off(5);
        assert_eq!(comp.inn.open(&mut part).unwrap(), None);
        part.extend(rest);
        let n = part.len();
        part[n - 1] ^= 1;
        assert!(comp.inn.open(&mut part).is_err());
        // Someone else's lasting key: the computer's keys differ, nothing opens.
        let other = keypair([8; 32]);
        let mut fake = finish(&agent, &e_relay, &other.1).unwrap();
        let mut raw = fake.out.seal(b"listen");
        assert!(relay.inn.open(&mut raw).is_err());
        // A point of small order is refused.
        assert!(answer(&[0; 32], &lasting, [5; 32]).is_none());
    }
}
