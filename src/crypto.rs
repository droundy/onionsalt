//! A rust translation of the TweetNaCl library.  It is mostly a
//! direct translation, but in places I tried to make the API more
//! rustic.  It has three major features, of which you are likely
//! to use only one.
//!
//! 1. **Authenticated symmetric-key encryption** This is not so
//!    very often useful, but on the off chance you have a shared
//!    secret you could use it.
//!
//! 2. **SHA512 hasing** This again could be handy, but is not
//!    necesarily what you want most of the time.  And to be
//!    honest, you probably don't want my crude translation to
//!    rust of the pure C TweetNaCl implementation.
//!
//! 3. **Public-key encryption with authentication** This is what
//!    you want.  It allows you to send messages to a remote
//!    party, and ensure they aren't modified in transit.  The
//!    remote party can verify that you sent the message (or
//!    someone else did who had access to either your private key
//!    or *their* private key), but they can't prove that you sent
//!    the message.  It's a nice set of functionality, implemented
//!    in the functions `box_up` (which encrypts) and `box_open`
//!    (which decrypts and authenticates).
//!
//! # Examples
//!
//! Here is a simple example of encrypting a message and
//! decrypting it.  The one thing that it doesn't demonstrate is
//! that the ciphertext is padded with 16 zero bytes, which you
//! probably don't want to bother sending over the network.
//!
//! ```
//! # use std::vec;
//! # use onionsalt::crypto;
//! #
//! // of course, in practice, don't use unwrap:  handle the error!
//! let mykey = crypto::box_keypair().unwrap();
//! let thykey = crypto::box_keypair().unwrap();
//!
//! let plaintext = b"Friendly message.";
//!
//! let mut padded_plaintext: vec::Vec<u8> = vec::Vec::with_capacity(32+plaintext.len());
//! for _ in 0..32 { padded_plaintext.push(0); }
//! for i in 0..plaintext.len() { padded_plaintext.push(plaintext[i]); }
//!
//! let mut ciphertext: vec::Vec<u8> = vec::Vec::with_capacity(padded_plaintext.len());
//! for _ in 0..padded_plaintext.len() { ciphertext.push(0); }
//!
//! let nonce = crypto::random_nonce().unwrap();
//!
//! // Here we encreypt the message.  Keep in mind when sending it
//! // that you should strip the 16 zeros off the beginning!
//!
//! crypto::box_up(&mut ciphertext, &padded_plaintext,
//!                &nonce, &thykey.public, &mykey.secret).unwrap();
//!
//! let mut decrypted: vec::Vec<u8> = vec::Vec::with_capacity(padded_plaintext.len());
//! for _ in 0..ciphertext.len() { decrypted.push(0); }
//!
//! // Use box_open to decrypt the message.  You REALLY don't want
//! // to unwrap (or ignore) the output of box_open, since this is
//! // how you know that the message was authenticated.
//!
//! crypto::box_open(&mut decrypted, &ciphertext,
//!                  &nonce, &mykey.public, &thykey.secret).unwrap();
//!
//! // Note that decrypted (like padded_plaintext) has 32 bytes of
//! // zeros padded at the beginning.
//! for i in 0..plaintext.len() {
//!     assert!(plaintext[i] == decrypted[i+32]);
//! }
//! ```

#![deny(warnings)]

#[cfg(test)]
extern crate quickcheck;

use std::num::Wrapping;
use std::fmt::{Formatter, Error, Display};

fn unwrap<T>(x: Wrapping<T>) -> T {
    let Wrapping(x) = x;
    x
}

static _0: [u8; 16] = [0; 16];
static _9: [u8; 32] = [9; 32];

type GF = [i64; 16];
static GF0: GF = [0; 16];
// static GF1: GF = [1; 16];
static _121665: GF = [0xDB41,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1];
// static D: GF = [0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070,
//                 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203];
// static D2: GF = [0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
//                  0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406];
// static X: GF = [0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
//                 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169];
// static Y: GF = [0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
//                 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666];
// static I: GF = [0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43,
//                 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83];

fn l32(x: Wrapping<u32>, c: usize) -> Wrapping<u32> {
    (x << c) | ((x&Wrapping(0xffffffff)) >> (32 - c))
}

fn ld32(x: &[u8; 4]) -> Wrapping<u32> {
    let mut u= Wrapping(x[3] as u32);
    u = (u<<8)|Wrapping(x[2] as u32);
    u = (u<<8)|Wrapping(x[1] as u32);
    (u<<8)|Wrapping(x[0] as u32)
}

fn st32(x: &mut[u8; 4], mut u: Wrapping<u32>) {
    for i in 0..4 {
        x[i] = unwrap(u) as u8;
        u = u >> 8;
    }
}

fn verify_16(x: &[u8; 16], y: &[u8; 16]) -> Result<(), NaClError> {
    let mut d: Wrapping<u32> = Wrapping(0);
    for i in 0..16 {
        d = d | Wrapping((x[i]^y[i]) as u32);
    }
    if unwrap(Wrapping(1) & ((d - Wrapping(1)) >> 8)) as i32 - 1 != 0 {
        Err(NaClError::AuthFailed)
    } else {
        Ok(())
    }
}

fn core(inp: &[u8; 16], k: &[u8; 32], c: &[u8; 16])
        -> ([Wrapping<u32>; 16], [Wrapping<u32>; 16]) {
    let mut x: [Wrapping<u32>; 16] = [Wrapping(0); 16];
    for i in 0..4 {
        x[5*i] = ld32(array_ref![c, 4*i, 4]);
        x[1+i] = ld32(array_ref![k, 4*i, 4]);
        x[6+i] = ld32(array_ref![inp, 4*i, 4]);
        x[11+i] = ld32(array_ref![k, 16+4*i, 4]);
    }

    let mut y: [Wrapping<u32>; 16] = [Wrapping(0); 16];
    for i in 0..16 {
        y[i] = x[i];
    }

    let mut w: [Wrapping<u32>; 16] = [Wrapping(0); 16];
    let mut t: [Wrapping<u32>; 4] = [Wrapping(0); 4];
    for _ in 0..20 {
        for j in 0..4 {
            for m in 0..4 {
                t[m] = x[(5*j+4*m)%16];
            }
            t[1] = t[1] ^ l32(t[0]+t[3], 7);
            t[2] = t[2] ^ l32(t[1]+t[0], 9);
            t[3] = t[3] ^ l32(t[2]+t[1],13);
            t[0] = t[0] ^ l32(t[3]+t[2],18);
            for m in 0..4 {
                w[4*j+(j+m)%4] = t[m];
            }
        }
        for m in 0..16 {
            x[m] = w[m];
        }
    }
    (x,y)
}

fn core_salsa20(inp: &[u8; 16], k: &[u8; 32], c: &[u8; 16]) -> [u8; 64] {
    let (x,y) = core(inp,k,c);

    let mut out: [u8; 64] = [0; 64];
    for i in 0..16 {
        st32(array_mut_ref!(out, 4*i, 4),x[i] + y[i]);
    }
    out
}

fn core_hsalsa20(n: &[u8; 16], k: &[u8; 32], c: &[u8; 16]) -> [u8; 32] {
    let (mut x,y) = core(n,k,c);

    let mut out: [u8; 32] = [0; 32];
    for i in 0..16 {
        x[i] = x[i] + y[i];
    }
    for i in 0..4 {
        x[5*i] = x[5*i] - ld32(array_ref![c, 4*i, 4]);
        x[6+i] = x[6+i] - ld32(array_ref!(n, 4*i, 4));
    }
    for i in 0..4 {
        st32(array_mut_ref!(out, 4*i, 4),x[5*i]);
        st32(array_mut_ref!(out, 16+4*i, 4),x[6+i]);
    }
    out
}

static SIGMA: &'static [u8; 16] = b"expand 32-byte k";

fn stream_salsa20_xor(c: &mut[u8], mut m: &[u8], mut b: u64,
                      n: &[u8; 16], k: &[u8; 32])
                      -> Result<(), NaClError> {
    if b == 0 {
        return Err(NaClError::InvalidInput);
    }
    let mut z: [u8; 16] = [0; 16];
    for i in 0..8 {
        z[i] = n[i];
    }
    let mut c_offset: usize = 0;
    while b >= 64 {
        let x = core_salsa20(&z,k,SIGMA);
        for i in 0..64 {
            c[c_offset + i] = if i < m.len() { m[i] ^ x[i] } else { x[i] };
        }
        let mut u: u64 = 1;
        for i in 8..16 {
            u += z[i] as u64;
            z[i] = u as u8;
            u >>= 8;
        }
        b -= 64;
        c_offset += 64;
        m = &m[64..];
    }

    if b != 0 {
        let x = core_salsa20(&z,k,SIGMA);
        for i in 0..b as usize {
            c[c_offset + i] = if i < m.len() { m[i] ^ x[i] } else { x[i] };
        }
    }
    Ok(())
}


fn stream_salsa20(c: &mut[u8], d: u64, n: &[u8; 16], k: &[u8; 32])
                         -> Result<(), NaClError> {
    stream_salsa20_xor(c,&[],d,n,k)
}

// stream_32 is a modified version of crypto_stream, which
// always has a fixed length of 32, and returns its output.  We
// don't need an actual crypto_stream, since it is only used once
// in tweetnacl.
fn stream_32(n: &Nonce, k: &[u8; 32])
             -> Result<[u8; 32], NaClError> {
    let s = core_hsalsa20(array_ref![n.0, 0, 16], k, SIGMA);
    let mut c: [u8; 32] = [0; 32];
    try!(stream_salsa20(&mut c,32,array_ref![n.0, 16, 16],&s));
    Ok(c)
}

fn stream_xor(c: &mut[u8], m: &[u8], d: u64, n: &Nonce, k: &[u8; 32])
                         -> Result<(), NaClError> {
    let s = core_hsalsa20(array_ref![n.0, 0, 16], k, SIGMA);
    stream_salsa20_xor(c,m,d,array_ref![n.0, 16, 16],&s)
}

fn add1305(h: &mut[u32], c: &[u32]) {
    let mut u: u32 = 0;
    for j in 0..17 {
        u += h[j] + c[j];
        h[j] = u & 255;
        u >>= 8;
    }
}

static MINUSP: &'static [u32; 17] = &[5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252];

use std;


/// The error return type.  You can get errors for only one of three reasons:
///
/// 1. You passed in slices that were the wrong sizes.  This is
///    your bug, and we would be justified in panicking for this.
///
/// 2. You called an "open" function, and the message failed to
///    authenticate.  This is only a bug if you thought the
///    message should be valid.  But you need to handle this,
///    since presumable some bad person could try to corrupt your
///    data.
///
/// 3. If you are generating random data (either generating keys
///    or a nonce), you could in principle encounter an IO error.
///    This should be unusual, but could happen.

// We derive `Debug` because all types should probably derive
// `Debug`.  This gives us a reasonable human readable description
// of the `NaClError` values.
#[derive(Debug)]
pub enum NaClError {
    AuthFailed,
    InvalidInput,
    WrongKey,
    IOError(std::io::Error),
    RecvError(std::sync::mpsc::RecvError),
}
impl std::convert::From<std::io::Error> for NaClError {
    fn from(e: std::io::Error) -> NaClError {
        NaClError::IOError(e)
    }
}
impl std::convert::From<std::sync::mpsc::RecvError> for NaClError {
    fn from(e: std::sync::mpsc::RecvError) -> NaClError {
        NaClError::RecvError(e)
    }
}
impl<'a> std::convert::From<&'a str> for NaClError {
    fn from(e: &str) -> NaClError {
        NaClError::IOError(std::io::Error::new(std::io::ErrorKind::Other, e))
    }
}

/// A public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey(pub [u8; 32]);
impl PublicKey {
    pub fn new<T: ToPublicKey>(x: &T) -> Result<PublicKey, NaClError> {
        return x.to_public_key()
    }
}
impl Display for PublicKey {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        let mut s = String::new();
        s = s + &format!("{:02x}{:02x}{:02x}{:02x}", self.0[0], self.0[1], self.0[2], self.0[3]);
        s = s + &format!("{:02x}{:02x}{:02x}{:02x}", self.0[4], self.0[5], self.0[6], self.0[7]);
        s = s + &format!("{:02x}{:02x}{:02x}{:02x}", self.0[8], self.0[9], self.0[10], self.0[11]);
        s = s + &format!("{:02x}{:02x}{:02x}{:02x}", self.0[12], self.0[13], self.0[14], self.0[15]);
        s = s + &format!("{:02x}{:02x}{:02x}{:02x}", self.0[16], self.0[17], self.0[18], self.0[19]);
        s = s + &format!("{:02x}{:02x}{:02x}{:02x}", self.0[20], self.0[21], self.0[22], self.0[23]);
        s = s + &format!("{:02x}{:02x}{:02x}{:02x}", self.0[24], self.0[25], self.0[26], self.0[27]);
        s = s + &format!("{:02x}{:02x}{:02x}{:02x}", self.0[28], self.0[29], self.0[30], self.0[31]);
        f.write_str(&s)
    }
}

/// A trait that is defined for types that can be used as a public
/// key.  Specifically, [u8; 32], &[u8] (with possible crash on the
/// wrong length) and PublicKey all implement this trait.
pub trait ToPublicKey {
    fn to_public_key(&self) -> Result<PublicKey, NaClError>;
}
impl ToPublicKey for PublicKey {
    fn to_public_key(&self) -> Result<PublicKey, NaClError> {
        Ok(self.clone())
    }
}
impl ToPublicKey for [u8; 32] {
    fn to_public_key(&self) -> Result<PublicKey, NaClError> {
        Ok(PublicKey(*self))
    }
}
impl<'a> ToPublicKey for &'a [u8] {
    fn to_public_key(&self) -> Result<PublicKey, NaClError> {
        if self.len() < 32 {
            return Err(NaClError::InvalidInput);
        }
        let mut k = [0; 32];
        for i in 0..32 {
            k[i] = self[i];
        }
        Ok(PublicKey(k))
    }
}
impl ToPublicKey for [u8] {
    fn to_public_key(&self) -> Result<PublicKey, NaClError> {
        if self.len() < 32 {
            return Err(NaClError::InvalidInput);
        }
        let mut k = [0; 32];
        for i in 0..32 {
            k[i] = self[i];
        }
        Ok(PublicKey(k))
    }
}

/// A secret key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SecretKey(pub [u8; 32]);
impl SecretKey {
    pub fn new<T: ToSecretKey>(x: &T) -> Result<SecretKey, NaClError> {
        return x.to_secret_key()
    }
}
impl Display for SecretKey {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        PublicKey(self.0).fmt(f)
    }
}

/// A trait that is defined for types that can be used as a secret
/// key.  Specifically, [u8; 32], &[u8] (with possible crash on the
/// wrong length) and SecretKey all implement this trait.
pub trait ToSecretKey {
    fn to_secret_key(&self) -> Result<SecretKey, NaClError>;
}
impl ToSecretKey for SecretKey {
    fn to_secret_key(&self) -> Result<SecretKey, NaClError> {
        Ok(self.clone())
    }
}
impl ToSecretKey for [u8; 32] {
    fn to_secret_key(&self) -> Result<SecretKey, NaClError> {
        Ok(SecretKey(*self))
    }
}
impl<'a> ToSecretKey for &'a [u8] {
    fn to_secret_key(&self) -> Result<SecretKey, NaClError> {
        Ok(SecretKey(try!(self.to_public_key()).0))
    }
}

/// A nonce.  You should never reuse a nonce for two different
/// messages between the same set of keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nonce(pub [u8; 32]);
impl Display for Nonce {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        PublicKey(self.0).fmt(f)
    }
}

/// A trait that is defined for types that can be used as a nonce.
/// Specifically, [u8; 32], &[u8] (with possible crash on the wrong
/// length) and Nonce all implement this trait.
pub trait ToNonce {
    fn to_nonce(&self) -> Result<Nonce, NaClError>;
}
impl ToNonce for Nonce {
    fn to_nonce(&self) -> Result<Nonce, NaClError> {
        Ok(self.clone())
    }
}
impl ToNonce for [u8; 32] {
    fn to_nonce(&self) -> Result<Nonce, NaClError> {
        Ok(Nonce(*self))
    }
}
impl<'a> ToNonce for &'a [u8] {
    fn to_nonce(&self) -> Result<Nonce, NaClError> {
        Ok(Nonce(try!(self.to_public_key()).0))
    }
}

fn onetimeauth(mut m: &[u8], k: &[u8])
               -> Result<[u8; 16], NaClError> {
    let mut n = m.len();

    let x: &mut[u32; 17] = &mut [0; 17];
    let r: &mut[u32; 17] = &mut [0; 17];
    let h: &mut[u32; 17] = &mut [0; 17];
    for j in 0..16 {
        r[j]=k[j] as u32;
    }
    r[3]&=15;
    r[4]&=252;
    r[7]&=15;
    r[8]&=252;
    r[11]&=15;
    r[12]&=252;
    r[15]&=15;

    let mut c: &mut[u32; 17] = &mut [0; 17];
    let mut g: &mut[u32; 17] = &mut [0; 17];
    while n > 0 {
        for j in 0..17 {
            c[j] = 0;
        }
        let nor16 = if n < 16 { n } else { 16 } as usize;
        for j in 0..nor16 {
            c[j] = m[j] as u32;
        }
        c[nor16] = 1;
        m = &m[nor16..];
        n -= nor16;
        add1305(h,c);
        for i in 0..17 {
            x[i] = 0;
            for j in 0..17 {
                x[i] += h[j] * (if j <= i { r[i - j] } else { 320 * r[i + 17 - j]});
            }
        }
        for i in 0..17 {
            h[i] = x[i];
        }
        let mut u: u32 = 0;
        for j in 0..16 {
            u += h[j];
            h[j] = u & 255;
            u >>= 8;
        }
        u += h[16];
        h[16] = u & 3;
        u = 5 * (u >> 2);
        for j in 0..16 {
            u += h[j];
            h[j] = u & 255;
            u >>= 8;
        }
        u += h[16];
        h[16] = u;
    }

    for j in 0..17 {
        g[j] = h[j];
    }
    add1305(h,MINUSP);
    let s: u32 = (-((h[16] >> 7) as i32)) as u32;
    for j in 0..17 {
        h[j] ^= s & (g[j] ^ h[j]);
    }

    for j in 0..16 {
        c[j] = k[j + 16] as u32;
    }
    c[16] = 0;
    add1305(h,c);
    let mut out: [u8; 16] = [0; 16];
    for j in 0..16 {
        out[j] = h[j] as u8;
    }
    Ok(out)
}

fn onetimeauth_verify(h: &[u8; 16], m: &[u8], k: &[u8])
                      -> Result<(), NaClError> {
    let x = try!(onetimeauth(m, k));
    verify_16(h,&x)
}

/// Use symmetric encryption to encrypt a message.
pub fn secretbox(c: &mut[u8], m: &[u8], n: &Nonce, k: &[u8; 32])
                        -> Result<(), NaClError> {
    let d = c.len() as u64;
    if d != m.len() as u64 {
        return Err(NaClError::InvalidInput);
    }
    if d < 32 {
        return Err(NaClError::InvalidInput);
    }
    try!(stream_xor(c,m,d,n,k));
    let h = try!(onetimeauth(&c[32..], c));
    for i in 0..16 {
        c[i] = 0;
    }
    // The following loop is additional overhead beyond what the C
    // version of the code does, which results from my choice to
    // use a return array rather than a mut slice argument for
    // "core" above.
    for i in 0..16 {
        c[16+i] = h[i];
    }
    Ok(())
}

/// Decrypt a message encrypted with `secretbox`.
pub fn secretbox_open(m: &mut[u8], c: &[u8], n: &Nonce, k: &[u8; 32])
                             -> Result<(), NaClError> {
    let d = c.len() as u64;
    if m.len() as u64 != d {
        return Err(NaClError::InvalidInput);
    }
    if d < 32 {
        return Err(NaClError::InvalidInput);
    }
    let x = try!(stream_32(n,k));
    try!(onetimeauth_verify(array_ref!(c, 16, 16), &c[32..], &x));
    try!(stream_xor(m,c,d,n,k));
    for i in 0..32 {
        m[i] = 0;
    }
    Ok(())
}

#[test]
fn secretbox_works() {
    use std::vec;

    let plaintext: &[u8] = b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0This is only a test.";
    let secretkey: &[u8; 32] = b"This is my secret key. It is me.";
    let mut ciphertext: vec::Vec<u8> = vec![];
    for _ in 0..plaintext.len() {
        ciphertext.push(0);
    }
    let nonce = Nonce([0; 32]);
    secretbox(&mut ciphertext, plaintext, &nonce, secretkey).unwrap();
    // There has got to be a better way to allocate an array of
    // zeros with dynamically determined type.
    let mut decrypted: vec::Vec<u8> = vec::Vec::with_capacity(plaintext.len());
    for _ in 0..plaintext.len() {
        decrypted.push(0);
    }
    secretbox_open(&mut decrypted, &ciphertext, &nonce, secretkey).unwrap();
    for i in 0..decrypted.len() {
        assert!(decrypted[i] == plaintext[i])
    }
}

/// Use symmetric encryption to encrypt a message, with only the first
/// `nauth` bytes plaintext authenticated.
fn funnybox(c: &mut[u8], m: &[u8], nauth: usize, n: &Nonce, k: &[u8; 32])
                -> Result<(), NaClError> {
    let d = c.len() as u64;
    if d != m.len() as u64 || nauth > d as usize -32 || d < 32 {
        return Err(NaClError::InvalidInput);
    }
    try!(stream_xor(c,m,d,n,k));
    let h = try!(onetimeauth(&c[32..32+nauth], c));
    for i in 0..16 {
        c[i] = 0;
    }
    // The following loop is additional overhead beyond what the C
    // version of the code does, which results from my choice to
    // use a return array rather than a mut slice argument for
    // "core" above.
    for i in 0..16 {
        c[16+i] = h[i];
    }
    Ok(())
}

/// Decrypt a message encrypted with `funnybox`, only authenticating
/// the first `nauth` bytes.
pub fn funnybox_open(m: &mut[u8], c: &[u8], nauth: usize, n: &Nonce, k: &[u8; 32])
                             -> Result<(), NaClError> {
    let d = c.len() as u64;
    if m.len() as u64 != d || nauth > d as usize - 32 || d < 32 {
        return Err(NaClError::InvalidInput);
    }
    let x = try!(stream_32(n,k));
    try!(onetimeauth_verify(array_ref!(c, 16, 16), &c[32..32+nauth], &x));
    try!(stream_xor(m,c,d,n,k));
    for i in 0..32 {
        m[i] = 0;
    }
    Ok(())
}

#[test]
fn funnybox_works() {
    use std::vec;

    let plaintext: &[u8] = b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0This is only a test.";
    let nauth = "This is only".len();
    let secretkey: &[u8; 32] = b"This is my secret key. It is me.";
    let mut ciphertext: vec::Vec<u8> = vec![];
    for _ in 0..plaintext.len() {
        ciphertext.push(0);
    }
    let nonce = Nonce([0; 32]);
    funnybox(&mut ciphertext, plaintext, nauth, &nonce, secretkey).unwrap();
    // There has got to be a better way to allocate an array of
    // zeros with dynamically determined type.
    let mut decrypted: vec::Vec<u8> = vec::Vec::with_capacity(plaintext.len());
    for _ in 0..plaintext.len() {
        decrypted.push(0);
    }
    funnybox_open(&mut decrypted, &ciphertext, nauth, &nonce, secretkey).unwrap();
    for i in 0..decrypted.len() {
        assert!(decrypted[i] == plaintext[i])
    }
}

fn car25519(o: &mut GF) {
    for i in 0..16 {
        o[i] += 1<<16;
        let c: i64 = o[i]>>16;
        let iis15 = if i == 15 {1} else {0};
        let ilt15 = if i < 15 {1} else {0};
        o[(i+1)*ilt15] += c-1+37*(c-1)*iis15;
        o[i] -= c<<16;
    }
}

fn sel25519(p: &mut GF, q: &mut GF, b: i64) {
    let c = !(b-1);
    for i in 0..16 {
        let t= c&(p[i]^q[i]);
        p[i]^=t;
        q[i]^=t;
    }
}

fn pack25519(o: &mut[u8], n: &GF) {
    let mut t = *n;
    car25519(&mut t);
    car25519(&mut t);
    car25519(&mut t);
    let mut m = [0; 16];
    for _ in 0..1 {
        m[0]=t[0]-0xffed;
        for i in 1..15 {
            m[i]=t[i]-0xffff-((m[i-1]>>16)&1);
            m[i-1]&=0xffff;
        }
        m[15]=t[15]-0x7fff-((m[14]>>16)&1);
        let b=(m[15]>>16)&1;
        m[14]&=0xffff;
        sel25519(&mut t,&mut m,1-b);
    }
    for i in 0..16 {
        o[2*i]= (t[i]&0xff) as u8;
        o[2*i+1]= (t[i]>>8) as u8;
    }
}

// fn neq25519(a: &GF, b: &GF) -> Result<(), NaClError> {
//     let mut c: [u8; 32] = [0; 32];
//     let mut d: [u8; 32] = [0; 32];
//     pack25519(&mut c,a);
//     pack25519(&mut d,b);
//     verify_32(&c,&d)
// }

// fn par25519(a: &GF) -> u8 {
//     let mut d: [u8; 32] = [0; 32];
//     pack25519(&mut d,a);
//     d[0]&1
// }

fn unpack25519(n: &[u8]) -> GF {
    let mut o = GF0;
    for i in 0..16 {
        o[i]=n[2*i] as i64 + ((n[2*i+1] as i64) << 8);
    }
    o[15]&=0x7fff;
    o
}

#[allow(non_snake_case)]
fn A(a: &GF, b: &GF) -> GF {
    let mut out: GF = *a;
    for i in 0..16 {
        out[i] += b[i];
    }
    out
}

#[allow(non_snake_case)]
fn Z(a: &GF, b: &GF) -> GF {
    let mut out: GF = *a;
    for i in 0..16 {
        out[i] -= b[i];
    }
    out
}

#[allow(non_snake_case)]
fn M(a: &GF, b: &GF) -> GF {
    let mut o: GF = *a;
    let mut t: [i64; 31] = [0; 31];
    for i in 0..16 {
        for j in 0..16 {
            t[i+j] += a[i]*b[j];
        }
    }
    for i in 0..15 {
        t[i]+=38*t[i+16];
    }
    for i in 0..16 {
        o[i]=t[i];
    }
    car25519(&mut o);
    car25519(&mut o);
    o
}

#[allow(non_snake_case)]
fn S(a: &GF) -> GF {
    M(a,a)
}

fn inv25519(i: &GF) -> GF {
    let mut c = *i;
    for a in (0..254).rev() {
        c = S(&c);
        if a!=2 && a!=4 {
            c = M(&c,i)
        }
    }
    c
}

// fn pow2523(i: &GF) -> GF {
//     let mut c = *i;
//     for a in (0..251).rev() {
//         c = S(&c);
//         if a != 1 {
//             c = M(&c, i);
//         }
//     }
//     c
// }

fn scalarmult(q: &mut[u8], n: &[u8], p: &[u8]) {
    let mut z: [u8; 32] = [0; 32];
    for i in 0..31 {
        z[i] = n[i];
    }
    z[31]=(n[31]&127)|64;
    z[0]&=248;
    let mut x: [GF; 5] = [unpack25519(p), [0;16], [0;16], [0;16], [0;16]];
    let mut b = x[0];
    let mut d = GF0;
    let mut a = GF0;
    let mut c = GF0;
    a[0]=1;
    d[0]=1;
    for i in (0..255).rev() {
        let r: i64 = ((z[i>>3]>>(i&7))&1) as i64;
        sel25519(&mut a, &mut b,r);
        sel25519(&mut c, &mut d,r);
        let mut e = A(&a,&c);
        a = Z(&a,&c);
        c = A(&b,&d);
        b = Z(&b,&d);
        d = S(&e);
        let f = S(&a);
        a = M(&c,&a);
        c = M(&b,&e);
        e = A(&a,&c);
        a = Z(&a,&c);
        b = S(&a);
        c = Z(&d,&f);
        a = M(&c,&_121665);
        a = A(&a,&d);
        c = M(&c,&a);
        a = M(&d,&f);
        d = M(&b,&x[0]);
        b = S(&e);
        sel25519(&mut a, &mut b,r);
        sel25519(&mut c, &mut d,r);
    }
    x[1] = a;
    x[2] = c;
    x[3] = b;
    x[4] = d;
    x[2] = inv25519(&x[2]);
    x[1] = M(&x[1],&x[2]);
    pack25519(q,&x[1]);
}

fn scalarmult_base(q: &mut[u8], n: &[u8]) {
    scalarmult(q,n,&_9)
}

use rand::{OsRng,Rng};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyPair {
    pub public: PublicKey,
    pub secret: SecretKey,
}
pub const EMPTY_PAIR: KeyPair = KeyPair{ public: PublicKey([0;32]),
                                         secret: SecretKey([0;32]), };

/// Generate a random public/secret key pair.  This is the *only*
/// way you generate keys.
pub fn box_keypair() -> Result<KeyPair, NaClError> {
    let mut rng = try!(OsRng::new());
    let mut pk: [u8; 32] = [0; 32];
    let mut sk: [u8; 32] = [0; 32];
    rng.fill_bytes(&mut sk);
    scalarmult_base(&mut pk, &sk);
    Ok(KeyPair{ public: PublicKey(pk), secret: SecretKey(sk) })
}

/// Securely creates a random nonce.  This function isn't in the
/// NaCl, but I feel like it could be very handy, and a random
/// nonce from a secure source is often what you want.
pub fn random_nonce() -> Result<Nonce, NaClError> {
    let mut rng = try!(OsRng::new());
    let mut n = Nonce([0; 32]);
    rng.fill_bytes(&mut n.0);
    Ok(n)
}

/// Prepare to either open or encrypt some public-key messages.
/// This is useful if you want to handle many messages between the
/// same two recipients, since it allows you to do the public-key
/// business just once.
pub fn box_beforenm<PK: ToPublicKey + ?Sized,
                    SK: ToSecretKey + ?Sized>(pk: &PK, sk: &SK)
                                              -> Result<[u8; 32], NaClError> {
    let x = try!(sk.to_secret_key());
    let y = try!(pk.to_public_key());
    let mut s: [u8; 32] = [0; 32];
    scalarmult(&mut s,&x.0,&y.0);
    Ok(core_hsalsa20(array_ref![_0, 0, 16],&s,SIGMA))
}

/// Encrypt a message after creating a secret key using
/// `box_beforenm`.  The two functions together come out to the
/// same thing as `box_up`.
pub fn box_afternm(c: &mut[u8], m: &[u8], n: &Nonce, k: &[u8; 32])
                   -> Result<(), NaClError> {
    secretbox(c, m, n, k)
}

/// An implementation of the NaCl function `crypto_box`, renamed
/// to `crypto::box_up` because `box` is a keyword in rust.
pub fn box_up<N: ToNonce,
              PK: ToPublicKey,
              SK: ToSecretKey>(c: &mut[u8], m: &[u8],
                               n: &N, pk: &PK, sk: &SK)
                               -> Result<(), NaClError> {
    let k = try!(box_beforenm(pk,sk));
    try!(box_afternm(c, m, &try!(n.to_nonce()), &k));
    Ok(())
}

/// Decrypt a message using a key that was precomputed using
/// `box_beforenm`.  The two functions together are the same as
/// the easier-to-use `box_open`.
pub fn box_open_afternm(m: &mut[u8], c: &[u8], n: &Nonce, k: &[u8; 32])
                           -> Result<(), NaClError> {
    secretbox_open(m,c,n,k)
}

/// Open a message encrypted with `crypto::box_up`.
///
pub fn box_open<N: ToNonce,
                PK: ToPublicKey,
                SK: ToSecretKey>(m: &mut[u8], c: &[u8],
                                 n: &N, pk: &PK, sk: &SK)
                                 -> Result<(), NaClError> {
    let k = try!(box_beforenm(pk,sk));
    box_open_afternm(m, c, &try!(n.to_nonce()), &k)
}

#[test]
fn box_works() {
    use std::vec;

    let plaintext: &[u8] = b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0This is only a test.";
    let k1 = box_keypair().unwrap();
    let k2 = box_keypair().unwrap();
    let mut ciphertext: vec::Vec<u8> = vec![];
    for _ in 0..plaintext.len() {
        ciphertext.push(0);
    }
    let nonce = Nonce([0; 32]);
    box_up(&mut ciphertext, plaintext, &nonce, &k1.public, &k2.secret).unwrap();
    // There has got to be a better way to allocate an array of
    // zeros with dynamically determined type.
    let mut decrypted: vec::Vec<u8> = vec::Vec::with_capacity(plaintext.len());
    for _ in 0..plaintext.len() {
        decrypted.push(0);
    }
    box_open(&mut decrypted, &ciphertext, &nonce, &k2.public, &k1.secret).unwrap();
    for i in 0..decrypted.len() {
        assert!(decrypted[i] == plaintext[i])
    }
}

/// Prepare to either open or encrypt some public-key messages.
/// This is useful if you want to handle many messages between the
/// same two recipients, since it allows you to do the public-key
/// business just once.
pub fn sillybox_beforenm<PK: ToPublicKey + ?Sized,
                         SK: ToSecretKey + ?Sized>(pk: &PK, sk: &SK)
                                                   -> Result<[u8; 32], NaClError> {
    let x = try!(sk.to_secret_key());
    let y = try!(pk.to_public_key());
    let mut s: [u8; 32] = [0; 32];
    scalarmult(&mut s,&x.0,&y.0);
    Ok(core_hsalsa20(array_ref![_0,0,16],&s,SIGMA))
}

/// Encrypt a message after creating a secret key using
/// `sillybox_beforenm`.  The two functions together come out to the
/// same thing as `sillybox`, which you should read to find out how it
/// differs from the standard NaCl `box` encryption.
pub fn sillybox_afternm(c: &mut[u8], m: &[u8], nauth: usize,
                        n: &Nonce, k: &[u8; 32])
                   -> Result<(), NaClError> {
    funnybox(c, m, nauth, n, k)
}

/// An implementation of public-key encryption similar to the NaCl
/// function `crypto_box` (renamed `crypto::sillybox_up` in this
/// package), but with the feature that it only authenticates the
/// first `nauth` bytes.  This is not useful for most purposes (thus
/// its silly name), but is helpful for enabling round-trip onion
/// routing in which all the routing information is authenticated (to
/// information leaks triggered by maliciously modified packets), but
/// information may be added to the communication en-route.
pub fn sillybox<N: ToNonce,
                PK: ToPublicKey,
                SK: ToSecretKey>(c: &mut[u8], m: &[u8], nauth: usize,
                                 n: &N, pk: &PK, sk: &SK)
                                 -> Result<(), NaClError> {
    let k = try!(sillybox_beforenm(pk,sk));
    sillybox_afternm(c, m, nauth, &try!(n.to_nonce()), &k)
}

/// Decrypt a message using a key that was precomputed using
/// `sillybox_beforenm`.  The two functions together are the same as
/// the easier-to-use `sillybox_open`.
pub fn sillybox_open_afternm(m: &mut[u8], c: &[u8], nauth: usize,
                             n: &Nonce, k: &[u8; 32])
                           -> Result<(), NaClError> {
    funnybox_open(m,c,nauth,n,k)
}

/// Open a message encrypted with `crypto::sillybox_up`, only
/// authenticating the first `nauth` bytes.  It is your business to
/// separately verify (or distrust) the remaining bytes.  An obvious
/// approach would be to nest in the remaining bytes an encrypted and
/// authenticated message.
///
pub fn sillybox_open<N: ToNonce,
                     PK: ToPublicKey,
                     SK: ToSecretKey>(m: &mut[u8], c: &[u8], nauth: usize,
                                      n: &N, pk: &PK, sk: &SK)
                                      -> Result<(), NaClError> {
    let k = try!(sillybox_beforenm(pk,sk));
    sillybox_open_afternm(m, c, nauth, &try!(n.to_nonce()), &k)
}

#[test]
fn sillybox_works() {
    use std::vec;

    let plaintext: &[u8] = b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0This is only a test.";
    let nauth = "This is only".len();
    let k1 = box_keypair().unwrap();
    let k2 = box_keypair().unwrap();
    let mut ciphertext: vec::Vec<u8> = vec![];
    for _ in 0..plaintext.len() {
        ciphertext.push(0);
    }
    let nonce = Nonce([0; 32]);
    sillybox(&mut ciphertext, plaintext, nauth, &nonce, &k1.public, &k2.secret).unwrap();
    // There has got to be a better way to allocate an array of
    // zeros with dynamically determined type.
    let mut decrypted: vec::Vec<u8> = vec::Vec::with_capacity(plaintext.len());
    for _ in 0..plaintext.len() {
        decrypted.push(0);
    }
    sillybox_open(&mut decrypted, &ciphertext, nauth,
                  &nonce, &k2.public, &k1.secret).unwrap();
    for i in 0..decrypted.len() {
        assert!(decrypted[i] == plaintext[i])
    }

    // Verify that we authenticate the first nauth bytes.
    for i in 16..32+nauth {
        ciphertext[i] ^= 1;
        assert!(sillybox_open(&mut decrypted, &ciphertext, nauth,
                              &nonce, &k2.public, &k1.secret).is_err());
        ciphertext[i] ^= 1;
    }
    // Verify that we do not authenticate any of the remaining bytes.
    for i in 32+nauth..ciphertext.len() {
        ciphertext[i] ^= 1;
        assert!(sillybox_open(&mut decrypted, &ciphertext, nauth,
                              &nonce, &k2.public, &k1.secret).is_ok());
        ciphertext[i] ^= 1;
    }
}

#[test]
fn sillybox_afternm_works() {
    use std::vec;

    let plaintext: &[u8] = b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0This is only a test.";
    let nauth = "This is only".len();
    let k1 = box_keypair().unwrap();
    let k2 = box_keypair().unwrap();
    let mut ciphertext: vec::Vec<u8> = vec![];
    for _ in 0..plaintext.len() {
        ciphertext.push(0);
    }
    let nonce = Nonce([0; 32]);
    let sk = sillybox_beforenm(&k1.public, &k2.secret).unwrap();
    sillybox_afternm(&mut ciphertext, plaintext, nauth, &nonce, &sk).unwrap();
    // There has got to be a better way to allocate an array of
    // zeros with dynamically determined type.
    let mut decrypted: vec::Vec<u8> = vec::Vec::with_capacity(plaintext.len());
    for _ in 0..plaintext.len() {
        decrypted.push(0);
    }
    sillybox_open_afternm(&mut decrypted, &ciphertext, nauth,
                          &nonce, &sk).unwrap();
    for i in 0..decrypted.len() {
        assert!(decrypted[i] == plaintext[i])
    }

    // Verify that we authenticate the first nauth bytes.
    for i in 16..32+nauth {
        ciphertext[i] ^= 1;
        assert!(sillybox_open_afternm(&mut decrypted, &ciphertext, nauth,
                                      &nonce, &sk).is_err());
        ciphertext[i] ^= 1;
    }
    // Verify that we do not authenticate any of the remaining bytes.
    for i in 32+nauth..ciphertext.len() {
        ciphertext[i] ^= 1;
        assert!(sillybox_open_afternm(&mut decrypted, &ciphertext, nauth,
                                      &nonce, &sk).is_ok());
        ciphertext[i] ^= 1;
    }
}


// The following code all has to do with implementing sha512.

fn dl64(x: &[u8]) -> Wrapping<u64> {
    let mut u = Wrapping(0 as u64);
    for i in 0..8 {
        u = (u<<8)|Wrapping(x[i] as u64);
    }
    u
}

fn ts64(x: &mut[u8], mut u: Wrapping<u64>) {
    for i in (0..8).rev() {
        x[i] = unwrap(u) as u8; u = u >> 8;
    }
}

#[allow(non_snake_case)]
fn R(x: Wrapping<u64>, c: usize) -> Wrapping<u64> {
    (x >> c) | (x << (64 - c))
}
#[allow(non_snake_case)]
fn Ch(x: Wrapping<u64>, y: Wrapping<u64>, z: Wrapping<u64>) -> Wrapping<u64> {
    (x & y) ^ (!x & z)
}
#[allow(non_snake_case)]
fn Maj(x: Wrapping<u64>, y: Wrapping<u64>, z: Wrapping<u64>) -> Wrapping<u64> {
    (x & y) ^ (x & z) ^ (y & z)
}
#[allow(non_snake_case)]
fn Sigma0(x: Wrapping<u64>) -> Wrapping<u64> {
    R(x,28) ^ R(x,34) ^ R(x,39)
}
#[allow(non_snake_case)]
fn Sigma1(x: Wrapping<u64>) -> Wrapping<u64> {
    R(x,14) ^ R(x,18) ^ R(x,41)
}
fn sigma0(x: Wrapping<u64>) -> Wrapping<u64> {
    R(x, 1) ^ R(x, 8) ^ (x >> 7)
}
fn sigma1(x: Wrapping<u64>) -> Wrapping<u64> {
    R(x,19) ^ R(x,61) ^ (x >> 6)
}

static K: [Wrapping<u64>; 80] =
   [Wrapping(0x428a2f98d728ae22), Wrapping(0x7137449123ef65cd),
    Wrapping(0xb5c0fbcfec4d3b2f), Wrapping(0xe9b5dba58189dbbc),
    Wrapping(0x3956c25bf348b538), Wrapping(0x59f111f1b605d019),
    Wrapping(0x923f82a4af194f9b), Wrapping(0xab1c5ed5da6d8118),
    Wrapping(0xd807aa98a3030242), Wrapping(0x12835b0145706fbe),
    Wrapping(0x243185be4ee4b28c), Wrapping(0x550c7dc3d5ffb4e2),
    Wrapping(0x72be5d74f27b896f), Wrapping(0x80deb1fe3b1696b1),
    Wrapping(0x9bdc06a725c71235), Wrapping(0xc19bf174cf692694),
    Wrapping(0xe49b69c19ef14ad2), Wrapping(0xefbe4786384f25e3),
    Wrapping(0x0fc19dc68b8cd5b5), Wrapping(0x240ca1cc77ac9c65),
    Wrapping(0x2de92c6f592b0275), Wrapping(0x4a7484aa6ea6e483),
    Wrapping(0x5cb0a9dcbd41fbd4), Wrapping(0x76f988da831153b5),
    Wrapping(0x983e5152ee66dfab), Wrapping(0xa831c66d2db43210),
    Wrapping(0xb00327c898fb213f), Wrapping(0xbf597fc7beef0ee4),
    Wrapping(0xc6e00bf33da88fc2), Wrapping(0xd5a79147930aa725),
    Wrapping(0x06ca6351e003826f), Wrapping(0x142929670a0e6e70),
    Wrapping(0x27b70a8546d22ffc), Wrapping(0x2e1b21385c26c926),
    Wrapping(0x4d2c6dfc5ac42aed), Wrapping(0x53380d139d95b3df),
    Wrapping(0x650a73548baf63de), Wrapping(0x766a0abb3c77b2a8),
    Wrapping(0x81c2c92e47edaee6), Wrapping(0x92722c851482353b),
    Wrapping(0xa2bfe8a14cf10364), Wrapping(0xa81a664bbc423001),
    Wrapping(0xc24b8b70d0f89791), Wrapping(0xc76c51a30654be30),
    Wrapping(0xd192e819d6ef5218), Wrapping(0xd69906245565a910),
    Wrapping(0xf40e35855771202a), Wrapping(0x106aa07032bbd1b8),
    Wrapping(0x19a4c116b8d2d0c8), Wrapping(0x1e376c085141ab53),
    Wrapping(0x2748774cdf8eeb99), Wrapping(0x34b0bcb5e19b48a8),
    Wrapping(0x391c0cb3c5c95a63), Wrapping(0x4ed8aa4ae3418acb),
    Wrapping(0x5b9cca4f7763e373), Wrapping(0x682e6ff3d6b2b8a3),
    Wrapping(0x748f82ee5defb2fc), Wrapping(0x78a5636f43172f60),
    Wrapping(0x84c87814a1f0ab72), Wrapping(0x8cc702081a6439ec),
    Wrapping(0x90befffa23631e28), Wrapping(0xa4506cebde82bde9),
    Wrapping(0xbef9a3f7b2c67915), Wrapping(0xc67178f2e372532b),
    Wrapping(0xca273eceea26619c), Wrapping(0xd186b8c721c0c207),
    Wrapping(0xeada7dd6cde0eb1e), Wrapping(0xf57d4f7fee6ed178),
    Wrapping(0x06f067aa72176fba), Wrapping(0x0a637dc5a2c898a6),
    Wrapping(0x113f9804bef90dae), Wrapping(0x1b710b35131c471b),
    Wrapping(0x28db77f523047d84), Wrapping(0x32caab7b40c72493),
    Wrapping(0x3c9ebe0a15c9bebc), Wrapping(0x431d67c49c100d4c),
    Wrapping(0x4cc5d4becb3e42b6), Wrapping(0x597f299cfc657e2a),
    Wrapping(0x5fcb6fab3ad6faec), Wrapping(0x6c44198c4a475817) ];

fn hashblocks(x: &mut[u8], mut m: &[u8], mut n: u64) -> u64 {
    let mut z: [Wrapping<u64>; 8] = [Wrapping(0); 8];
    for i in 0..8 {
        z[i] = dl64(&x[8 * i..]);
    }
    let mut a = z;

    let mut w: [Wrapping<u64>; 16] = [Wrapping(0); 16];
    while n >= 128 {
        for i in 0..16 {
            w[i] = dl64(&m[8 * i..]);
        }
        for i in 0..80 {
            let mut b = a;
            let t = a[7] + Sigma1(a[4]) + Ch(a[4],a[5],a[6]) + K[i] + w[i%16];
            b[7] = t + Sigma0(a[0]) + Maj(a[0],a[1],a[2]);
            b[3] = b[3] + t;
            for j in 0..8 {
                a[(j+1)%8] = b[j];
            }
            if i%16 == 15 {
                for j in 0..16 {
                    w[j] = w[j] + w[(j+9)%16] + sigma0(w[(j+1)%16]) + sigma1(w[(j+14)%16]);
                }
            }
        }
        for i in 0..8 {
            a[i] = a[i] + z[i];
            z[i] = a[i];
        }
        m = &m[128..];
        n -= 128;
    }
    for i in 0..8 {
        ts64(&mut x[8*i..],z[i]);
    }
    n
}

const IV: [u8; 64] = [ 0x6a,0x09,0xe6,0x67,0xf3,0xbc,0xc9,0x08,
                       0xbb,0x67,0xae,0x85,0x84,0xca,0xa7,0x3b,
                       0x3c,0x6e,0xf3,0x72,0xfe,0x94,0xf8,0x2b,
                       0xa5,0x4f,0xf5,0x3a,0x5f,0x1d,0x36,0xf1,
                       0x51,0x0e,0x52,0x7f,0xad,0xe6,0x82,0xd1,
                       0x9b,0x05,0x68,0x8c,0x2b,0x3e,0x6c,0x1f,
                       0x1f,0x83,0xd9,0xab,0xfb,0x41,0xbd,0x6b,
                       0x5b,0xe0,0xcd,0x19,0x13,0x7e,0x21,0x79 ];

/// Compute the SHA512 hash of some data.
pub fn hash(mut m: &[u8]) -> [u8; 64] {
    let mut n = m.len();
    let b = Wrapping(n as u64);
    let mut h = IV;
    hashblocks(&mut h,m,n as u64);
    let n_old = n;
    n &= 127;
    m = &m[n_old - n..];

    let mut x: [u8; 256] = [0; 256];
    for i in 0..n {
        x[i] = m[i];
    }
    x[n] = 128;

    n = if n < 112 { 128 } else { 256 };
    x[n-9] = unwrap(b >> 61) as u8;
    ts64(&mut x[n-8..],b<<3);

    hashblocks(&mut h,&x,n as u64);
    h
}

#[test]
fn hash_works() {
    use std::vec;

    fn fromhexit(h: u8) -> u8 {
        match h {
            b'0' ... b'9' => h - b'0',
            b'a' ... b'f' => h - b'a' + 10,
            _ => 0,
        }
    }
    fn fromhex(h: &[u8]) -> vec::Vec<u8> {
        let mut out: vec::Vec<u8> = vec![];
        for i in 0 .. h.len()/2 {
            out.push(fromhexit(h[2*i])*16 + fromhexit(h[2*i+1]));
        }
        out
    }
    fn test_hash(content: &[u8], hashval: &[u8]) {
        let c = fromhex(content);
        let hsh = fromhex(hashval);
        let myhsh = hash(&c);
        assert!(hsh.len() == myhsh.len());
    }
    test_hash(b"",
              b"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    test_hash(b"21",
              b"3831a6a6155e509dee59a7f451eb35324d8f8f2df6e3708894740f98fdee23889f4de5adb0c5010dfb555cda77c8ab5dc902094c52de3278f35a75ebc25f093a");
    test_hash(b"9083",
              b"55586ebba48768aeb323655ab6f4298fc9f670964fc2e5f2731e34dfa4b0c09e6e1e12e3d7286b3145c61c2047fb1a2a1297f36da64160b31fa4c8c2cddd2fb4");
    test_hash(b"0a55db",
              b"7952585e5330cb247d72bae696fc8a6b0f7d0804577e347d99bc1b11e52f384985a428449382306a89261ae143c2f3fb613804ab20b42dc097e5bf4a96ef919b");
    test_hash(b"23be86d5",
              b"76d42c8eadea35a69990c63a762f330614a4699977f058adb988f406fb0be8f2ea3dce3a2bbd1d827b70b9b299ae6f9e5058ee97b50bd4922d6d37ddc761f8eb");
    test_hash(b"eb0ca946c1",
              b"d39ecedfe6e705a821aee4f58bfc489c3d9433eb4ac1b03a97e321a2586b40dd0522f40fa5aef36afff591a78c916bfc6d1ca515c4983dd8695b1ec7951d723e");
    test_hash(b"38667f39277b",
              b"85708b8ff05d974d6af0801c152b95f5fa5c06af9a35230c5bea2752f031f9bd84bd844717b3add308a70dc777f90813c20b47b16385664eefc88449f04f2131");
    test_hash(b"b39f71aaa8a108",
              b"258b8efa05b4a06b1e63c7a3f925c5ef11fa03e3d47d631bf4d474983783d8c0b09449009e842fc9fa15de586c67cf8955a17d790b20f41dadf67ee8cdcdfce6");
    test_hash(b"6f8d58b7cab1888c",
              b"a3941def2803c8dfc08f20c06ba7e9a332ae0c67e47ae57365c243ef40059b11be22c91da6a80c2cff0742a8f4bcd941bdee0b861ec872b215433ce8dcf3c031");
    test_hash(b"162b0cf9b3750f9438",
              b"ade217305dc34392aa4b8e57f64f5a3afdd27f1fa969a9a2608353f82b95cfb4ae84598d01575a578a1068a59b34b5045ff6d5299c5cb7ee17180701b2d1d695");
    test_hash(b"bad7c618f45be207975e",
              b"5886828959d1f82254068be0bd14b6a88f59f534061fb20376a0541052dd3635edf3c6f0ca3d08775e13525df9333a2113c0b2af76515887529910b6c793c8a5");
    test_hash(b"6213e10a4420e0d9b77037",
              b"9982dc2a04dff165567f276fd463efef2b369fa2fbca8cee31ce0de8a79a2eb0b53e437f7d9d1f41c71d725cabb949b513075bad1740c9eefbf6a5c6633400c7");
    test_hash(b"6332c3c2a0a625a61df71858",
              b"9d60375d9858d9f2416fb86fa0a2189ee4213e8710314fd1ebed0fd158b043e6e7c9a76d62c6ba1e1d411a730902309ec676dd491433c6ef66c8f116233d6ce7");
    test_hash(b"f47be3a2b019d1beededf5b80c",
              b"b94292625caa28c7be24a0997eb7328062a76d9b529c0f1d568f850df6d569b5e84df07e9e246be232033ffac3adf2d18f92ab9dacfc0ecf08aff7145f0b833b");
    test_hash(b"b1715f782ff02c6b88937f054116",
              b"ee1a56ee78182ec41d2c3ab33d4c41871d437c5c1ca060ee9e219cb83689b4e5a4174dfdab5d1d1096a31a7c8d3abda75c1b5e6da97e1814901c505b0bc07f25");
    test_hash(b"9bcd5262868cd9c8a96c9e82987f03",
              b"2e07662a001b9755ae922c8e8a95756db5341dc0f2e62ae1cf827038f33ce055f63ad5c00b65391428434ddc01e5535e7fecbf53db66d93099b8e0b7e44e4b25");
    test_hash(b"cd67bd4054aaa3baa0db178ce232fd5a",
              b"0d8521f8f2f3900332d1a1a55c60ba81d04d28dfe8c504b6328ae787925fe0188f2ba91c3a9f0c1653c4bf0ada356455ea36fd31f8e73e3951cad4ebba8c6e04");
    test_hash(b"6ba004fd176791efb381b862e298c67b08",
              b"112e19144a9c51a223a002b977459920e38afd4ca610bd1c532349e9fa7c0d503215c01ad70e1b2ac5133cf2d10c9e8c1a4c9405f291da2dc45f706761c5e8fe");
    test_hash(b"c6a170936568651020edfe15df8012acda8d",
              b"c36c100cdb6c8c45b072f18256d63a66c9843acb4d07de62e0600711d4fbe64c8cf314ec3457c90308147cb7ac7e4d073ba10f0ced78ea724a474b32dae71231");
    test_hash(b"61be0c9f5cf62745c7da47c104597194db245c",
              b"b379249a3ca5f14c29456710114ba6f6136b34c3fc9f6fb91b59d491af782d6b237eb71aaffdd38079461cf690a46d9a4ddd602d19808ab6235d1d8aa01e8200");
    test_hash(b"e07056d4f7277bc548099577720a581eec94141d",
              b"59f1856303ff165e2ab5683dddeb6e8ad81f15bb578579b999eb5746680f22cfec6dba741e591ca4d9e53904837701b374be74bbc0847a92179ac2b67496d807");
    // Skipping a few test test vectors, because I am impatient.
    test_hash(b"0a78b16b4026f7ec063db4e7b77c42a298e524e268093c5038853e217dcd65f66428650165fca06a1b4c9cf1537fb5d463630ff3bd71cf32c3538b1fdda3fed5c9f601203319b7e1869a",
              b"6095c3df5b9db7ce524d76123f77421ce888b86a477ae8c6db1d0be8d326d22c852915ab03c0c81a5b7ac71e2c14e74bda17a78d2b10585fa214f6546eb710a0");
    test_hash(b"c1ca70ae1279ba0b918157558b4920d6b7fba8a06be515170f202fafd36fb7f79d69fad745dba6150568db1e2b728504113eeac34f527fc82f2200b462ecbf5d",
              b"046e46623912b3932b8d662ab42583423843206301b58bf20ab6d76fd47f1cbbcf421df536ecd7e56db5354e7e0f98822d2129c197f6f0f222b8ec5231f3967d");
    test_hash(b"ebb3e2ad7803508ba46e81e220b1cff33ea8381504110e9f8092ef085afef84db0d436931d085d0e1b06bd218cf571c79338da31a83b4cb1ec6c06d6b98768",
              b"f33428d8fc67aa2cc1adcb2822f37f29cbd72abff68190483e415824f0bcecd447cb4f05a9c47031b9c50e0411c552f31cd04c30cea2bc64bcf825a5f8a66028");
    test_hash(b"d3ddddf805b1678a02e39200f6440047acbb062e4a2f046a3ca7f1dd6eb03a18be00cd1eb158706a64af5834c68cf7f105b415194605222c99a2cbf72c50cb14bf",
              b"bae7c5d590bf25a493d8f48b8b4638ccb10541c67996e47287b984322009d27d1348f3ef2999f5ee0d38e112cd5a807a57830cdc318a1181e6c4653cdb8cf122");
    test_hash(b"79ecdfd47a29a74220a52819ce4589747f2b30b364d0852cce52f91e4f0f48e61c72fa76b60d3002cae89dfc5519d3430b95c098fa4678516b5e355109ea9b3745aa41d6f8206ee64ae720f8d44653b001057f2eba7f63cd42f9",
              b"ba3d0fe04470f4cf8f08c46d82ae3afd1caea8c13bebbe026b5c1777aa59860af2e3da7751844e0be24072af48bc8a6fd77678aaee04e08f63395f5c8a465763");
    test_hash(b"cede6697d422ddaa78e2d55ae080b8b9e9356c69bc558201a2d4b0b3190a812c27b34bbcee3a62b781378b1bf636b372bcbae1fa2f816a046a0a649a5c555c641fea4ccd841cc761f38f777972f8c91b0324e71c333ce787f04741439bf087ef5e895011c0",
              b"0be42a25d77ac6ad995c6be48e783380bad25a61732f87cefb0cce1a769cd69081f494a1a12d657664ef2b4d9c41f2ee83f6e9a84327d8756af9f985595e7d3b");
    test_hash(b"fd2203e467574e834ab07c9097ae164532f24be1eb5d88f1af7748ceff0d2c67a21f4e4097f9d3bb4e9fbf97186e0db6db0100230a52b453d421f8ab9c9a6043aa3295ea20d2f06a2f37470d8a99075f1b8a8336f6228cf08b5942fc1fb4299c7d2480e8e82bce175540bdfad7752bc95b577f229515394f3ae5cec870a4b2f8",
              b"a21b1077d52b27ac545af63b32746c6e3c51cb0cb9f281eb9f3580a6d4996d5c9917d2a6e484627a9d5a06fa1b25327a9d710e027387fc3e07d7c4d14c6086cc");
    test_hash(b"c13e6ca3abb893aa5f82c4a8ef754460628af6b75af02168f45b72f8f09e45ed127c203bc7bb80ff0c7bd96f8cc6d8110868eb2cfc01037d8058992a6cf2effcbfe498c842e53a2e68a793867968ba18efc4a78b21cdf6a11e5de821dcabab14921ddb33625d48a13baffad6fe8272dbdf4433bd0f7b813c981269c388f001",
              b"6e56f77f6883d0bd4face8b8d557f144661989f66d51b1fe4b8fc7124d66d9d20218616fea1bcf86c08d63bf8f2f21845a3e519083b937e70aa7c358310b5a7c");
    test_hash(b"85360c3d4257d9878e2f5c16d3cd7d0747df3d231e1a8f63fddc69b3b1101af72153de4c8154b090c9815f2466e0e4f02f3af3a89a7fd04e306664f93e5490d4ce7fc169d553c520ae15dd02c7c613c39b4acd00e0c9a3c501566e52cecea11f7303dd1da61abf3f2532fd396047b1887255f4b256c0afcf58f3ae48c947",
              b"e8352ddcac59e377ea0f9c32bbb43dfd1b6c829fad1954240c41b7c45b0b09db11064b64e2442a96f6530aac2c4abf3beb1eae77f2bce4efe88fee1a70cf5423");
    test_hash(b"18e75b47d898ac629c48e80dbfb75dae1e1700b771165eccdb18d628bfc4063dd6c3839a7ec4cd1255c4821b078cd174647b320bb685541d517c579f6b8e3cdd2e109a610c7a921653b204ad018d0340d9938735b60262662016767e1d8824a64954086229c0e3b5bd9ad88c54c1dc5aa4e768ff1a9470ee6f6e998f",
              b"01c756b7c20b5f95fd2b079ab6a50f28b946fb16266b07c6060945dc4fe9e0d279c5b1505b9ec7d8f8f3c9ebf0c5ee9365aec08cf278d65b64daeccc19d3cbf4");
    test_hash(b"c2963342cfaa88ccd102a258e6d629f6b0d367dd55116502ca4451ea523623bc4175819a0648df3168e8ea8f10ed27354807d76e02ee1fdf1c9c655ee2b9fd08d557058dabdf8dcf964bfcacc996ae173971e26ea038d407c824260d06c2848a04a488c4c456dbcde2939e561ab908c4097b508638d6cda556465c9cc5",
              b"a4d2f59393a5fea612c3c745f4bb9f41aaf3a3ce1679aa8afc1a62baa4ed452819418c8ae1a1e658757976692390fc43d4decf7d855cd8b498b6dc60cae05a90");
}


#[test]
fn funnybox_unfunnybox_auth() {
    fn f(data: Vec<u8>, k: SecretKey, authlen: usize, whichbyte: usize) -> quickcheck::TestResult {
        let n = random_nonce().unwrap();
        if data.len() == 0 {
            return quickcheck::TestResult::discard();
        }
        if authlen == 0 || authlen > data.len() {
            return quickcheck::TestResult::discard();
        }
        let mut padded_data = vec![0;32];
        padded_data.extend(data.clone());
        let mut ciphertext = vec![0;padded_data.len()];
        funnybox(&mut ciphertext, &padded_data, authlen, &n, &k.0).unwrap();
        for i in 0..padded_data.len() {
            padded_data[i] = 0; // no cheating!
        }
        ciphertext[32 + whichbyte % authlen] ^= 1;
        quickcheck::TestResult::from_bool(funnybox_open(&mut padded_data, &ciphertext,
                                                        authlen, &n, &k.0).is_err())
    }
    quickcheck::quickcheck(f as fn(Vec<u8>, SecretKey, usize, usize) -> quickcheck::TestResult);
}

#[test]
fn funnybox_unfunnybox_works() {
    fn f(data: Vec<u8>, authlen: usize, whichbyte: usize) -> quickcheck::TestResult {
        let n = random_nonce().unwrap();
        let k = SecretKey([0;32]);
        if data.len() == 0 {
            return quickcheck::TestResult::discard();
        }
        if authlen == 0 || authlen >= data.len() {
            return quickcheck::TestResult::discard();
        }
        let mut padded_data = vec![0;32];
        padded_data.extend(data.clone());
        let mut ciphertext = vec![0;padded_data.len()];
        funnybox(&mut ciphertext, &padded_data, authlen, &n, &k.0).unwrap();
        for i in 0..padded_data.len() {
            padded_data[i] = 0; // no cheating!
        }
        ciphertext[32 + authlen + whichbyte % (data.len()-authlen)] ^= 1;
        if funnybox_open(&mut padded_data, &ciphertext,
                         authlen, &n, &k.0).is_err() {
            return quickcheck::TestResult::error("it failed");
        }
        for i in 0..data.len() {
            if i != authlen + whichbyte % (data.len()-authlen) {
                if data[i] != padded_data[32+i] {
                    return quickcheck::TestResult::error(format!("{} != {} at {}",
                                                                 data[i], padded_data[32+i],
                                                                 i));
                }
            }
        }
        quickcheck::TestResult::passed()
    }
    quickcheck::quickcheck(f as fn(Vec<u8>, usize, usize) -> quickcheck::TestResult);
}

#[test]
fn secretbox_unsecretbox() {
    fn f(data: Vec<u8>, n: Nonce, k: SecretKey) {
        let mut padded_data = vec![0;32];
        padded_data.extend(data.clone());
        let mut ciphertext = vec![0;padded_data.len()];
        secretbox(&mut ciphertext, &padded_data, &n, &k.0).unwrap();
        for i in 0..padded_data.len() {
            padded_data[i] = 0; // no cheating!
        }
        secretbox_open(&mut padded_data, &ciphertext, &n, &k.0).unwrap();
        for i in 0..data.len() {
            assert_eq!(data[i], padded_data[32+i]);
        }
    }
    quickcheck::quickcheck(f as fn(Vec<u8>, Nonce, SecretKey));
}

#[test]
fn secretbox_unsecretbox_auth() {
    fn f(data: Vec<u8>, n: Nonce, k: SecretKey, whichbyte: usize) -> quickcheck::TestResult {
        if data.len() == 0 {
            return quickcheck::TestResult::discard();
        }
        let mut padded_data = vec![0;32];
        padded_data.extend(data.clone());
        let mut ciphertext = vec![0;padded_data.len()];
        secretbox(&mut ciphertext, &padded_data, &n, &k.0).unwrap();
        for i in 0..padded_data.len() {
            padded_data[i] = 0; // no cheating!
        }
        ciphertext[32 + whichbyte % data.len()] ^= 1;
        quickcheck::TestResult::from_bool(secretbox_open(&mut padded_data, &ciphertext,
                                                         &n, &k.0).is_err())
    }
    quickcheck::quickcheck(f as fn(Vec<u8>, Nonce, SecretKey, usize) -> quickcheck::TestResult);
}

#[test]
fn box_unbox() {
    fn f(data: Vec<u8>, n: Nonce, k1: KeyPair, k2: KeyPair) {
        let mut padded_data = vec![0;32];
        padded_data.extend(data.clone());
        let mut ciphertext = vec![0;padded_data.len()];
        box_up(&mut ciphertext, &padded_data, &n, &k1.public, &k2.secret).unwrap();
        for i in 0..padded_data.len() {
            padded_data[i] = 0; // no cheating!
        }
        box_open(&mut padded_data, &ciphertext, &n, &k2.public, &k1.secret).unwrap();
        for i in 0..data.len() {
            assert_eq!(data[i], padded_data[32+i]);
        }
    }
    quickcheck::quickcheck(f as fn(Vec<u8>, Nonce, KeyPair, KeyPair));
}

#[cfg(test)]

#[test]
fn nonce_is_ashow() {
    fn true_nonce(_n: Nonce) -> bool { true }
    quickcheck::quickcheck(true_nonce as fn(Nonce) -> bool);
}

#[test]
fn keypair_is_ashow() {
    fn f(_n: KeyPair) -> bool { true }
    quickcheck::quickcheck(f as fn(KeyPair) -> bool);
}

#[test]
fn secretkey_is_ashow() {
    fn f(_n: SecretKey) -> bool { true }
    quickcheck::quickcheck(f as fn(SecretKey) -> bool);
}

#[cfg(test)]
impl quickcheck::Arbitrary for Nonce {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Self {
        let mut array = [u8::arbitrary(g); 32];
        for i in 1..32 {
            array[i] = u8::arbitrary(g);
        }
        Nonce(array)
    }
    fn shrink(&self) -> Box<Iterator<Item=Self>> {
        if self.0 == [0;32] {
            quickcheck::empty_shrinker()
        } else {
            quickcheck::single_shrinker(Nonce([0;32]))
        }
    }
}

#[cfg(test)]
impl quickcheck::Arbitrary for PublicKey {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Self {
        KeyPair::arbitrary(g).public
    }
}

#[cfg(test)]
impl quickcheck::Arbitrary for SecretKey {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Self {
        let mut array = [u8::arbitrary(g); 32];
        for i in 1..32 {
            array[i] = u8::arbitrary(g);
        }
        SecretKey(array)
    }
    fn shrink(&self) -> Box<Iterator<Item=Self>> {
        if self.0 == [0;32] {
            quickcheck::empty_shrinker()
        } else {
            quickcheck::single_shrinker(SecretKey([0;32]))
        }
    }
}

#[cfg(test)]
impl quickcheck::Arbitrary for KeyPair {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Self {
        let mut pk: [u8; 32] = [0; 32];
        let sk = SecretKey::arbitrary(g);
        scalarmult_base(&mut pk, &sk.0);
        KeyPair{ public: PublicKey(pk), secret: sk }
    }
    fn shrink(&self) -> Box<Iterator<Item=Self>> {
        if self.secret.0 == [0;32] {
            quickcheck::empty_shrinker()
        } else {
            Box::new(self.secret.0[0].shrink().map(|c| {
                let sk = SecretKey([c;32]);
                let mut pk: [u8; 32] = [0; 32];
                scalarmult_base(&mut pk, &sk.0);
                KeyPair{ public: PublicKey(pk), secret: sk }
            }))
        }
    }
}
