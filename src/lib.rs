//! The onionsalt crate.
//!
//! The Onion Salt encryption scheme is an onion encryption scheme
//! that is closely derived from the NaCl `crypto_box` format.
//!
//! # Examples
//!
//! Here is a simple example of onion encrypting a message and
//! decrypting it.
//!
//! ```
//! # use onionsalt::*;
//! #
//! let pairs = [crypto::box_keypair().unwrap(),
//!              crypto::box_keypair().unwrap(),
//!              crypto::box_keypair().unwrap(),
//!              crypto::box_keypair().unwrap(),
//!              crypto::box_keypair().unwrap(),
//!              crypto::box_keypair().unwrap()];
//! let recipient = 2;
//! let recipient_key = pairs[recipient].clone();
//! let keys_and_routes: [(crypto::PublicKey, [u8; ROUTING_LENGTH]); ROUTE_COUNT]
//!                        = [(pairs[0].public, *b"address for 0 router    "),
//!                           (pairs[1].public, *b"the address for router 1"),
//!                           (pairs[2].public, *b"this is the recipient!!!"),
//!                           (pairs[3].public, *b"the next router is nice."),
//!                           (pairs[4].public, *b"the second-to-last node."),
//!                           (pairs[5].public, *b"This is my own address. ")];
//! let mut payload: [u8; PAYLOAD_LENGTH] = [0; PAYLOAD_LENGTH];
//! payload[3] = 3;
//! let payload = payload;
//! let our_personal_key = crypto::box_keypair().unwrap();
//! let mut ob = onionbox(&keys_and_routes, recipient).unwrap();
//! ob.add_payload(our_personal_key, &payload);
//!
//! let mut packet = ob.packet();
//! let response = [1; PAYLOAD_LENGTH];
//! for i in 0..6 {
//!     println!("opening box {}", i);
//!     let mut oob = onionbox_open(&packet, &pairs[i].secret).unwrap();
//!     println!("grabbing routing for {}", i);
//!     let routing = oob.routing();
//!     // routing now holds the routing information sent to "i"
//! #     for j in 0..ROUTING_LENGTH {
//! #         assert_eq!(routing[j], keys_and_routes[i].1[j]);
//! #     }
//!     if i == recipient {
//!         // This is how to attach a response if you are the recipient.
//!         oob.respond(&recipient_key, &response);
//!     }
//!     packet = oob.packet();
//! }
//! let resp = ob.read_return(our_personal_key, &packet).unwrap();
//! // resp now holds the return message, authenticated and decrypted.
//! # for i in 0..PAYLOAD_LENGTH {
//! #     println!("{:02x} {:02x}", resp[i], response[i]);
//! # }
//! # for j in 0..PAYLOAD_LENGTH {
//! #     assert_eq!(resp[j], response[j]);
//! # }
//! ```

#![deny(warnings)]

#[cfg(test)]
extern crate quickcheck;

#[macro_use]
extern crate arrayref;

extern crate rand;

pub mod crypto;
mod bytes;
pub mod creatediagrams;

const AUTHENTICATIONBYTES: usize = 16;

/// The number of extra bytes needed per recipient.  Includes public
/// key and authentication bytes.
pub const OVERHEADBYTES: usize = 48;

/// The ROUTING_LENGTH is big enough for an ipv6 address and some
/// extra information.
pub const ROUTING_LENGTH: usize = 24;

const ROUTING_OVERHEAD: usize = ROUTING_LENGTH + OVERHEADBYTES;

/// The number of routers we send through.  Eventually I want to
/// implement the feature to send through fewer routers with the
/// message arriving back early.
pub const ROUTE_COUNT: usize = 6;

const AUTH_LENGTH: usize = (ROUTE_COUNT+1)*ROUTING_OVERHEAD - AUTHENTICATIONBYTES - 32;

/// `PACKET_LENGTH` is the size that we actually send to each recipient.
///
/// ```
/// # use onionsalt::*;
/// assert_eq!(PACKET_LENGTH, 1024);
/// ```
pub const PACKET_LENGTH: usize =
    bytes::BUFSIZE - 16 + 32 - ROUTING_OVERHEAD;

/// `ENCRYPTEDPAYLOAD_LENGTH` is the size of the encrypted payload
/// that is intended for the primary recipient.  It differs from
/// `PACKET_LENGTH` by the total routing overhead.
///
/// ```
/// # use onionsalt::*;
/// assert_eq!(ENCRYPTEDPAYLOAD_LENGTH, 592);
/// ```
pub const ENCRYPTEDPAYLOAD_LENGTH: usize = PACKET_LENGTH - ROUTE_COUNT*ROUTING_OVERHEAD;

/// `PAYLOAD_LENGTH` is the size of the payload that the primary
/// recipient can get.  It differs from `ENCRYPTEDPAYLOAD_LENGTH` by 48
/// (or `OVERHEADBYTES`).
///
/// ```
/// # use onionsalt::*;
/// assert_eq!(PAYLOAD_LENGTH, 544);
/// ```
pub const PAYLOAD_LENGTH: usize = ENCRYPTEDPAYLOAD_LENGTH - OVERHEADBYTES;

pub struct OnionBox {
    packet: [u8; PACKET_LENGTH],
    return_key: [u8; PACKET_LENGTH],
    payload_recipient_key: crypto::PublicKey,
    payload_nonce: crypto::Nonce,
}
impl OnionBox {
    /// The encrypted packet, to be sent to the first receiver.
    pub fn packet(&self) -> [u8; PACKET_LENGTH] {
        self.packet
    }
    /// This function accepts a packet that has been sent to us, and
    /// decrypts it without authentication if it is the response to
    /// our original message.
    pub fn read_return(&self, payload_key: crypto::KeyPair, msg: &[u8; PACKET_LENGTH])
                       -> Result<[u8; PAYLOAD_LENGTH], crypto::NaClError> {
        if *array_ref![msg,0,32] != *array_ref![self.return_key,0,32] {
            // this doesn't look to be the return packet
            return Err(crypto::NaClError::InvalidInput);
        }
        let mut encrypted = *array_ref![msg, PACKET_LENGTH - ENCRYPTEDPAYLOAD_LENGTH,
                                        ENCRYPTEDPAYLOAD_LENGTH];
        let simple_key = array_ref![self.return_key, PACKET_LENGTH - ENCRYPTEDPAYLOAD_LENGTH,
                                    ENCRYPTEDPAYLOAD_LENGTH];
        for i in 0 .. ENCRYPTEDPAYLOAD_LENGTH {
            encrypted[i] ^= simple_key[i];
        }
        let semidecrypted = &mut encrypted;
        println!("expected       {}", self.payload_recipient_key);
        let response_nonce = crypto::Nonce(*array_ref![semidecrypted,0,32]);
        println!("response_nonce {}", response_nonce);
        let payload = array_mut_ref![semidecrypted, 16, PAYLOAD_LENGTH+32];
        *array_mut_ref![payload,0,16] = [0;16];
        let mut plain = [0; PAYLOAD_LENGTH+32];
        println!("payload_nonce is {}", self.payload_nonce);
        println!("payload public key is {}", payload_key.public);
        try!(crypto::box_open(&mut plain, payload, &response_nonce,
                              &self.payload_recipient_key, &payload_key.secret));
        Ok(*array_ref![plain, 32, PAYLOAD_LENGTH])
    }
    pub fn add_payload(&mut self,
                       payload_key: crypto::KeyPair,
                       payload_contents: &[u8; PAYLOAD_LENGTH]) -> &mut Self {
        let mut plain = [0; PAYLOAD_LENGTH + 32];
        for i in 0..PAYLOAD_LENGTH {
            plain[i+32] = payload_contents[i];
        }
        // FIXME fill up plain here with the actual content to send.
        let mut cipher = [0; ENCRYPTEDPAYLOAD_LENGTH];
        crypto::box_up(&mut cipher[16..], &plain, &self.payload_nonce,
                       &self.payload_recipient_key, &payload_key.secret).unwrap();
        println!("\nfirst 32 bytes {:?}", &cipher[16..48]);
        println!("last 32 bytes {:?}", &cipher[PAYLOAD_LENGTH+16..]);
        *array_mut_ref![cipher, 0, 32] = payload_key.public.0;
        for i in 0..ENCRYPTEDPAYLOAD_LENGTH {
            self.packet[PACKET_LENGTH - ENCRYPTEDPAYLOAD_LENGTH + i] ^= cipher[i];
        }
        self
    }
}

pub struct OpenedOnionBox {
    packet: [u8; PACKET_LENGTH],
    routing: [u8; ROUTING_LENGTH],
    payload_nonce: crypto::Nonce,
}
impl OpenedOnionBox {
    /// The packet to be forwarded onwards to the next router.
    pub fn packet(&self) -> [u8; PACKET_LENGTH] {
        self.packet
    }
    /// The routing information for us.
    pub fn routing(&self) -> [u8; ROUTING_LENGTH] {
        self.routing
    }
    /// The payload public key of the sender (if we are the recipient).
    pub fn key(&self) -> crypto::PublicKey {
        crypto::PublicKey(*array_ref![self.packet,PACKET_LENGTH-ENCRYPTEDPAYLOAD_LENGTH,32])
    }
    /// Attempt to decrypt and authenticate the payload.
    pub fn payload(&self, response_key: &crypto::KeyPair)
                   -> Result<[u8; PAYLOAD_LENGTH], crypto::NaClError> {
        let mut ciphertext = *array_ref![self.packet, PACKET_LENGTH - PAYLOAD_LENGTH - 32,
                                         PAYLOAD_LENGTH + 32];
        *array_mut_ref![ciphertext,0,16] = [0;16];
        println!("\n-------------------------------------------\n");
        println!("grabbing payload from          {}", self.key());
        let mut plaintext = [0; PAYLOAD_LENGTH + 32];
        println!("first 32 bytes {:?}", &ciphertext[0..32]);
        println!("last 32 bytes {:?}", &ciphertext[PAYLOAD_LENGTH..]);
        println!("payload self.payload_nonce is {}", self.payload_nonce);
        try!(crypto::box_open(&mut plaintext, &ciphertext, &self.payload_nonce,
                              &self.key(), &response_key.secret));
        println!("box_open did not fail");
        Ok(*array_ref![plaintext,32,PAYLOAD_LENGTH])
    }
    /// Set `response` to the response payload information.  This is
    /// only likely to work correctly if the sender intended to ask us
    /// for a response.
    pub fn respond(&mut self,
                   response_key: &crypto::KeyPair,
                   response: &[u8; PAYLOAD_LENGTH]) {
        let mut buffer = bytes::Bytes([0; bytes::BUFSIZE]);
        for i in 0..PACKET_LENGTH {
            buffer.0[i] = self.packet[i];
        }
        let mut pl = [0; PAYLOAD_LENGTH+32];
        let mut ci = [0; ENCRYPTEDPAYLOAD_LENGTH];
        *array_mut_ref![pl,32,PAYLOAD_LENGTH] = *response;
        let response_nonce = crypto::random_nonce().unwrap();
        println!("\nvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv-\n");
        println!("response_nonce is {}", response_nonce);
        println!("compare with {}", self.key());
        crypto::box_up(&mut ci[16..], &pl, &response_nonce, &self.key(),
                       &response_key.secret).unwrap();
        *array_mut_ref![ci, 0, 32] = response_nonce.0;
        onionbox_insert_response_algorithm(&mut buffer, &ci);
        for i in 0..PACKET_LENGTH {
            self.packet[i] = buffer.0[i];
        }
    }
}

/// Encrypt a message in an onion defined by `keys_and_routings`, with
/// `payload` directed to `payload_recipient`.
///
/// `keys_and_routings` is the sequence of public keys owned by
/// recipients, and the routing information that said recipient should
/// use, presumably to send the message to the next recipient.  There
/// can be up to `ROUTE_COUNT` elements in this slice.  The final
/// address should be our own, if a return message is desired.  The
/// routing information should indicate to the payload recipient
/// (whose index in the slice is `payload_recipient`) what to do with
/// the payload.
///
/// # Security properties
///
/// No recipient (not possessing the secret keys of any other
/// recipient) by examining the packet received should be able to
/// determine any information other than the plaintext contents of the
/// routing information (except for the payload recipient, who should
/// also be able to read the plaintext payload.  Similarly, each
/// recipient can be confident that the routing information has not
/// been tampered with, although it could have been replaced in its
/// entirety with other routing information.
///
/// The recipient of the message payload may ensure that the payload
/// originated from the sender (or someone with the sender's secret
/// key), although the recipient cannot prove this to anyone else.
///
/// Things to keep in mind:
///
/// 1. There is no protection against tampering with the payload until
///    the payload is received by the recipient.  Thus the recipient
///    must take particular care not to reveal anything by its
///    response to the payload.
///
/// 2. No recipient can in any way determine (from the message
///    received) her place in the series of routing.
pub fn onionbox(keys_and_routings: &[(crypto::PublicKey,
                                      [u8; ROUTING_LENGTH])],
                payload_recipient: usize) -> Result<OnionBox, crypto::NaClError> {
    let mut out = OnionBox {
        packet: [0; PACKET_LENGTH],
        return_key: [0; PACKET_LENGTH],
        payload_recipient_key: keys_and_routings[payload_recipient].0,
        payload_nonce: crypto::Nonce([0;32]),
    };
    let mut buffer = bytes::Bytes([0; bytes::BUFSIZE]);
    let mut return_key = bytes::Bytes([0; bytes::BUFSIZE]);
    out.payload_nonce = try!(onionbox_algorithm(&mut buffer, &mut return_key,
                                                keys_and_routings, payload_recipient));
    println!("payload_nonce in onionbox is {}", out.payload_nonce);
    for i in 0..PACKET_LENGTH {
        out.packet[i] = buffer.0[i];
        out.return_key[i] = return_key.0[i];
    }
    Ok(out)
}

/// The buffer already contains the message, and contains the next message
/// on exit.
pub fn onionbox_open(input: &[u8; PACKET_LENGTH],
                     secret_key: &crypto::SecretKey)
                     -> Result<OpenedOnionBox, crypto::NaClError> {
    let mut oob = OpenedOnionBox {
        packet: [0; PACKET_LENGTH],
        routing: [0; ROUTING_LENGTH],
        payload_nonce: crypto::Nonce(*array_ref![input, 0, 32]),
    };
    println!("payload_nonce in onionbox_open is {}", oob.payload_nonce);
    println!("I am in onionbox_open");
    let mut buffer = bytes::Bytes([0; bytes::BUFSIZE]);
    for i in 0..PACKET_LENGTH {
        buffer.0[i] = input[i];
    }
    oob.routing = try!(onionbox_open_algorithm(&mut buffer, secret_key));
    for i in 0..PACKET_LENGTH {
        oob.packet[i] = buffer.0[i];
    }
    Ok(oob)
}


/// **Not for public consumption!** Encrypt a message in an onion
/// defined by `keys_and_routings`, with `payload` directed to
/// `payload_recipient`.
fn onionbox_algorithm<T: bytes::SelfDocumenting>(buffer: &mut T,
                                                 return_key: &mut T,
                                                 keys_and_routings: &[(crypto::PublicKey,
                                                                       [u8; ROUTING_LENGTH])],
                                                 payload_recipient: usize)
                                                 -> Result<crypto::Nonce, crypto::NaClError> {
    let route_count = keys_and_routings.len();
    if payload_recipient >= route_count || route_count > ROUTE_COUNT {
        return Err(crypto::NaClError::InvalidInput);
    }

    assert_eq!(PACKET_LENGTH, bytes::PACKET_LENGTH);
    assert_eq!(PACKET_LENGTH, ROUTE_COUNT*ROUTING_OVERHEAD + ENCRYPTEDPAYLOAD_LENGTH);
    assert_eq!(16 + (ROUTE_COUNT+1)*ROUTING_OVERHEAD - 32 + ENCRYPTEDPAYLOAD_LENGTH,
               bytes::BUFSIZE);
    // We always use a zero nonce.
    let nonce = crypto::Nonce([0; 32]);

    // Here we create buffers for my_public_keys, my_private_keys, and
    // our plaintext.
    let mut my_keypairs: [crypto::KeyPair; ROUTE_COUNT] =
        [crypto::EMPTY_PAIR; ROUTE_COUNT];
    for i in 0..route_count {
        my_keypairs[i] = try!(crypto::box_keypair());
    }
    let mut skeys: [[u8; 32]; ROUTE_COUNT] = [[0;32]; ROUTE_COUNT];
    for i in 0..route_count {
        skeys[i] = try!(crypto::sillybox_beforenm(&keys_and_routings[i].0,
                                                  &my_keypairs[i].secret));
    }

    // First let's grab the ciphertext to decrypt the return message...
    for i in payload_recipient+1..route_count {
        return_key.sillybox_afternm(AUTH_LENGTH, &nonce, &skeys[i],
                                    &format!("{}", i));
        return_key.annotate(&format!("Preparing to decrypt with respect to key {}",
                                     i));
    }
    return_key.move_bytes(bytes::BUFSIZE - ENCRYPTEDPAYLOAD_LENGTH,
                          PACKET_LENGTH - ENCRYPTEDPAYLOAD_LENGTH,
                          ENCRYPTEDPAYLOAD_LENGTH);
    return_key.set_bytes(0,
                         PACKET_LENGTH - ENCRYPTEDPAYLOAD_LENGTH,
                         &[0;PACKET_LENGTH-ENCRYPTEDPAYLOAD_LENGTH],
                         "0");

    buffer.set_bytes(0, bytes::BUFSIZE, &[0; bytes::BUFSIZE], "0");
    if route_count == ROUTE_COUNT {
        buffer.annotate(&format!("Starting with buffer of zeros."));
    } else {
        // For a short onion, we need to start with random data
        let nonce = try!(crypto::random_nonce());
        let skey = try!(crypto::random_nonce()).0;
        buffer.sillybox_afternm(AUTH_LENGTH, &nonce, &skey, &format!("Random"));
        buffer.set_bytes(0,32, &[0;32], "0");
        buffer.set_bytes(bytes::BUFSIZE - ENCRYPTEDPAYLOAD_LENGTH - ROUTING_OVERHEAD,
                         ENCRYPTEDPAYLOAD_LENGTH + ROUTING_OVERHEAD,
                         &[0; ENCRYPTEDPAYLOAD_LENGTH + ROUTING_OVERHEAD], "0");
        buffer.annotate(&format!("Starting with a random+zeros buffer for {}-layer onion.",
                                 route_count));
    }

    for i in 0..route_count {
        buffer.sillybox_afternm(AUTH_LENGTH, &nonce, &skeys[i],
                                &format!("{}", i));
        buffer.annotate(&format!("Encrypting to key {}", i));
        buffer.set_bytes(0, 32, &[0;32], "0");
        if i != route_count-1 {
            buffer.move_bytes(bytes::BUFSIZE + 32 - ENCRYPTEDPAYLOAD_LENGTH - ROUTE_COUNT*ROUTING_OVERHEAD,
                              bytes::BUFSIZE + 32 - ENCRYPTEDPAYLOAD_LENGTH - (ROUTE_COUNT+1)*ROUTING_OVERHEAD,
                              ROUTE_COUNT*ROUTING_OVERHEAD - 32);
            buffer.annotate(&format!("Shifting left routing bytes"));
        }
    }
    // At this stage, plaintext should be set up for the innermost
    // layer of the onion, although offset by a ROUTING_OVERHEAD.

    for i in (0..route_count).rev() {
        // Move into place the portion of the routing information
        // which has already been encrypted.
        if i != route_count-1 {
            buffer.move_bytes(bytes::BUFSIZE + 32 - ENCRYPTEDPAYLOAD_LENGTH - (ROUTE_COUNT+1)*ROUTING_OVERHEAD,
                              bytes::BUFSIZE + 32 - ENCRYPTEDPAYLOAD_LENGTH - ROUTE_COUNT*ROUTING_OVERHEAD,
                              ROUTE_COUNT*ROUTING_OVERHEAD - 32);
            buffer.annotate(&format!("Shifting right routing info"));
        }
        // Now we add the routing info!
        buffer.set_bytes(32, ROUTING_LENGTH, &keys_and_routings[i].1,
                         &format!("R{}", i) );
        // Add the public key we are using for the encryption.
        if i < route_count-1 {
            buffer.set_bytes(32+ROUTING_LENGTH, 32, &my_keypairs[i+1].public.0,
                             &format!("P{}", i+1));
            buffer.annotate(&format!("Adding routing info for {}", i));
        } else {
            return_key.copy_bytes(0, buffer, 32+ROUTING_LENGTH, 32);
            return_key.annotate("Shifting and adding the final public key to the return key");
            buffer.annotate(&format!("Adding routing info but no public key {}", i));
        }
        // Add the payload if it is the right time.
        if i == payload_recipient {
            buffer.set_bytes(bytes::BUFSIZE-ENCRYPTEDPAYLOAD_LENGTH,
                             ENCRYPTEDPAYLOAD_LENGTH, &[0; ENCRYPTEDPAYLOAD_LENGTH], "Payload".into());
            buffer.annotate(&format!("Adding payload {}", i));
        }
        // Now we encrypt the plaintext, which expands it by
        // AUTHENTICATIONBYTES.
        buffer.sillybox_afternm(AUTH_LENGTH, &nonce, &skeys[i],
                                &format!("{}", i));
        buffer.annotate(&format!("Encrypting to key {}", i));
        // for j in auth_length-ROUTING_OVERHEAD .. auth_length {
        //     assert!(ciphertext[j] == 0);
        // }
    }
    buffer.move_bytes(16, 32, ROUTE_COUNT*ROUTING_OVERHEAD);
    buffer.move_bytes(bytes::BUFSIZE-ENCRYPTEDPAYLOAD_LENGTH,
                      ROUTE_COUNT*ROUTING_OVERHEAD,
                      ENCRYPTEDPAYLOAD_LENGTH);
    buffer.annotate(&format!("Putting packet into place"));
    buffer.set_bytes(0, 32, &my_keypairs[0].public.0, "P0");
    buffer.annotate(&format!("Adding the last public key"));
    Ok(crypto::Nonce(my_keypairs[payload_recipient].public.0))
}

/// **Not for public consumption!** The buffer already contains the
/// message, and contains the next message on exit.
fn onionbox_open_algorithm<T: bytes::SelfDocumenting>(buffer: &mut T,
                                                      secret_key: &crypto::SecretKey)
                                                      -> Result<[u8; ROUTING_LENGTH],
                                                                crypto::NaClError>
{
    let pk: &[u8] = &buffer.get_bytes(0, 32);
    buffer.move_bytes(ROUTE_COUNT*ROUTING_OVERHEAD,
                      bytes::BUFSIZE-ENCRYPTEDPAYLOAD_LENGTH,
                      ENCRYPTEDPAYLOAD_LENGTH);
    buffer.move_bytes(32, 16, ROUTE_COUNT*ROUTING_OVERHEAD);
    // the following is only to beautify the picture, since the bytes
    // are already zero.
    buffer.set_bytes(bytes::BUFSIZE-ENCRYPTEDPAYLOAD_LENGTH-ROUTING_OVERHEAD,
                     ROUTING_OVERHEAD,
                     &[0;ROUTING_OVERHEAD],
                     "0");
    buffer.annotate(&format!("Extract the public key and insert zeros"));

    let skey = try!(crypto::sillybox_beforenm(pk, secret_key));
    try!(buffer.sillybox_open_afternm(AUTH_LENGTH, &crypto::Nonce([0;32]), &skey));
    buffer.annotate(&format!("Decrypting with our secret key"));
    let routevec = buffer.get_bytes(32, ROUTING_LENGTH);
    buffer.move_bytes(32+ROUTING_LENGTH,
                      0, bytes::BUFSIZE - 32 - ROUTING_LENGTH);
    buffer.annotate(&format!("Extracting routing information and shifted back"));
    let mut route = [0;ROUTING_LENGTH];
    for i in 0..ROUTING_LENGTH {
        route[i] = routevec[i];
    }
    Ok(route)
}

/// **Not for public consumption!**
fn onionbox_insert_response_algorithm<T: bytes::SelfDocumenting>(buffer: &mut T,
                                                                 payload: &[u8; ENCRYPTEDPAYLOAD_LENGTH]) {
    buffer.set_bytes(bytes::BUFSIZE - ENCRYPTEDPAYLOAD_LENGTH - 32 - ROUTING_LENGTH,
                     ENCRYPTEDPAYLOAD_LENGTH, payload, "Response");
    buffer.annotate(&format!("Read payload and replace with response"));
}

#[test]
fn check_onionbox_on_diagram() {
    use bytes::{SelfDocumenting};

    let mut diagram = bytes::Diagram::new();
    let mut return_key = bytes::Diagram::new();

    let pairs = [crypto::box_keypair().unwrap(),
                 crypto::box_keypair().unwrap(),
                 crypto::box_keypair().unwrap(),
                 crypto::box_keypair().unwrap(),
                 crypto::box_keypair().unwrap(),
                 crypto::box_keypair().unwrap()];

    let keys_and_routes: [(crypto::PublicKey, [u8; ROUTING_LENGTH]); ROUTE_COUNT]
                           = [(pairs[0].public, *b"123456789012345612345678"),
                              (pairs[1].public, *b"my friend is hermy frien"),
                              (pairs[2].public, *b"address 3 for yoaddress "),
                              (pairs[3].public, *b"another is - heranother "),
                              (pairs[4].public, *b"router here is orouter h"),
                              (pairs[5].public, *b"how to get to mehow to g")];
    onionbox_algorithm(&mut diagram, &mut return_key, &keys_and_routes, 2).unwrap();

    println!("{}", diagram.postscript());

    for i in 0..6 {
        diagram.clear();

        diagram.annotate(&format!("Message as received"));
        let route = onionbox_open_algorithm(&mut diagram, &pairs[i].secret).unwrap();
        assert_eq!(route, keys_and_routes[i].1);

        if i == 2 {
            // We are the recipient!
            let mut response: [u8; ENCRYPTEDPAYLOAD_LENGTH] = [0; ENCRYPTEDPAYLOAD_LENGTH];
            for j in 0..ENCRYPTEDPAYLOAD_LENGTH {
                response[j] = j as u8;
            }
            onionbox_insert_response_algorithm(&mut diagram, &response);
        }

        println!("{}", diagram.postscript());
    }
}

#[test]
fn check_onionbox_on_buffer() {
    use bytes::{SelfDocumenting};

    let mut buffer = bytes::Bytes([0; bytes::BUFSIZE]);
    let mut return_key = bytes::Bytes([0; bytes::BUFSIZE]);

    let pairs = [crypto::box_keypair().unwrap(),
                 crypto::box_keypair().unwrap(),
                 crypto::box_keypair().unwrap(),
                 crypto::box_keypair().unwrap(),
                 crypto::box_keypair().unwrap(),
                 crypto::box_keypair().unwrap()];

    let keys_and_routes: [(crypto::PublicKey, [u8; ROUTING_LENGTH]); ROUTE_COUNT]
                           = [(pairs[0].public, *b"123456789012345612345678"),
                              (pairs[1].public, *b"my friend is hermy frien"),
                              (pairs[2].public, *b"address 3 for yoaddress "),
                              (pairs[3].public, *b"another is - heranother "),
                              (pairs[4].public, *b"router here is orouter h"),
                              (pairs[5].public, *b"how to get to mehow to g")];
    onionbox_algorithm(&mut buffer, &mut return_key, &keys_and_routes, 2).unwrap();

    for i in 0..6 {
        buffer.clear();

        buffer.annotate(&format!("Message as received by {}", i));
        let route = onionbox_open_algorithm(&mut buffer, &pairs[i].secret).unwrap();
        println!("route should be {}", String::from_utf8_lossy(&keys_and_routes[i].1));
        println!("route is actually {}", String::from_utf8_lossy(&route));
        assert_eq!(route, keys_and_routes[i].1);
    }
}

#[test]
fn check_short_onionbox_on_buffer() {
    use bytes::{SelfDocumenting};

    let mut buffer = bytes::Bytes([0; bytes::BUFSIZE]);
    let mut return_key = bytes::Bytes([0; bytes::BUFSIZE]);

    let pairs = [crypto::box_keypair().unwrap(),
                 crypto::box_keypair().unwrap(),
                 crypto::box_keypair().unwrap()];

    let keys_and_routes = [(pairs[0].public, *b"123456789012345612345678"),
                           (pairs[1].public, *b"my friend is hermy frien"),
                           (pairs[2].public, *b"address 3 for yoaddress ")];
    onionbox_algorithm(&mut buffer, &mut return_key, &keys_and_routes, 1).unwrap();

    for i in 0..pairs.len() {
        buffer.clear();

        buffer.annotate(&format!("Message as received by {}", i));
        let route = onionbox_open_algorithm(&mut buffer, &pairs[i].secret).unwrap();
        println!("route should be {}", String::from_utf8_lossy(&keys_and_routes[i].1));
        println!("route is actually {}", String::from_utf8_lossy(&route));
        assert_eq!(route, keys_and_routes[i].1);
    }
}

#[test]
fn test_onionbox_auth() {
    use crypto::KeyPair;
    fn f(data: Vec<u8>, response_data: Vec<u8>,
         payload_recipient: usize,
         pairs : (KeyPair,KeyPair,KeyPair,KeyPair,KeyPair,KeyPair))
         -> quickcheck::TestResult {
        if data.len() == 0 || response_data.len() == 0 {
            return quickcheck::TestResult::discard();
        }

        let payload_recipient = payload_recipient % ROUTE_COUNT;

        let mut buffer = bytes::Bytes([0; bytes::BUFSIZE]);
        let mut return_key = bytes::Bytes([0; bytes::BUFSIZE]);

        let pairs = [pairs.0, pairs.1, pairs.2, pairs.3, pairs.4, pairs.5];
        let keys_and_routes: [(crypto::PublicKey, [u8; ROUTING_LENGTH]); ROUTE_COUNT]
            = [(pairs[0].public, *b"123456789012345612345678"),
               (pairs[1].public, *b"my friend is hermy frien"),
               (pairs[2].public, *b"address 3 for yoaddress "),
               (pairs[3].public, *b"another is - heranother "),
               (pairs[4].public, *b"router here is orouter h"),
               (pairs[5].public, *b"how to get to mehow to g")];
        onionbox_algorithm(&mut buffer, &mut return_key,
                           &keys_and_routes, payload_recipient).unwrap();

        for i in 0..6 {
            let route = onionbox_open_algorithm(&mut buffer, &pairs[i].secret).unwrap();
            if route != keys_and_routes[i].1 {
                return quickcheck::TestResult::error(
                    format!("route[{}] {:?} != {:?}", i, route, keys_and_routes[i].1));
            }

            if i == payload_recipient {
                // We are the recipient!
                let mut response: [u8; ENCRYPTEDPAYLOAD_LENGTH] = [0; ENCRYPTEDPAYLOAD_LENGTH];
                for j in 0..ENCRYPTEDPAYLOAD_LENGTH {
                    response[j] = response_data[j % response_data.len()];
                    if buffer.0[PACKET_LENGTH - ENCRYPTEDPAYLOAD_LENGTH + j] != 0 {
                        return quickcheck::TestResult::error(
                            format!("Response {:?} != 0",
                                    &buffer.0[PACKET_LENGTH - ENCRYPTEDPAYLOAD_LENGTH + j]));
                    }
                }
                onionbox_insert_response_algorithm(&mut buffer, &response);
            }
        }
        for j in 0..32 {
            if buffer.0[j] != return_key.0[j] {
                return quickcheck::TestResult::error(
                    format!("Bad return key {:?} != {:?}",
                            &buffer.0[j], &return_key.0[j]));
            }
        }
        for j in 0 .. ENCRYPTEDPAYLOAD_LENGTH {
            let decrypted = buffer.0[PACKET_LENGTH-ENCRYPTEDPAYLOAD_LENGTH+j] ^ return_key.0[PACKET_LENGTH-ENCRYPTEDPAYLOAD_LENGTH+j];
            let resp = response_data[j % response_data.len()];
            if decrypted != resp {
                return quickcheck::TestResult::error(
                    format!("Bad response {:?} != {:?}", decrypted, resp));
            }
        }
        quickcheck::TestResult::passed()
    }
    quickcheck::quickcheck(f as fn(Vec<u8>, Vec<u8>, usize,
                                   (KeyPair, KeyPair, KeyPair,
                                    KeyPair, KeyPair, KeyPair)) -> quickcheck::TestResult);
}


#[test]
fn test_short_onionbox_auth() {
    use crypto::KeyPair;
    fn f(data: Vec<u8>, response_data: Vec<u8>,
         payload_recipient: usize,
         pairs : (KeyPair,KeyPair,KeyPair))
         -> quickcheck::TestResult {
        if data.len() == 0 || response_data.len() == 0 {
            return quickcheck::TestResult::discard();
        }

        let mut buffer = bytes::Bytes([0; bytes::BUFSIZE]);
        let mut return_key = bytes::Bytes([0; bytes::BUFSIZE]);

        let pairs = [pairs.0, pairs.1, pairs.2];
        let payload_recipient = payload_recipient % pairs.len();
        let keys_and_routes
            = [(pairs[0].public, *b"123456789012345612345678"),
               (pairs[1].public, *b"my friend is hermy frien"),
               (pairs[2].public, *b"address 3 for yoaddress ")];
        onionbox_algorithm(&mut buffer, &mut return_key,
                           &keys_and_routes, payload_recipient).unwrap();

        for i in 0..pairs.len() {
            let route = onionbox_open_algorithm(&mut buffer, &pairs[i].secret).unwrap();
            if route != keys_and_routes[i].1 {
                return quickcheck::TestResult::error(
                    format!("route[{}] {:?} != {:?}", i, route, keys_and_routes[i].1));
            }

            if i == payload_recipient {
                // We are the recipient!
                let mut response: [u8; ENCRYPTEDPAYLOAD_LENGTH] = [0; ENCRYPTEDPAYLOAD_LENGTH];
                for j in 0..ENCRYPTEDPAYLOAD_LENGTH {
                    response[j] = response_data[j % response_data.len()];
                    if buffer.0[PACKET_LENGTH - ENCRYPTEDPAYLOAD_LENGTH + j] != 0 {
                        return quickcheck::TestResult::error(
                            format!("Response {:?} != 0",
                                    &buffer.0[PACKET_LENGTH - ENCRYPTEDPAYLOAD_LENGTH + j]));
                    }
                }
                onionbox_insert_response_algorithm(&mut buffer, &response);
            }
        }
        for j in 0..32 {
            if buffer.0[j] != return_key.0[j] {
                return quickcheck::TestResult::error(
                    format!("Bad return key {:?} != {:?}",
                            &buffer.0[j], &return_key.0[j]));
            }
        }
        for j in 0 .. ENCRYPTEDPAYLOAD_LENGTH {
            let decrypted = buffer.0[PACKET_LENGTH-ENCRYPTEDPAYLOAD_LENGTH+j]
                ^ return_key.0[PACKET_LENGTH-ENCRYPTEDPAYLOAD_LENGTH+j];
            let resp = response_data[j % response_data.len()];
            if decrypted != resp {
                return quickcheck::TestResult::error(
                    format!("Bad response {:?} != {:?}", decrypted, resp));
            }
        }
        quickcheck::TestResult::passed()
    }
    quickcheck::quickcheck(f as fn(Vec<u8>, Vec<u8>, usize,
                                   (KeyPair, KeyPair, KeyPair)) -> quickcheck::TestResult);
}

#[test]
fn test_onionbox_simple() {
    let pairs = [crypto::box_keypair().unwrap(),
                 crypto::box_keypair().unwrap(),
                 crypto::box_keypair().unwrap(),
                 crypto::box_keypair().unwrap(),
                 crypto::box_keypair().unwrap(),
                 crypto::box_keypair().unwrap()];
    let recipient = 2;
    let recipient_key = pairs[recipient].clone();
    let keys_and_routes: [(crypto::PublicKey, [u8; ROUTING_LENGTH]); ROUTE_COUNT]
        = [(pairs[0].public, *b"address for 0 router    "),
           (pairs[1].public, *b"the address for router 1"),
           (pairs[2].public, *b"this is the recipient!!!"),
           (pairs[3].public, *b"the next router is nice."),
           (pairs[4].public, *b"the second-to-last node."),
           (pairs[5].public, *b"This is my own address. ")];
    let mut payload: [u8; PAYLOAD_LENGTH] = [0; PAYLOAD_LENGTH];
    payload[3] = 3;
    let payload = payload;
    let our_personal_key = crypto::box_keypair().unwrap();
    let mut ob = onionbox(&keys_and_routes, recipient).unwrap();
    ob.add_payload(our_personal_key, &payload);

    let mut packet = ob.packet();
    let response = [1; PAYLOAD_LENGTH];
    for i in 0..6 {
        println!("opening box {}", i);
        let mut oob = onionbox_open(&packet, &pairs[i].secret).unwrap();
        println!("grabbing routing for {}", i);
        let routing = oob.routing();
        // routing now holds the routing information sent to "i"
        for j in 0..ROUTING_LENGTH {
            assert_eq!(routing[j], keys_and_routes[i].1[j]);
        }
        if i == recipient {
            // This is how to attach a response if you are the recipient.
            println!("opening payload should be from {}", our_personal_key.public);
            let payl = oob.payload(&recipient_key).unwrap();
            println!("got payload");
            for j in 0..PAYLOAD_LENGTH {
                assert_eq!(payl[j], payload[j]);
            }
            println!("\nXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
            oob.respond(&recipient_key, &response);
            println!("\nYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY");
        }
        packet = oob.packet();
    }
    println!("\nXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
    let resp = ob.read_return(our_personal_key, &packet).unwrap();
    println!("\nYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY");
    // resp now holds the return message
    for i in 0..PAYLOAD_LENGTH {
        println!("{:02x} {:02x}", resp[i], response[i]);
    }
    for j in 0..PAYLOAD_LENGTH {
        assert_eq!(resp[j], response[j]);
    }
}
