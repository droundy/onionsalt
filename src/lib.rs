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
//! let recipient = 2;
//! let ob = onionbox(&keys_and_routes, &payload, recipient).unwrap();
//!
//! let mut packet = ob.packet();
//! let response = [1; PAYLOAD_LENGTH];
//! for i in 0..6 {
//!     let mut oob = onionbox_open(&packet, &pairs[i].secret).unwrap();
//!     let routing = oob.routing();
//!     // routing now holds the routing information sent to "i"
//! #     for j in 0..ROUTING_LENGTH {
//! #         assert_eq!(routing[j], keys_and_routes[i].1[j]);
//! #     }
//!     if i == recipient {
//!         // This is how to attach a response if you are the recipient.
//!         oob.respond(&response);
//!     }
//!     packet = oob.packet();
//! }
//! let resp = ob.read_return(&packet).expect("failed on response");
//! // resp now holds the return message
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

extern crate rand;

pub mod crypto;
pub mod bytes;

const AUTHENTICATIONBYTES: usize = 16;

/// The number of extra bytes needed per recipient.  Includes public
/// key and authentication bytes.
pub const OVERHEADBYTES: usize = 48;

/// The ROUTING_LENGTH is big enough for an ipv6 address and some
/// extra information.
pub const ROUTING_LENGTH: usize = 24;

const ROUTING_OVERHEAD: usize = ROUTING_LENGTH + OVERHEADBYTES;

pub const ROUTE_COUNT: usize = 6;

const AUTH_LENGTH: usize = (ROUTE_COUNT+1)*ROUTING_OVERHEAD - AUTHENTICATIONBYTES - 32;

/// PACKET_LENGTH is the size that we actually send to each recipient.
pub const PACKET_LENGTH: usize =
    bytes::BUFSIZE - 16 + 32 - ROUTING_OVERHEAD;

/// PAYLOAD_LENGTH is the size of the payload that the primary
/// recipient can get.  It differs from PACKET_LENGTH by the total
/// routing overhead.
pub const PAYLOAD_LENGTH: usize = PACKET_LENGTH - ROUTE_COUNT*ROUTING_OVERHEAD;

pub struct OnionBox {
    packet: [u8; PACKET_LENGTH],
    return_key: [u8; PACKET_LENGTH],
}
impl OnionBox {
    /// The encrypted packet, to be sent to the first receiver.
    pub fn packet(&self) -> [u8; PACKET_LENGTH] {
        self.packet
    }
    /// This function accepts a packet that has been sent to us, and
    /// decrypts it without authentication if it is the response to
    /// our original message.
    pub fn read_return(&self, msg: &[u8; PACKET_LENGTH]) -> Option<[u8; PAYLOAD_LENGTH]> {
        for i in 0..32 {
            if msg[i] != self.return_key[i] {
                return None;
            }
        }
        let mut payload = [0; PAYLOAD_LENGTH];
        for i in 0..PAYLOAD_LENGTH {
            let j = PACKET_LENGTH - PAYLOAD_LENGTH + i;
            payload[i] = msg[j] ^ self.return_key[j];
        }
        Some(payload)
    }
}

pub struct OpenedOnionBox {
    packet: [u8; PACKET_LENGTH],
    routing: [u8; ROUTING_LENGTH],
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
    /// The decrypted payload, *if* it is intended for us.  There is
    /// no authentication on this method, so you need some other
    /// mechanism to ensure that this information is valid.
    pub fn payload(&self) -> [u8; PAYLOAD_LENGTH] {
        let mut out = [0; PAYLOAD_LENGTH];
        for i in 0..PAYLOAD_LENGTH {
            out[i] = self.packet[PACKET_LENGTH - PAYLOAD_LENGTH + i];
        }
        out
    }
    /// Set `response` to the response payload information.  This is
    /// only likely to work correctly if the sender intended to ask us
    /// for a response.
    pub fn respond(&mut self, response: &[u8; PAYLOAD_LENGTH]) {
        let mut buffer = [8; bytes::BUFSIZE];
        for i in 0..PACKET_LENGTH {
            buffer[i] = self.packet[i];
        }
        onionbox_insert_payload_algorithm(&mut buffer, response);
        for i in 0..PACKET_LENGTH {
            self.packet[i] = buffer[i];
        }
    }
}

/// Encrypt a message in an onion defined by `keys_and_routings`, with
/// `payload` directed to `payload_recipient`.
pub fn onionbox(keys_and_routings: &[(crypto::PublicKey,
                                      [u8; ROUTING_LENGTH]);
                                     ROUTE_COUNT],
                payload: &[u8; PAYLOAD_LENGTH],
                payload_recipient: usize) -> Result<OnionBox, crypto::NaClError> {
    let mut out = OnionBox {
        packet: [0; PACKET_LENGTH],
        return_key: [0; PACKET_LENGTH],
    };
    let mut buffer = [0; bytes::BUFSIZE];
    let mut return_key = [0; bytes::BUFSIZE];
    try!(onionbox_algorithm(&mut buffer, &mut return_key, keys_and_routings, payload,
                            payload_recipient));
    for i in 0..PACKET_LENGTH {
        out.packet[i] = buffer[i];
        out.return_key[i] = return_key[i];
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
    };
    let mut buffer = [0; bytes::BUFSIZE];
    for i in 0..PACKET_LENGTH {
        buffer[i] = input[i];
    }
    oob.routing = try!(onionbox_open_algorithm(&mut buffer, secret_key));
    for i in 0..PACKET_LENGTH {
        oob.packet[i] = buffer[i];
    }
    Ok(oob)
}


/// **Not for public consumption!** Encrypt a message in an onion
/// defined by `keys_and_routings`, with `payload` directed to
/// `payload_recipient`.
pub fn onionbox_algorithm<T: bytes::SelfDocumenting>(buffer: &mut T,
                                                     return_key: &mut T,
                                                     keys_and_routings: &[(crypto::PublicKey,
                                                                           [u8; ROUTING_LENGTH]);
                                                                          ROUTE_COUNT],
                                                     payload: &[u8; PAYLOAD_LENGTH],
                                                     payload_recipient: usize)
                                                     -> Result<(), crypto::NaClError> {
    if payload_recipient >= ROUTE_COUNT {
        return Err(crypto::NaClError::InvalidInput);
    }

    assert_eq!(PACKET_LENGTH, bytes::PACKET_LENGTH);
    assert_eq!(PACKET_LENGTH, ROUTE_COUNT*ROUTING_OVERHEAD + PAYLOAD_LENGTH);
    assert_eq!(16 + (ROUTE_COUNT+1)*ROUTING_OVERHEAD - 32 + PAYLOAD_LENGTH,
               bytes::BUFSIZE);
    // We always use a zero nonce.
    let nonce = crypto::Nonce([0; 32]);

    // Here we create buffers for my_public_keys, my_private_keys, and
    // our plaintext.
    let mut my_keypairs: [crypto::KeyPair; ROUTE_COUNT] =
        [crypto::EMPTY_PAIR; ROUTE_COUNT];
    for i in 0..ROUTE_COUNT {
        my_keypairs[i] = try!(crypto::box_keypair());
    }
    let mut skeys: [[u8; 32]; ROUTE_COUNT] = [[8;32]; ROUTE_COUNT];
    for i in 0..ROUTE_COUNT {
        skeys[i] = try!(crypto::sillybox_beforenm(&keys_and_routings[i].0,
                                                  &my_keypairs[i].secret));
    }

    // First let's grab the ciphertext to decrypt the return message...
    for i in payload_recipient+1..ROUTE_COUNT {
        return_key.sillybox_afternm(AUTH_LENGTH, &nonce, &skeys[i],
                                    &format!("{}", i));
        return_key.annotate(&format!("Preparing to decrypt with respect to key {}",
                                     i));
    }
    return_key.move_bytes(bytes::BUFSIZE - PAYLOAD_LENGTH,
                          PACKET_LENGTH - PAYLOAD_LENGTH,
                          PAYLOAD_LENGTH);
    return_key.set_bytes(0,
                         PACKET_LENGTH - PAYLOAD_LENGTH,
                         &[0;PACKET_LENGTH-PAYLOAD_LENGTH],
                         "0");


    buffer.annotate(&format!("Starting with buffer of zeros."));

    for i in 0..ROUTE_COUNT {
        buffer.sillybox_afternm(AUTH_LENGTH, &nonce, &skeys[i],
                                &format!("{}", i));
        buffer.annotate(&format!("Encrypting to key {}", i));
        buffer.set_bytes(0, 32, &[0;32], "0");
        if i != ROUTE_COUNT-1 {
            buffer.move_bytes(bytes::BUFSIZE + 32 - PAYLOAD_LENGTH - ROUTE_COUNT*ROUTING_OVERHEAD,
                              bytes::BUFSIZE + 32 - PAYLOAD_LENGTH - (ROUTE_COUNT+1)*ROUTING_OVERHEAD,
                              ROUTE_COUNT*ROUTING_OVERHEAD - 32);
            buffer.annotate(&format!("Shifting left routing bytes to {}",
                                     bytes::BUFSIZE - PAYLOAD_LENGTH - ROUTE_COUNT*ROUTING_OVERHEAD));
        }
    }
    // At this stage, plaintext should be set up for the innermost
    // layer of the onion, although offset by a ROUTING_OVERHEAD.

    for i in (0..ROUTE_COUNT).rev() {
        // Move into place the portion of the routing information
        // which has already been encrypted.
        if i != ROUTE_COUNT-1 {
            buffer.move_bytes(bytes::BUFSIZE + 32 - PAYLOAD_LENGTH - (ROUTE_COUNT+1)*ROUTING_OVERHEAD,
                              bytes::BUFSIZE + 32 - PAYLOAD_LENGTH - ROUTE_COUNT*ROUTING_OVERHEAD,
                              ROUTE_COUNT*ROUTING_OVERHEAD - 32);
            buffer.annotate(&format!("Shifting right routing info"));
        }
        // Now we add the routing info!
        buffer.set_bytes(32, ROUTING_LENGTH, &keys_and_routings[i].1,
                         &format!("R{}", i) );
        // Add the public key we are using for the encryption.
        if i < ROUTE_COUNT-1 {
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
            buffer.set_bytes(bytes::BUFSIZE-PAYLOAD_LENGTH,
                             PAYLOAD_LENGTH, payload, "Payload".into());
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
    buffer.move_bytes(bytes::BUFSIZE-PAYLOAD_LENGTH,
                      ROUTE_COUNT*ROUTING_OVERHEAD,
                      PAYLOAD_LENGTH);
    buffer.annotate(&format!("Putting packet into place"));
    buffer.set_bytes(0, 32, &my_keypairs[0].public.0, "P0");
    buffer.annotate(&format!("Adding the last public key"));
    Ok(())
}

/// **Not for public consumption!** The buffer already contains the
/// message, and contains the next message on exit.
pub fn onionbox_open_algorithm<T: bytes::SelfDocumenting>(buffer: &mut T,
                                                          secret_key: &crypto::SecretKey)
                                                          -> Result<[u8; ROUTING_LENGTH],
                                                                    crypto::NaClError>
{
    let pk: &[u8] = &buffer.get_bytes(0, 32);
    buffer.move_bytes(ROUTE_COUNT*ROUTING_OVERHEAD,
                      bytes::BUFSIZE-PAYLOAD_LENGTH,
                      PAYLOAD_LENGTH);
    buffer.move_bytes(32, 16, ROUTE_COUNT*ROUTING_OVERHEAD);
    // the following is only to beautify the picture, since the bytes
    // are already zero.
    buffer.set_bytes(bytes::BUFSIZE-PAYLOAD_LENGTH-ROUTING_OVERHEAD,
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
pub fn onionbox_insert_payload_algorithm<T: bytes::SelfDocumenting>(buffer: &mut T,
                                                                    payload: &[u8; PAYLOAD_LENGTH]) {
    buffer.set_bytes(bytes::BUFSIZE - PAYLOAD_LENGTH - 32 - ROUTING_LENGTH,
                     PAYLOAD_LENGTH, payload, "Response");
    buffer.annotate(&format!("Add response payload"));
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
    let mut payload: [u8; PAYLOAD_LENGTH] = [0; PAYLOAD_LENGTH];
    payload[3] = 3;
    let payload = payload;
    onionbox_algorithm(&mut diagram, &mut return_key, &keys_and_routes, &payload, 2).unwrap();

    println!("{}", diagram.postscript());

    for i in 0..6 {
        diagram.clear();

        diagram.annotate(&format!("Message as received"));
        let route = onionbox_open_algorithm(&mut diagram, &pairs[i].secret).unwrap();
        assert_eq!(route, keys_and_routes[i].1);

        if i == 2 {
            // We are the recipient!
            let mut response: [u8; PAYLOAD_LENGTH] = [0; PAYLOAD_LENGTH];
            for j in 0..PAYLOAD_LENGTH {
                response[j] = j as u8;
            }
            onionbox_insert_payload_algorithm(&mut diagram, &response);
        }

        println!("{}", diagram.postscript());
    }
}

#[test]
fn check_onionbox_on_buffer() {
    use bytes::{SelfDocumenting};

    let mut buffer = [0; bytes::BUFSIZE];
    let mut return_key = [0; bytes::BUFSIZE];

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
    let mut payload: [u8; PAYLOAD_LENGTH] = [0; PAYLOAD_LENGTH];
    payload[3] = 3;
    let payload = payload;
    onionbox_algorithm(&mut buffer, &mut return_key, &keys_and_routes, &payload, 2).unwrap();

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

        let mut buffer = [0; bytes::BUFSIZE];
        let mut return_key = [0; bytes::BUFSIZE];

        let pairs = [pairs.0, pairs.1, pairs.2, pairs.3, pairs.4, pairs.5];
        let keys_and_routes: [(crypto::PublicKey, [u8; ROUTING_LENGTH]); ROUTE_COUNT]
            = [(pairs[0].public, *b"123456789012345612345678"),
               (pairs[1].public, *b"my friend is hermy frien"),
               (pairs[2].public, *b"address 3 for yoaddress "),
               (pairs[3].public, *b"another is - heranother "),
               (pairs[4].public, *b"router here is orouter h"),
               (pairs[5].public, *b"how to get to mehow to g")];
        let mut payload: [u8; PAYLOAD_LENGTH] = [0; PAYLOAD_LENGTH];
        for i in 0..PAYLOAD_LENGTH {
            payload[i] = data[i % data.len()];
        }
        payload[3] = 3;
        let payload = payload;
        onionbox_algorithm(&mut buffer, &mut return_key,
                           &keys_and_routes, &payload, payload_recipient).unwrap();

        for i in 0..6 {
            let route = onionbox_open_algorithm(&mut buffer, &pairs[i].secret).unwrap();
            if route != keys_and_routes[i].1 {
                return quickcheck::TestResult::error(
                    format!("route[{}] {:?} != {:?}", i, route, keys_and_routes[i].1));
            }

            if i == payload_recipient {
                // We are the recipient!
                let mut response: [u8; PAYLOAD_LENGTH] = [0; PAYLOAD_LENGTH];
                for j in 0..PAYLOAD_LENGTH {
                    response[j] = response_data[j % response_data.len()];
                    if buffer[PACKET_LENGTH - PAYLOAD_LENGTH + j] != payload[j] {
                        return quickcheck::TestResult::error(
                            format!("Response {:?} != {:?}",
                                    &buffer[PACKET_LENGTH - PAYLOAD_LENGTH + j],
                                    &payload[j]));
                    }
                }
                onionbox_insert_payload_algorithm(&mut buffer, &response);
            }
        }
        for j in 0..32 {
            if buffer[j] != return_key[j] {
                return quickcheck::TestResult::error(
                    format!("Bad return key {:?} != {:?}",
                            &buffer[j], &return_key[j]));
            }
        }
        for j in 0 .. PAYLOAD_LENGTH {
            let decrypted = buffer[PACKET_LENGTH-PAYLOAD_LENGTH+j] ^ return_key[PACKET_LENGTH-PAYLOAD_LENGTH+j];
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
