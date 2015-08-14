//! The onionsalt crate.
//!
//! The Onion Salt encryption scheme is an onion encryption scheme
//! that is closely derived from the NaCl `crypto_box` format.
//!
//! # Examples
//!
//! Here is a simple example of onion encrypting a message and
//! decrypting it.  We encrypt the message "Hi!" with two routers, and
//! verify that everything gets decrypted all right in the end.
//!
//! `x` x`
//! # use onionsalt::*;
//! #
//! let k0 = crypto::box_keypair().unwrap();
//! let k1 = crypto::box_keypair().unwrap();
//! let yu = crypto::box_keypair().unwrap();
//! let k3 = crypto::box_keypair().unwrap();
//! let k4 = crypto::box_keypair().unwrap();
//! let k5 = crypto::box_keypair().unwrap();
//!
//! let keys_and_routes: [(crypto::PublicKey, [u8; ROUTING_LENGTH]); ROUTE_COUNT]
//!                        = [(k0.public, b"12345678901234567"),
//!                           (k1.public, b"my friend is here"),
//!                           (yu.public, b"address 3 for you"),
//!                           (k3.public, b"another is - here"),
//!                           (k4.public, b"router here is ok"),
//!                           (k5.public, b"how to get to me!")];
//! let mut payload: [u8; PAYLOAD_LENGTH] = [0; PAYLOAD_LENGTH];
//! payload[3] = 3;
//! let payload = payload;
//! let my_box = onionbox(&keys_and_routes, &payload, 2).unwrap();
//!
//! // We now have encrypted the onionbox message.  Yay! So let's open the box...
//!
//! let b1 = onionbox_open_easy(&my_box.packet, &k0.secret).unwrap();
//! assert_eq!(&b1.route, &b"12345678901234567");
//! assert!(b1.is_for_relay());
//!
//! // Now our first router has opened his message and can route it.
//!
//! let b2 = onionbox_open_easy(&b1.packet, &k1.secret).unwrap();
//! assert_eq!(&b2.route, b"my friend is here");
//! assert!(b2.is_for_relay());
//!
//! // Now our second router has opened his message and can route it.
//!
//! let mut bu = onionbox_open_easy(&b2.packet, &yu.secret).unwrap();
//! match bu {
//!     ForMe { payload: p } => {
//!         assert_eq!(3, p[3]);
//!         assert_eq!(0, p[0]);
//!         assert_eq!(0, p[73]);
//!         let mut response = [0; PAYLOAD_LENGTH];
//!         for i in 0..PAYLOAD_LENGTH {
//!             response[PAYLOAD_LENGTH-1-i] = i as u8;
//!         }
//!         bu.respond(response);
//!     },
//!     _ => assert!(false),
//! }
//! assert_eq!(&bu.route, b"address 3 for you");
//!
//! let b4 = onionbox_open_easy(&bu.packet, &k3.secret).unwrap();
//! assert_eq!(&b4.route, b"another is - here");
//! assert!(b4.is_for_relay());
//!
//! let b5 = onionbox_open_easy(&b4.packet, &k4.secret).unwrap();
//! assert_eq!(&b5.route, b"router here is ok");
//! assert!(b5.is_for_relay());
//!
//! let bme = onionbox_open_easy(&b5.packet, &k5.secret).unwrap();
//! assert_eq!(&bme.route, b"how to get to me!");
//! assert!(bme.is_for_relay());
//!
//! let response = my_box.receive(bme.packet).unwrap();
//! for i in 0..PAYLOAD_LENGTH {
//! let     assert_eq!(response[PAYLOAD_LENGTH-1-i], i);
//! }
//! ` x` d`


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

pub const ROUTING_OVERHEAD: usize = ROUTING_LENGTH + OVERHEADBYTES;

pub const ROUTE_COUNT: usize = 6;

/// PACKET_LENGTH is the size that we actually send to each recipient.
pub const PACKET_LENGTH: usize =
    bytes::BUFSIZE - 16 + 32 - ROUTING_OVERHEAD;

/// PAYLOAD_LENGTH is the size of the payload that the primary
/// recipient can get.  It differs from PACKET_LENGTH by the total
/// routing overhead.
pub const PAYLOAD_LENGTH: usize = PACKET_LENGTH - ROUTE_COUNT*ROUTING_OVERHEAD;

use std::vec::Vec;
use crypto::ToPublicKey;

pub struct OnionBox {
    keys: Vec<[u8; 32]>,
    pub packet: [u8; PACKET_LENGTH],
    pub final_key: crypto::PublicKey,
}

impl OnionBox {
    pub fn receive(&self, _ciphertext: &[u8; PACKET_LENGTH])
               -> Result<[u8; PAYLOAD_LENGTH], crypto::NaClError> {
        unimplemented!()
    }
    pub fn new() -> OnionBox {
        OnionBox {
            keys: Vec::new(),
            packet: [0; PACKET_LENGTH],
            final_key: crypto::PublicKey([0;32]),
        }
    }
}

/// Encrypt a message in an onion directed to `their_public_keys`
/// recipients.
pub fn onionbox(keys_and_routings: &[(crypto::PublicKey, [u8; ROUTING_LENGTH]);
                                     ROUTE_COUNT],
                payload: &[u8; PAYLOAD_LENGTH],
                payload_recipient: usize)
                -> Result<OnionBox, crypto::NaClError> {
    assert!(payload_recipient < ROUTE_COUNT);
    assert_eq!(ROUTE_COUNT*(ROUTING_LENGTH+OVERHEADBYTES)+32+16 + PAYLOAD_LENGTH, PACKET_LENGTH);
    // layer_overhead is the amount of space needed for each
    // additional layer.  This ends up being equal to the amount of
    // zero padding that we have to add to the end.
    let layer_overhead = ROUTING_LENGTH + OVERHEADBYTES;
    // message_length is the length of the transmitted message.
    let encrypted_length = PAYLOAD_LENGTH + ROUTE_COUNT*(ROUTING_LENGTH+OVERHEADBYTES);
    // cb_length is the length that we always pass to crypto_box.  It
    // corresponds to encrypted_length plus one layer_overhead (filled
    // with zeros at the end) plus crypto_box_BOXZEROBYTES.
    let cb_length = AUTHENTICATIONBYTES + encrypted_length + layer_overhead;

    let mut ciphertext: Vec<u8> = vec![0; cb_length];
    let mut plaintext: Vec<u8> = vec![0; cb_length];

    // We always use a zero nonce.
    let nonce = crypto::Nonce([0; 32]);

    // Here we create buffers for my_public_keys, my_private_keys, and
    // our plaintext.
    let mut my_keypairs: [crypto::KeyPair; ROUTE_COUNT+1] =
        [crypto::EMPTY_PAIR; ROUTE_COUNT+1];
    for i in 0..ROUTE_COUNT {
        my_keypairs[i] = try!(crypto::box_keypair());
    }
    let mut skeys: [[u8; 32]; ROUTE_COUNT] = [[8;32]; ROUTE_COUNT];
    for i in 0..ROUTE_COUNT {
        skeys[i] = try!(crypto::sillybox_beforenm(&keys_and_routings[i].0,
                                                  &my_keypairs[i].secret));
    }

    let total_routing_length = ROUTE_COUNT*(ROUTING_LENGTH+OVERHEADBYTES);
    let auth_length = total_routing_length + layer_overhead;
    for i in 0..ROUTE_COUNT {
        for j in 32..total_routing_length {
            plaintext[j] = ciphertext[j+layer_overhead];
        }
        try!(crypto::sillybox_afternm(&mut ciphertext, &plaintext,
                                      auth_length,
                                      &nonce, &skeys[i]));
    }
    // At this stage, plaintext should be set up for the innermost
    // layer of the onion, although offset by a layer_overhead.
    for i in (0..ROUTE_COUNT).rev() {
        // Now we add the routing info!
        for j in 0..ROUTING_LENGTH {
            plaintext[32+j] = keys_and_routings[i].1[j];
        }
        // Add the public key we are using for the encryption.
        for j in 0..32 {
            plaintext[32+ROUTING_LENGTH+j] = my_keypairs[i+1].public.0[j];
        }
        // Add the rest of the routing information, which has already
        // been encrypted.
        for j in 0..total_routing_length-layer_overhead {
            plaintext[64+total_routing_length-layer_overhead+j] =
                ciphertext[16+j];
        }
        // Either add the payload, or copy over the possibly encrypted
        // payload.
        if i == payload_recipient {
            for j in 0..PAYLOAD_LENGTH {
                plaintext[PACKET_LENGTH-PAYLOAD_LENGTH+j] = payload[j];
            }
        } else {
            for j in 0..PAYLOAD_LENGTH {
                plaintext[PACKET_LENGTH-PAYLOAD_LENGTH+j] =
                    ciphertext[PACKET_LENGTH-PAYLOAD_LENGTH+j];
            }
        }
        // Now we encrypt the plaintext, which expands it by
        // AUTHENTICATIONBYTES.
        try!(crypto::sillybox_afternm(&mut ciphertext, &plaintext, auth_length,
                                      &nonce, &skeys[i]));
        {
            let mut cc = String::new();
            cc = cc + &format!("E {} ", i);
            for x in 0..ciphertext.len() {
                cc = cc + &format!("{:02x}", ciphertext[x]);
            }
            println!("{}", &cc);
        }
        {
            let mut cc = String::new();
            cc = cc + &format!("P {} ", i);
            for x in 0..32 {
                cc = cc + &format!("{:02x}", my_keypairs[i].public.0[x]);
            }
            println!("{}", &cc);
        }
        for j in auth_length-layer_overhead .. auth_length {
            assert!(ciphertext[j] == 0);
        }
    }
    let mut output = OnionBox::new();
    for i in payload_recipient..ROUTE_COUNT {
        output.keys.push(skeys[i]);
    }
    output.final_key = my_keypairs[ROUTE_COUNT-1].public;
    for j in 0..total_routing_length {
        output.packet[j] = ciphertext[j+16];
    }
    for j in 0..PAYLOAD_LENGTH {
        output.packet[total_routing_length+j] =
            ciphertext[32+auth_length+j];
    }
    println!("cb_length {} and message_length {}", cb_length, encrypted_length+32);
    Ok(output)
}

pub struct OpenedOnionBox {
    pub route: [u8; ROUTING_LENGTH],
    pub packet: [u8; PACKET_LENGTH],
    _payload: Option<[u8; PAYLOAD_LENGTH]>,
}
impl OpenedOnionBox {
    pub fn respond(&mut self, response: &[u8; PAYLOAD_LENGTH]) -> &[u8; PACKET_LENGTH] {
        for i in 0..PAYLOAD_LENGTH {
            self.packet[PACKET_LENGTH-PAYLOAD_LENGTH+i] ^= response[i];
        }
        &self.packet
    }
    pub fn payload(&self) -> Option<[u8; PAYLOAD_LENGTH]> {
        self._payload
    }
    pub fn is_for_me(&self) -> bool {
        self._payload.is_some()
    }
    pub fn is_for_relay(&self) -> bool {
        !self.is_for_me()
    }
}

/// The easy way to decrypt one layer of an onionsalt message.  Unline
/// `onionbox_open`, this function allocates memory on the heap, and
/// thus could have increased slowness.

pub fn onionbox_open_easy(_onionmessage: &[u8; PACKET_LENGTH],
                          _secret_key: &crypto::SecretKey)
                          -> Result<OpenedOnionBox,
                                    crypto::NaClError> {
    unimplemented!()
}
//     let layer_overhead = address_length + OVERHEADBYTES;
//     fn zeros(len: usize) -> Vec<u8> {
//         let mut out: Vec<u8> = vec![];
//         for _ in 0..len {
//             out.push(0);
//         }
//         out
//     }
//     // let mut ciphertext = zeros(100);
//     let mut ciphertext = zeros(onionmessage.len() + layer_overhead - 16);
//     let mut plaintext = zeros(onionmessage.len() + layer_overhead - 16);
//     for i in 0..onionmessage.len() {
//         ciphertext[i] = onionmessage[i];
//     }
//     try!(onionbox_open(&mut plaintext, &mut ciphertext, address_length, secret_key));
//     let mut output = zeros(onionmessage.len() + address_length);
//     for i in 0..output.len() {
//         output[i] = plaintext[i];
//     }
//     Ok(output)
// }

// /// Attempt to open an onionsalt message.  The `plaintext` and
// /// `ciphertext` arguments are padded and used as intermediate storage
// /// in order to avoid any heap allocations in this function (as in the
// /// C versions of NaCl).

// pub fn onionbox_open<SK: crypto::ToSecretKey>(plaintext: &mut[u8],
//                                               ciphertext: &mut[u8],
//                                               address_length: usize,
//                                               secret_key: &SK)
//                                               -> Result<(), crypto::NaClError> {
//     if plaintext.len() != ciphertext.len() {
//         return Err(crypto::NaClError::InvalidInput);
//     }
//     let cb_length = plaintext.len();
//     println!("onion opening with cb_length {}", cb_length);

//     let layer_overhead = address_length + OVERHEADBYTES;
//     let encrypted_length = cb_length - 16 - layer_overhead;
//     let transmitted_length = encrypted_length + 32;

//     // first rescue the public key
//     let mut public_key = crypto::PublicKey([0; 32]);
//     for i in 0..32 {
//         public_key.0[i] = ciphertext[i];
//     }
//     // then shift things into place for the decryption.
//     for i in (16..ciphertext.len() - 32) {
//         ciphertext[i] = ciphertext[i+16];
//     }
//     // zero out the initial padding
//     for i in 0..16 {
//         ciphertext[i] = 0;
//     }
//     // we just always use a zero nonce, since we never reuse a public
//     // key for encryption
//     let nonce = crypto::Nonce([0; 32]);

//     {
//         let mut cc = String::new();
//         cc = cc + &format!("D ? ");
//         for x in 0..ciphertext.len() {
//             cc = cc + &format!("{:02x}", ciphertext[x]);
//         }
//         println!("{}", &cc);
//     }
//     {
//         let mut cc = String::new();
//         cc = cc + &format!("P ? ");
//         for x in 0..32 {
//             cc = cc + &format!("{:02x}", public_key.0[x]);
//         }
//         println!("{}", &cc);
//     }
//     try!(crypto::box_open(plaintext, ciphertext,
//                           &nonce, &public_key, secret_key));
//     for i in 0..transmitted_length + address_length {
//         plaintext[i] = plaintext[i+32];
//     }
//     for i in transmitted_length + address_length .. cb_length {
//         plaintext[i] = 0;
//     }
//     Ok(())
// }

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn onionbox_works() {
//         let k0 = crypto::box_keypair().unwrap();
//         let k1 = crypto::box_keypair().unwrap();
//         let yu = crypto::box_keypair().unwrap();
//         let k3 = crypto::box_keypair().unwrap();
//         let k4 = crypto::box_keypair().unwrap();
//         let k5 = crypto::box_keypair().unwrap();

//         let keys_and_routes: [(crypto::PublicKey, [u8; ROUTING_LENGTH]); ROUTE_COUNT]
//             = [(k0.public, *b"12345678901234561234567890123456"),
//                (k1.public, *b"my friend is hermy friend is her"),
//                (yu.public, *b"address 3 for yoaddress 3 for yo"),
//                (k3.public, *b"another is - heranother is - her"),
//                (k4.public, *b"router here is orouter here is o"),
//                (k5.public, *b"how to get to mehow to get to me")];
//         let mut payload: [u8; PAYLOAD_LENGTH] = [0; PAYLOAD_LENGTH];
//         payload[3] = 3;
//         let payload = payload;
//         // onionbox(&keys_and_routes, &payload, 2).unwrap();
//     }
// }

//     #[allow(non_snake_case)]
//     #[test]
//     fn u8_is_ToPublicKey() {
//         use crypto::{ToPublicKey, PublicKey};
//         let x: [u8; 32] = [0; 32];
//         println!("x.public_key is {:?}", x.to_public_key());
//         let y: &[u8] = &x[0..32];
//         println!("y.public_key is {:?}", y.to_public_key());
//         println!("PublicKey::new(&x) is {:?}", PublicKey::new(&x));
//         let z = PublicKey::new(&y);
//         println!("PublicKey::new(y) is {:?}", z);
//     }

//     #[allow(non_snake_case)]
//     #[test]
//     fn u8_is_ToSecretKey() {
//         use crypto::{ToSecretKey};
//         let x: [u8; 32] = [0; 32];
//         println!("x.secret_key is {:?}", x.to_secret_key());
//         let y = &x[0..32];
//         println!("y.secret_key is {:?}", y.to_secret_key());
//     }

//     #[test]
//     fn onionbox_open_works() {
//         for n in 0..10 {
//             println!("Testing with {} routers", n);
//             onionbox_open_works_n(n);
//         }
//     }

//     fn onionbox_open_works_n(n: usize) {
//         println!("onionbox_open_works");
//         let plaintext: &[u8] = b"A test.";
//         let nrouters = n;
//         let mut keys_and_messages: Vec<(crypto::PublicKey, &[u8])> = Vec::new();
//         let mut secret_keys: Vec<crypto::SecretKey> = Vec::new();
//         let message = b"Hello world";
//         let address_length = message.len();
//         for _ in 0..nrouters {
//             let (pk, sk) = crypto::box_keypair().unwrap();
//             secret_keys.push(sk);
//             keys_and_messages.push((pk, message));
//         }
//         let (pk, sk) = crypto::box_keypair().unwrap();
//         keys_and_messages.push((pk, plaintext));
//         secret_keys.push(sk);
//         let mut ob = onionbox(address_length, &keys_and_messages).unwrap();
//         println!("ob.len() is {}", ob.len());
//         for i in 0..keys_and_messages.len() {
//             println!("Trying layer {}", i);
//             let r = onionbox_open_easy(&ob, address_length, &secret_keys[i]).unwrap();
//             if i == nrouters {
//                 assert_eq!(plaintext, &r[0..plaintext.len()]);
//                 break;
//             }
//             assert_eq!(message, &r[0..address_length]);
//             {
//                 let mut cc = String::new();
//                 cc = cc + &format!("R ? ");
//                 for x in 0 .. r.len() {
//                     cc = cc + &format!("{:02x}", r[x]);
//                 }
//                 println!("{}", &cc);
//             }
//             for i in 0..ob.len() {
//                 ob[i] = r[i+address_length];
//             }
//             println!("Got {} working", i);
//         }
//     }
// }





/// Encrypt a message in an onion directed to `their_public_keys`
/// recipients.
pub fn onionbox_algorithm<T: bytes::SelfDocumenting>(buffer: &mut T,
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

    let total_routing_length = ROUTE_COUNT*ROUTING_OVERHEAD;
    let auth_length = total_routing_length + ROUTING_OVERHEAD;
    buffer.annotate(&format!("Starting with buffer of zeros."));

    for i in 0..ROUTE_COUNT {
        buffer.sillybox_afternm(auth_length, &nonce, &skeys[i],
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
        buffer.sillybox_afternm(auth_length, &nonce, &skeys[i],
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

/// The buffer already contains the message, and contains the next message
/// on exit.
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
                     &vec![0;ROUTING_OVERHEAD],
                     "0");
    buffer.annotate(&format!("Extract the public key and insert zeros"));

    let auth_length = (ROUTE_COUNT+1)*ROUTING_OVERHEAD;
    let skey = try!(crypto::sillybox_beforenm(pk, secret_key));
    try!(buffer.sillybox_open_afternm(auth_length, &crypto::Nonce([0;32]), &skey));
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


pub fn onionbox_insert_payload_algorithm<T: bytes::SelfDocumenting>(buffer: &mut T,
                                                                    payload: &[u8; PAYLOAD_LENGTH]) {
    buffer.set_bytes(bytes::BUFSIZE - PAYLOAD_LENGTH - 32 - ROUTING_LENGTH,
                     PAYLOAD_LENGTH, payload, "Response");
    buffer.annotate(&format!("Add response payload"));
}
