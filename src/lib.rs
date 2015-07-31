//! The onionsalt crate.

extern crate rand;

pub mod crypto;

const AUTHENTICATIONBYTES: usize = 16;

/// The number of extra bytes needed per recipient.
pub const LAYEROVERHEADBYTES: usize = AUTHENTICATIONBYTES + 32;

/// The number of bytes needed in the buffer per recipient.
pub const PERLAYERBUFFERBYTES: usize = LAYEROVERHEADBYTES + 64;

use std::vec::Vec;

/// Encrypt a message in an onion directed to `their_public_keys`
/// recipients.
pub fn onion_box(keys_and_messages: &[(crypto::PublicKey, &[u8])])
                 -> Result<Vec<u8>, crypto::NaClError> {
    let num_layers = keys_and_messages.len();
    let address_length = keys_and_messages[0].1.len();
    for i in 0..num_layers-1 {
        // All the addresses must be the same length.
        if keys_and_messages[i].1.len() != address_length {
            return Err(crypto::NaClError::InvalidInput);
        }
    }
    let secret_length = keys_and_messages[keys_and_messages.len()-1].1.len();

    // layer_overhead is the amount of space needed for each
    // additional layer.  This ends up being equal to the amount of
    // zero padding that we have to add to the end.
    let layer_overhead = address_length + LAYEROVERHEADBYTES;
    // message_length is the length of the transmitted message.
    let encrypted_length = secret_length + AUTHENTICATIONBYTES
        + (num_layers-1)*layer_overhead;
    // cb_length is the length that we always pass to crypto_box.  It
    // corresponds to encrypted_length plus one layer_overhead (filled
    // with zeros at the end) plus crypto_box_BOXZEROBYTES.
    let cb_length = 16 + encrypted_length + layer_overhead;

    let mut ciphertext: Vec<u8> = Vec::with_capacity(cb_length);
    let mut plaintext: Vec<u8> = Vec::with_capacity(cb_length);
    for _ in 0..cb_length {
        ciphertext.push(0);
        plaintext.push(0);
    }

    // We always use a zero nonce.
    let nonce = crypto::Nonce([0; 32]);

    // Here we create buffers for my_public_keys, my_private_keys, and
    // our plaintext.
    let mut my_public_keys: Vec<crypto::PublicKey> =
        Vec::with_capacity(num_layers);
    let mut my_secret_keys: Vec<crypto::SecretKey> =
        Vec::with_capacity(num_layers);
    for _ in 0..num_layers {
        let (pk, sk) = try!(crypto::box_keypair());
        my_public_keys.push(pk);
        my_secret_keys.push(sk);
    }

    for i in 0..num_layers {
        try!(crypto::box_up(&mut ciphertext, &plaintext, &nonce,
                            &keys_and_messages[i].0,
                            &my_secret_keys[i]));
        if i == num_layers - 1 { break; }
        for j in 0..cb_length - 32 - layer_overhead {
            plaintext[j+32] = ciphertext[j+32+layer_overhead];
        }
    }
    for j in 0..cb_length-32 {
        plaintext[j+32] = ciphertext[j+32];
    }
    // At this stage, plaintext should be set up for the innermost
    // layer of the onion, with everything but the actual plaintext
    // that we want.
    for i in (0..num_layers).rev() {
        // Now we add the true message!
        for j in 0..keys_and_messages[i].1.len() {
            plaintext[j+32] = keys_and_messages[i].1[j];
        }
        if i != num_layers-1 {
            for j in 0..32 {
                plaintext[j+32+address_length] = my_public_keys[i+1].0[j];
            }
        }
        // Now we encrypt the plaintext, which expands it just a tad
        try!(crypto::box_up(&mut ciphertext, &plaintext, &nonce,
                            &keys_and_messages[i].0,
                            &my_secret_keys[i]));
        for j in cb_length-layer_overhead .. cb_length {
            assert!(ciphertext[j] == 0);
        }
        if i == 0 { break; }
        // Now shift things to the right to make room for the next
        // address and public key.
        for j in 0 .. cb_length - layer_overhead {
            plaintext[j+layer_overhead] = ciphertext[j];
        }
        for j in 0..32 {
            plaintext[j] = 0;
        }
    }
    for j in (0 .. cb_length - layer_overhead).rev() {
        ciphertext[j+16] = ciphertext[j];
    }
    for j in 0..32 {
        ciphertext[j] = my_public_keys[0].0[j];
    }
    ciphertext.truncate(encrypted_length + 32);
    Ok(ciphertext)
}

/// Attempt to open an onionsalt message.

pub fn onion_box_open(plaintext: &mut[u8],
                      ciphertext: &mut[u8],
                      address_length: usize,
                      secret_key: &crypto::SecretKey)
                      -> Result<(), crypto::NaClError> {
    if plaintext.len() != ciphertext.len() {
        return Err(crypto::NaClError::InvalidInput);
    }
    let cb_length = plaintext.len();

    let layer_overhead = address_length + LAYEROVERHEADBYTES;
    let encrypted_length = cb_length - 16 - layer_overhead;
    let transmitted_length = encrypted_length + 32;

    // first rescue the public key
    let mut public_key = crypto::PublicKey([0; 32]);
    for i in 0..32 {
        public_key.0[i] = ciphertext[i];
    }
    // then shift things into place for the decryption.
    for i in (16..ciphertext.len() - 16).rev() {
        ciphertext[i+16] = ciphertext[i];
    }
    // zero out the initial padding
    for i in 0..16 {
        ciphertext[i] = 0;
    }
    // we just always use a zero nonce, since we never reuse a public
    // key for encryption
    let nonce = crypto::Nonce([0; 32]);

    try!(crypto::box_open(plaintext, ciphertext,
                          &nonce, &public_key, secret_key));
    for i in 0..transmitted_length + address_length {
        plaintext[i] = plaintext[i+32];
    }
    for i in transmitted_length + address_length .. cb_length {
        plaintext[i] = 0;
    }
    Ok(())
}
