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
pub fn onionbox(keys_and_messages: &[(crypto::PublicKey, &[u8])])
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
                cc = cc + &format!("{:02x}", my_public_keys[i].0[x]);
            }
            println!("{}", &cc);
        }
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
    println!("cb_length {} and message_length {}", cb_length, encrypted_length+32);
    Ok(ciphertext)
}

#[test]
fn onionbox_works() {
    let plaintext: &[u8] = b"This is only a test.";
    let nrouters = 5;
    let mut keys_and_messages: Vec<(crypto::PublicKey, &[u8])> = Vec::new();
    for _ in 0..nrouters {
        let (pk, _) = crypto::box_keypair().unwrap();
        let message = b"Hello world";
        keys_and_messages.push((pk, message));
    }
    let (pk, _) = crypto::box_keypair().unwrap();
    keys_and_messages.push((pk, plaintext));
    onionbox(&keys_and_messages).unwrap();
}

pub fn onionbox_open_easy(onionmessage: &[u8], address_length: usize,
                          secret_key: &crypto::SecretKey)
                          -> Result<Vec<u8>, crypto::NaClError> {
    let layer_overhead = address_length + LAYEROVERHEADBYTES;
    fn zeros(len: usize) -> Vec<u8> {
        let mut out: Vec<u8> = vec![];
        for _ in 0..len {
            out.push(0);
        }
        out
    }
    // let mut ciphertext = zeros(100);
    let mut ciphertext = zeros(onionmessage.len() + layer_overhead - 16);
    let mut plaintext = zeros(onionmessage.len() + layer_overhead - 16);
    for i in 0..onionmessage.len() {
        ciphertext[i] = onionmessage[i];
    }
    try!(onionbox_open(&mut plaintext, &mut ciphertext, address_length, secret_key));
    let mut output = zeros(onionmessage.len() + address_length);
    for i in 0..output.len() {
        output[i] = plaintext[i];
    }
    Ok(output)
}

/// Attempt to open an onionsalt message.

pub fn onionbox_open(plaintext: &mut[u8],
                     ciphertext: &mut[u8],
                     address_length: usize,
                     secret_key: &crypto::SecretKey)
                     -> Result<(), crypto::NaClError> {
    if plaintext.len() != ciphertext.len() {
        return Err(crypto::NaClError::InvalidInput);
    }
    let cb_length = plaintext.len();
    println!("onion opening with cb_length {}", cb_length);

    let layer_overhead = address_length + LAYEROVERHEADBYTES;
    let encrypted_length = cb_length - 16 - layer_overhead;
    let transmitted_length = encrypted_length + 32;

    // first rescue the public key
    let mut public_key = crypto::PublicKey([0; 32]);
    for i in 0..32 {
        public_key.0[i] = ciphertext[i];
    }
    // then shift things into place for the decryption.
    for i in (16..ciphertext.len() - 32) {
        ciphertext[i] = ciphertext[i+16];
    }
    // zero out the initial padding
    for i in 0..16 {
        ciphertext[i] = 0;
    }
    // we just always use a zero nonce, since we never reuse a public
    // key for encryption
    let nonce = crypto::Nonce([0; 32]);

    {
        let mut cc = String::new();
        cc = cc + &format!("D ? ");
        for x in 0..ciphertext.len() {
            cc = cc + &format!("{:02x}", ciphertext[x]);
        }
        println!("{}", &cc);
    }
    {
        let mut cc = String::new();
        cc = cc + &format!("P ? ");
        for x in 0..32 {
            cc = cc + &format!("{:02x}", public_key.0[x]);
        }
        println!("{}", &cc);
    }
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

#[test]
fn onionbox_open_works() {
    println!("onionbox_open_works");
    let plaintext: &[u8] = b"A test.";
    let nrouters = 1;
    let mut keys_and_messages: Vec<(crypto::PublicKey, &[u8])> = Vec::new();
    let mut secret_keys: Vec<crypto::SecretKey> = Vec::new();
    let message = b"Hello world";
    let address_length = message.len();
    for _ in 0..nrouters {
        let (pk, sk) = crypto::box_keypair().unwrap();
        secret_keys.push(sk);
        keys_and_messages.push((pk, message));
    }
    let (pk, sk) = crypto::box_keypair().unwrap();
    keys_and_messages.push((pk, plaintext));
    secret_keys.push(sk);
    let mut ob = onionbox(&keys_and_messages).unwrap();
    println!("ob.len() is {}", ob.len());
    for i in 0..keys_and_messages.len() {
        println!("Trying layer {}", i);
        let r = onionbox_open_easy(&ob, address_length, &secret_keys[i]).unwrap();
        if i == nrouters {
            break;
        }
        assert_eq!(message, &r[0..address_length]);
        {
            let mut cc = String::new();
            cc = cc + &format!("R ? ");
            for x in 0 .. r.len() {
                cc = cc + &format!("{:02x}", r[x]);
            }
            println!("{}", &cc);
        }
        for i in 0..ob.len() {
            ob[i] = r[i+address_length];
        }
        println!("Got {} working", i);
    }
}
