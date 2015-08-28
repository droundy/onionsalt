use super::*;
use super::bytes;
use super::{onionbox_insert_response_algorithm,
            onionbox_algorithm,
            onionbox_open_algorithm};
use std::fs::File;
use std::io::prelude::*;
use super::bytes::{SelfDocumenting};

pub fn shouldbeprivate() {
    create_big_diagram();
    create_short_diagram();
}

fn create_short_diagram() {
    let mut diagram = bytes::Diagram::new();
    let mut return_key = bytes::Diagram::new();

    let pairs = [crypto::box_keypair().unwrap(),
                 crypto::box_keypair().unwrap(),
                 crypto::box_keypair().unwrap()];

    let keys_and_routes = [(pairs[0].public, *b"123456789012345612345678"),
                           (pairs[1].public, *b"my friend is hermy frien"),
                           (pairs[2].public, *b"address 3 for yoaddress ")];
    let recipient = 1;
    onionbox_algorithm(&mut diagram, &mut return_key, &keys_and_routes, recipient).unwrap();

    for i in 0..pairs.len() {
        diagram.annotate(&format!("Message as received by {}", i));
        let route = onionbox_open_algorithm(&mut diagram, &pairs[i].secret).unwrap();
        assert_eq!(route, keys_and_routes[i].1);

        if i == recipient {
            // We are the recipient!
            let mut response: [u8; ENCRYPTEDPAYLOAD_LENGTH] = [0; ENCRYPTEDPAYLOAD_LENGTH];
            for j in 0..PAYLOAD_LENGTH {
                response[j] = j as u8;
            }
            onionbox_insert_response_algorithm(&mut diagram, &response);
        }
    }
    let mut f = File::create("paper/short-onion.eps").unwrap();
    f.write_all(diagram.postscript().as_bytes()).unwrap();
}

fn create_big_diagram() {
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

    let mut f = File::create("paper/encryption.eps").unwrap();
    f.write_all(diagram.postscript().as_bytes()).unwrap();
    // println!("\n\n{}", diagram.asciiart());

    f = File::create("paper/return-key.eps").unwrap();
    f.write_all(return_key.postscript().as_bytes()).unwrap();

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

        let mut f = File::create(&format!("paper/decryption-{}.eps", i)).unwrap();
        f.write_all(diagram.postscript().as_bytes()).unwrap();
    }
}
