#![deny(warnings)]

extern crate onionsalt;

use onionsalt::*;
use std::fs::File;
use std::io::prelude::*;
use onionsalt::bytes::{SelfDocumenting};

#[allow(dead_code)]
fn main() {
    create_big_diagram();
    create_short_diagram();
}

#[allow(dead_code)]
fn create_short_diagram() {
    let mut diagram = bytes::Diagram::new();
    let mut return_key = bytes::Diagram::new();

    let pairs = [crypto::box_keypair().unwrap(),
                 crypto::box_keypair().unwrap(),
                 crypto::box_keypair().unwrap()];

    let keys_and_routes = [(pairs[0].public, *b"123456789012345612345678"),
                           (pairs[1].public, *b"my friend is hermy frien"),
                           (pairs[2].public, *b"address 3 for yoaddress ")];
    let mut payload: [u8; PAYLOAD_LENGTH] = [0; PAYLOAD_LENGTH];
    let recipient = 1;
    payload[3] = 3;
    let payload = payload;
    onionbox_algorithm(&mut diagram, &mut return_key, &keys_and_routes, &payload, recipient).unwrap();

    for i in 0..pairs.len() {
        diagram.annotate(&format!("Message as received by {}", i));
        let route = onionbox_open_algorithm(&mut diagram, &pairs[i].secret).unwrap();
        assert_eq!(route, keys_and_routes[i].1);

        if i == recipient {
            // We are the recipient!
            let mut response: [u8; PAYLOAD_LENGTH] = [0; PAYLOAD_LENGTH];
            for j in 0..PAYLOAD_LENGTH {
                response[j] = j as u8;
            }
            onionbox_insert_payload_algorithm(&mut diagram, &response);
        }
    }
    let mut f = File::create("paper/short-onion.eps").unwrap();
    f.write_all(diagram.postscript().as_bytes()).unwrap();
}

#[allow(dead_code)]
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
    let mut payload: [u8; PAYLOAD_LENGTH] = [0; PAYLOAD_LENGTH];
    payload[3] = 3;
    let payload = payload;
    onionbox_algorithm(&mut diagram, &mut return_key, &keys_and_routes, &payload, 2).unwrap();

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
            let mut response: [u8; PAYLOAD_LENGTH] = [0; PAYLOAD_LENGTH];
            for j in 0..PAYLOAD_LENGTH {
                response[j] = j as u8;
            }
            onionbox_insert_payload_algorithm(&mut diagram, &response);
        }

        let mut f = File::create(&format!("paper/decryption-{}.eps", i)).unwrap();
        f.write_all(diagram.postscript().as_bytes()).unwrap();
    }
}
