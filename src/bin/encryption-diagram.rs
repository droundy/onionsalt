extern crate onionsalt;

use onionsalt::*;
use std::fs::File;
use std::io::prelude::*;
use onionsalt::bytes::{SelfDocumenting};

fn main() {
    let mut diagram = bytes::Diagram::new();

    let pairs = [crypto::box_keypair().unwrap(),
                 crypto::box_keypair().unwrap(),
                 crypto::box_keypair().unwrap(),
                 crypto::box_keypair().unwrap(),
                 crypto::box_keypair().unwrap(),
                 crypto::box_keypair().unwrap()];
    let your_key = pairs[2];

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
    onionbox_algorithm(&mut diagram, &keys_and_routes, &payload, 2);

    let mut f = File::create("paper/encryption.eps").unwrap();
    f.write_all(diagram.postscript().as_bytes()).unwrap();
    // println!("\n\n{}", diagram.asciiart());

    for i in 0..6 {
        diagram.clear();

        diagram.annotate(&format!("Message as received"));
        let route = onionbox_open_algorithm(&mut diagram, &pairs[i].secret).unwrap();
        assert_eq!(route.0, keys_and_routes[i].1);

        if i == 2 {
            // We are the recipient!
            let mut response: [u8; PAYLOAD_LENGTH] = [0; PAYLOAD_LENGTH];
            for j in 0..PAYLOAD_LENGTH {
                response[j] = j as u8;
            }
            route.1(&mut diagram, &response);
        }

        let mut f = File::create(&format!("paper/decryption-{}.eps", i)).unwrap();
        f.write_all(diagram.postscript().as_bytes()).unwrap();
    }
}
