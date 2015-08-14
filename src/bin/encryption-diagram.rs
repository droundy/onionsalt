extern crate onionsalt;

use onionsalt::*;
use std::fs::File;
use std::io::prelude::*;
use onionsalt::bytes::{SelfDocumenting};

fn main() {
    let mut diagram = bytes::Diagram::new();

    let k0 = crypto::box_keypair().unwrap();
    let k1 = crypto::box_keypair().unwrap();
    let yu = crypto::box_keypair().unwrap();
    let k3 = crypto::box_keypair().unwrap();
    let k4 = crypto::box_keypair().unwrap();
    let k5 = crypto::box_keypair().unwrap();

    let keys_and_routes: [(crypto::PublicKey, [u8; ROUTING_LENGTH]); ROUTE_COUNT]
                           = [(k0.public, *b"123456789012345612345678"),
                              (k1.public, *b"my friend is hermy frien"),
                              (yu.public, *b"address 3 for yoaddress "),
                              (k3.public, *b"another is - heranother "),
                              (k4.public, *b"router here is orouter h"),
                              (k5.public, *b"how to get to mehow to g")];
    let mut payload: [u8; PAYLOAD_LENGTH] = [0; PAYLOAD_LENGTH];
    payload[3] = 3;
    let payload = payload;
    onionbox_algorithm(&mut diagram, &keys_and_routes, &payload, 2);

    let mut f = File::create("paper/encryption.eps").unwrap();
    f.write_all(diagram.postscript().as_bytes()).unwrap();
    // println!("\n\n{}", diagram.asciiart());

    diagram.clear();

    let route = onionbox_open_algorithm(&mut diagram, &k0.secret).unwrap();
    assert_eq!(route, keys_and_routes[0].1);

    let mut f = File::create("paper/decryption-0.eps").unwrap();
    f.write_all(diagram.postscript().as_bytes()).unwrap();

    diagram.clear();

    let route = onionbox_open_algorithm(&mut diagram, &k1.secret).unwrap();
    assert_eq!(route, keys_and_routes[1].1);

    let mut f = File::create("paper/decryption-1.eps").unwrap();
    f.write_all(diagram.postscript().as_bytes()).unwrap();

    diagram.clear();
}
