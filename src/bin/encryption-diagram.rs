extern crate onionsalt;

use onionsalt::*;

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
    println!("{}", diagram.postscript());
    // println!("\n\n{}", diagram.asciiart());
}
