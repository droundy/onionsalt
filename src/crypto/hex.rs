
pub fn bytes_32(bytes: &[u8;64]) -> Option<[u8;32]> {
    let mut out = [0;32];
    for i in 0 .. 32 {
        match hex_to_u8(array_ref![bytes,2*i,2]) {
            None => { return None; },
            Some(b) => {
                out[i] = b;
            },
        }
    }
    Some(out)
}
pub fn bytes_24(bytes: &[u8;48]) -> Option<[u8;24]> {
    let mut out = [0;24];
    for i in 0 .. 24 {
        match hex_to_u8(array_ref![bytes,2*i,2]) {
            None => { return None; },
            Some(b) => {
                out[i] = b;
            },
        }
    }
    Some(out)
}
pub fn hex_to_u8(bytes: &[u8;2]) -> Option<u8> {
    match (hexit_to_u8(bytes[0]), hexit_to_u8(bytes[1])) {
        (Some(b1), Some(b2)) => Some(b2 + (b1 << 4)),
        _ => None
    }
}

pub fn hexit_to_u8(hexit: u8) -> Option<u8> {
    match hexit {
        b'0' ... b'9' => Some(hexit - b'0'),
        b'a' ... b'f' => Some(hexit - b'a' + 10),
        _ => None,
    }
}

#[test]
fn test_hexit() {
    assert_eq!(hexit_to_u8(b'0'), Some(0x0));
    assert_eq!(hexit_to_u8(b'1'), Some(0x1));
    assert_eq!(hexit_to_u8(b'2'), Some(0x2));
    assert_eq!(hexit_to_u8(b'3'), Some(0x3));
    assert_eq!(hexit_to_u8(b'4'), Some(0x4));
    assert_eq!(hexit_to_u8(b'5'), Some(0x5));
    assert_eq!(hexit_to_u8(b'6'), Some(0x6));
    assert_eq!(hexit_to_u8(b'7'), Some(0x7));
    assert_eq!(hexit_to_u8(b'8'), Some(0x8));
    assert_eq!(hexit_to_u8(b'9'), Some(0x9));
    assert_eq!(hexit_to_u8(b'a'), Some(0xa));
    assert_eq!(hexit_to_u8(b'b'), Some(0xb));
    assert_eq!(hexit_to_u8(b'c'), Some(0xc));
    assert_eq!(hexit_to_u8(b'd'), Some(0xd));
    assert_eq!(hexit_to_u8(b'e'), Some(0xe));
    assert_eq!(hexit_to_u8(b'f'), Some(0xf));
}
