pub mod tweetnacl {

    #[test]
    fn it_works() {
    }

    static _0: [u8; 16] = [0; 16];
    static _9: [u8; 32] = [9; 32];

    type GF = [i64; 16];
    static GF0: GF = [0; 16];
    static GF1: GF = [1; 16];
    static _121665: GF = [0xDB41,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1];
    static D: GF = [0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070,
                    0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203];
    static D2: GF = [0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
                     0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406];
    static X: GF = [0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
                    0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169];
    static Y: GF = [0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
                    0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666];
    static I: GF = [0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43,
                    0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83];

    fn l32(x: u32, c: i32) -> u32 {
        (x << c) | ((x&0xffffffff) >> (32 - c))
    }

    fn ld32(x: &[u8]) -> u32 {
        let mut u= x[3] as u32;
        u = (u<<8)|x[2] as u32;
        u = (u<<8)|x[1] as u32;
        (u<<8)|x[0] as u32
    }

    fn dl64(x: &[u8]) -> u64 {
        let mut u: u64 = 0;
        for i in 0..8 {
            u = (u<<8)|x[i] as u64;
        }
        u
    }

    fn st32(x: &mut[u8], mut u: u32) {
        for i in 0..4 {
            x[i] = u as u8;
            u >>= 8;
        }
    }

    fn ts64(x: &mut[u8], mut u: u64) {
        for i in 0..8 {
            x[i] = u as u8; u >>= 8;
        }
    }

    fn vn(x: &[u8], y: &[u8], n: usize) -> i32 {
        let mut d: u32 = 0;
        for i in 0..n {
            d |= (x[i]^y[i]) as u32;
        }
        (1 & ((d - 1) >> 8)) as i32 - 1
    }

    fn crypto_verify_16(x: &[u8], y: &[u8]) -> i32 {
        vn(x,y,16)
    }

    fn crypto_verify_32(x: &[u8], y: &[u8]) -> i32 {
        vn(x,y,32)
    }

    fn core(out: &mut[u8], inp: &[u8], k: &[u8], c: &[u8], h: bool) {
        let mut x: [u32; 16] = [0; 16];
        for i in 0..4 {
            x[5*i] = ld32(&c[4*i..]);
            x[1+i] = ld32(&k[4*i..]);
            x[6+i] = ld32(&inp[4*i..]);
            x[11+i] = ld32(&k[16+4*i..]);
        }

        let mut y: [u32; 16] = [0; 16];
        for i in 0..16 {
            y[i] = x[i];
        }

        let mut w: [u32; 16] = [0; 16];
        let mut t: [u32; 4] = [0; 4];
        for _ in 0..20 {
            for j in 0..4 {
                for m in 0..4 {
                    t[m] = x[(5*j+4*m)%16];
                }
                t[1] ^= l32(t[0]+t[3], 7);
                t[2] ^= l32(t[1]+t[0], 9);
                t[3] ^= l32(t[2]+t[1],13);
                t[0] ^= l32(t[3]+t[2],18);
                for m in 0..4 {
                    w[4*j+(j+m)%4] = t[m];
                }
            }
            for m in 0..16 {
                x[m] = w[m];
            }
        }

        if h {
            for i in 0..16 {
                x[i] += y[i];
            }
            for i in 0..4 {
                x[5*i] -= ld32(&c[4*i..]);
                x[6+i] -= ld32(&inp[4*i..]);
            }
            for i in 0..4 {
                st32(&mut out[4*i..],x[5*i]);
                st32(&mut out[16+4*i..],x[6+i]);
            }
        } else {
            for i in 0..16 {
                st32(&mut out[4 * i..],x[i] + y[i]);
            }
        }
    }

    pub fn crypto_core_salsa20(out: &mut[u8], inp: &[u8], k: &[u8], c: &[u8]) -> i32 {
        core(out,inp,k,c,false);
        0
    }

    pub fn crypto_core_hsalsa20(out: &mut[u8], inp: &[u8], k: &[u8], c: &[u8]) -> i32 {
        core(out,inp,k,c,true);
        0
    }

    static sigma: &'static [u8; 16] = b"expand 32-byte k";

    fn crypto_stream_salsa20_xor(c: &mut[u8], m_input: &[u8], mut b: u64,
                                 n: &[u8], k: &[u8]) -> i32 {
        let mut m_offset: usize = 0;
        if b == 0 {
            return 0;
        }
        let mut z: [u8; 16] = [0; 16];
        for i in 0..8 {
            z[i] = n[i];
        }
        let mut x: [u8; 64] = [0; 64];
        let mut c_offset: usize = 0;
        while b >= 64 {
            crypto_core_salsa20(&mut x,&z,k,sigma);
            for i in 0..64 {
                // The following is really ugly.  I wish I could
                // define this closure just once and have it used
                // throughout.  Also note the ugly duplication of code
                // below.  :(
                let m = |i: usize| {
                    if m_offset + i > m_input.len() {
                        0
                    } else {
                        m_input[m_offset+i]
                    }
                };
                c[c_offset + i] = m(i) ^ x[i];
            }
            let mut u: u64 = 1;
            for i in 8..16 {
                u += z[i] as u64;
                z[i] = u as u8;
                u >>= 8;
            }
            b -= 64;
            c_offset += 64;
            m_offset += 64;
        }

        let m = |i: usize| {
            if m_offset + i > m_input.len() {
                0
            } else {
                m_input[m_offset+i]
            }
        };
        if b != 0 {
            crypto_core_salsa20(&mut x,&z,k,sigma);
            for i in 0..b as usize {
                c[c_offset + i] = m(i) ^ x[i];
            }
        }
        0
    }
}
