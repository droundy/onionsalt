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

    fn vn(x: &[u8], y: &[u8], n: usize) -> Result<(), NaClError> {
        let mut d: u32 = 0;
        for i in 0..n {
            d |= (x[i]^y[i]) as u32;
        }
        if (1 & ((d - 1) >> 8)) as i32 - 1 != 0 {
            Err(NaClError::AuthFailed)
        } else {
            Ok(())
        }
    }

    fn crypto_verify_16(x: &[u8], y: &[u8]) -> Result<(), NaClError> {
        vn(x,y,16)
    }

    fn crypto_verify_32(x: &[u8], y: &[u8]) -> Result<(), NaClError> {
        vn(x,y,32)
    }

    fn core(inp: &[u8], k: &[u8], c: &[u8], h: bool)
            -> Result<[u8; 64], NaClError> {
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

        let mut out: [u8; 64] = [0; 64];
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
        Ok(out)
    }

    fn crypto_core_salsa20(inp: &[u8], k: &[u8], c: &[u8])
                           -> Result<[u8; 64], NaClError> {
        core(inp,k,c,false)
    }

    fn crypto_core_hsalsa20(inp: &[u8], k: &[u8], c: &[u8])
                            -> Result<[u8; 64], NaClError> {
        core(inp,k,c,true)
    }

    static SIGMA: &'static [u8; 16] = b"expand 32-byte k";

    fn crypto_stream_salsa20_xor(c: &mut[u8], m_input: &[u8], mut b: u64,
                                 n: &[u8], k: &[u8])
                                 -> Result<(), NaClError> {
        let mut m_offset: usize = 0;
        if b == 0 {
            return Err(NaClError::InvalidInput);
        }
        let mut z: [u8; 16] = [0; 16];
        for i in 0..8 {
            z[i] = n[i];
        }
        let mut c_offset: usize = 0;
        while b >= 64 {
            let x = try!(crypto_core_salsa20(&z,k,SIGMA));
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
            let x = try!(crypto_core_salsa20(&z,k,SIGMA));
            for i in 0..b as usize {
                c[c_offset + i] = m(i) ^ x[i];
            }
        }
        Ok(())
    }


    fn crypto_stream_salsa20(c: &mut[u8], d: u64, n: &[u8], k: &[u8])
                             -> Result<(), NaClError> {
        crypto_stream_salsa20_xor(c,&[],d,n,k)
    }

    // crypto_stream_32 is a modified version of crypto_stream, which
    // always has a fixed length of 32, and returns its output.  We
    // don't need an actual crypto_stream, since it is only used once
    // in tweetnacl.
    pub fn crypto_stream_32(n: &[u8], k: &[u8])
                            -> Result<[u8; 32], NaClError> {
        let s = try!(crypto_core_hsalsa20(n,k,SIGMA));
        let mut c: [u8; 32] = [0; 32];
        try!(crypto_stream_salsa20(&mut c,32,&n[16..],&s));
        Ok(c)
    }

    pub fn crypto_stream_xor(c: &mut[u8], m: &[u8], d: u64, n: &[u8], k: &[u8])
                             -> Result<(), NaClError> {
        let s = try!(crypto_core_hsalsa20(n,k,SIGMA));
        crypto_stream_salsa20_xor(c,m,d,&n[16..],&s)
    }

    fn add1305(h: &mut[u32], c: &[u32]) {
        let mut u: u32 = 0;
        for j in 0..17 {
            u += h[j] + c[j];
            h[j] = u & 255;
            u >>= 8;
        }
    }

    static MINUSP: &'static [u32; 17] = &[5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252];

    // We derive `Debug` because all types should probably derive `Debug`.
    // This gives us a reasonable human readable description of `CliError` values.
    #[derive(Debug)]
    pub enum NaClError {
        AuthFailed,
        InvalidInput,
    }

    fn crypto_onetimeauth(mut m: &[u8], mut n: u64, k: &[u8])
                          -> Result<[u8; 16], NaClError> {
        //u32 s,i,j,u,x[17],r[17],h[17],c[17],g[17];

        let x: &mut[u32; 17] = &mut [0; 17];
        let r: &mut[u32; 17] = &mut [0; 17];
        let h: &mut[u32; 17] = &mut [0; 17];
        for j in 0..16 {
            r[j]=k[j] as u32;
        }
        r[3]&=15;
        r[4]&=252;
        r[7]&=15;
        r[8]&=252;
        r[11]&=15;
        r[12]&=252;
        r[15]&=15;

        let mut c: &mut[u32; 17] = &mut [0; 17];
        let mut g: &mut[u32; 17] = &mut [0; 17];
        while n > 0 {
            for j in 0..17 {
                c[j] = 0;
            }
            let nor16: usize = if n < 16 { n } else { 16 } as usize;
            for j in 0..nor16 {
                c[j] = m[j] as u32;
            }
            c[nor16] = 1;
            m = &m[nor16..];
            n -= nor16 as u64;
            add1305(h,c);
            for i in 0..17 {
                x[i] = 0;
                for j in 0..17 {
                    x[i] += h[j] * (if j <= i { r[i - j] } else { 320 * r[i + 17 - j]});
                }
            }
            for i in 0..17 {
                h[i] = x[i];
            }
            let mut u: u32 = 0;
            for j in 0..16 {
                u += h[j];
                h[j] = u & 255;
                u >>= 8;
            }
            u += h[16];
            h[16] = u & 3;
            u = 5 * (u >> 2);
            for j in 0..16 {
                u += h[j];
                h[j] = u & 255;
                u >>= 8;
            }
            u += h[16];
            h[16] = u;
        }

        for j in 0..17 {
            g[j] = h[j];
        }
        add1305(h,MINUSP);
        let s: u32 = (-((h[16] >> 7) as i32)) as u32;
        for j in 0..17 {
            h[j] ^= s & (g[j] ^ h[j]);
        }

        for j in 0..16 {
            c[j] = k[j + 16] as u32;
        }
        c[16] = 0;
        add1305(h,c);
        let mut out: [u8; 16] = [0; 16];
        for j in 0..16 {
            out[j] = h[j] as u8;
        }
        Ok(out)
    }

    pub fn crypto_onetimeauth_verify(h: &[u8], m: &[u8], n: u64, k: &[u8])
                                     -> Result<(), NaClError> {
        let x = try!(crypto_onetimeauth(m,n,k));
        crypto_verify_16(h,&x)
    }

    fn crypto_secretbox(c: &mut[u8], m: &[u8], d: u64, n: &[u8], k: &[u8])
                        -> Result<(), NaClError> {
        if d < 32 {
            return Err(NaClError::InvalidInput);
        }
        try!(crypto_stream_xor(c,m,d,n,k));
        let h = try!(crypto_onetimeauth(&c[32..],d - 32,c));
        for i in 0..16 {
            c[i] = 0;
        }
        // The following loop is additional overhead beyond what the C
        // version of the code does, which results from my choice to
        // use a return array rather than a mut slice argument for
        // "core" above.
        for i in 16..32 {
            c[16+i] = h[i];
        }
        Ok(())
    }

    fn crypto_secretbox_open(m: &mut[u8], c: &[u8], d: u64, n: &[u8], k: &[u8])
                             -> Result<(), NaClError> {
        if d < 32 {
            return Err(NaClError::InvalidInput);
        }
        let x = try!(crypto_stream_32(n,k));
        try!(crypto_onetimeauth_verify(&c[16..],&c[32..],d - 32,&x));
        try!(crypto_stream_xor(m,c,d,n,k));
        for i in 0..32 {
            m[i] = 0;
        }
        Ok(())
    }

}
