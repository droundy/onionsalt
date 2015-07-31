extern crate rand;

pub mod tweetnacl {

    use std::num::Wrapping;
    fn unwrap<T>(x: Wrapping<T>) -> T {
        let Wrapping(x) = x;
        x
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

    fn l32(x: Wrapping<u32>, c: usize) -> Wrapping<u32> {
        (x << c) | ((x&Wrapping(0xffffffff)) >> (32 - c))
    }

    fn ld32(x: &[u8]) -> Wrapping<u32> {
        let mut u= Wrapping(x[3] as u32);
        u = (u<<8)|Wrapping(x[2] as u32);
        u = (u<<8)|Wrapping(x[1] as u32);
        (u<<8)|Wrapping(x[0] as u32)
    }

    fn dl64(x: &[u8]) -> u64 {
        let mut u = Wrapping(0 as u64);
        for i in 0..8 {
            u = (u<<8)|Wrapping(x[i] as u64);
        }
        let Wrapping(u) = u;
        u
    }

    fn st32(x: &mut[u8], mut u: Wrapping<u32>) {
        for i in 0..4 {
            x[i] = unwrap(u) as u8;
            u = u >> 8;
        }
    }

    fn ts64(x: &mut[u8], mut u: u64) {
        for i in 0..8 {
            x[i] = u as u8; u >>= 8;
        }
    }

    fn vn(x: &[u8], y: &[u8], n: usize) -> Result<(), NaClError> {
        let mut d: Wrapping<u32> = Wrapping(0);
        for i in 0..n {
            d = d | Wrapping((x[i]^y[i]) as u32);
        }
        if unwrap(Wrapping(1) & ((d - Wrapping(1)) >> 8)) as i32 - 1 != 0 {
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
        let mut x: [Wrapping<u32>; 16] = [Wrapping(0); 16];
        for i in 0..4 {
            x[5*i] = ld32(&c[4*i..]);
            x[1+i] = ld32(&k[4*i..]);
            x[6+i] = ld32(&inp[4*i..]);
            x[11+i] = ld32(&k[16+4*i..]);
        }

        let mut y: [Wrapping<u32>; 16] = [Wrapping(0); 16];
        for i in 0..16 {
            y[i] = x[i];
        }

        let mut w: [Wrapping<u32>; 16] = [Wrapping(0); 16];
        let mut t: [Wrapping<u32>; 4] = [Wrapping(0); 4];
        for _ in 0..20 {
            for j in 0..4 {
                for m in 0..4 {
                    t[m] = x[(5*j+4*m)%16];
                }
                t[1] = t[1] ^ l32(t[0]+t[3], 7);
                t[2] = t[2] ^ l32(t[1]+t[0], 9);
                t[3] = t[3] ^ l32(t[2]+t[1],13);
                t[0] = t[0] ^ l32(t[3]+t[2],18);
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
                x[i] = x[i] + y[i];
            }
            for i in 0..4 {
                x[5*i] = x[5*i] - ld32(&c[4*i..]);
                x[6+i] = x[6+i] - ld32(&inp[4*i..]);
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

    fn crypto_core_hsalsa20(n: &[u8], k: &[u8], c: &[u8])
                            -> Result<[u8; 32], NaClError> {
        let x = try!(core(n,k,c,true));
        let mut o: [u8; 32] = [0; 32];
        for i in 0..32 {
            o[i] = x[i];
        }
        Ok(o)
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
        println!("hello world A");
        let mut c_offset: usize = 0;
        while b >= 64 {
            let x = try!(crypto_core_salsa20(&z,k,SIGMA));
            for i in 0..64 {
                // The following is really ugly.  I wish I could
                // define this closure just once and have it used
                // throughout.  Also note the ugly duplication of code
                // below.  :(
                let m = |i: usize| {
                    if m_offset + i < m_input.len() {
                        m_input[m_offset+i]
                    } else {
                        0
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
        println!("hello world B");

        let m = |i: usize| {
            if m_offset + i < m_input.len() {
                m_input[m_offset+i]
            } else {
                0
            }
        };
        println!("hello world C");

        if b != 0 {
            println!("hello world C1");
            let x = try!(crypto_core_salsa20(&z,k,SIGMA));
            println!("hello world C2 with b {} and m_input.len() {}", b, m_input.len());
            for i in 0..b as usize {
                c[c_offset + i] = m(i) ^ x[i];
            }
        }
        println!("hello world D");
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
    pub fn crypto_stream_32(n: &Nonce, k: &[u8])
                            -> Result<[u8; 32], NaClError> {
        println!("about to hsalsa20");
        let s = try!(crypto_core_hsalsa20(&n.0,k,SIGMA));
        let mut c: [u8; 32] = [0; 32];
        println!("about to salsa20");
        try!(crypto_stream_salsa20(&mut c,32,&n.0[16..],&s));
        println!("done with salsa20");
        Ok(c)
    }

    pub fn crypto_stream_xor(c: &mut[u8], m: &[u8], d: u64, n: &Nonce, k: &[u8])
                             -> Result<(), NaClError> {
        let s = try!(crypto_core_hsalsa20(&n.0,k,SIGMA));
        crypto_stream_salsa20_xor(c,m,d,&n.0[16..],&s)
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

    use std;

    // We derive `Debug` because all types should probably derive `Debug`.
    // This gives us a reasonable human readable description of `CliError` values.
    #[derive(Debug)]
    pub enum NaClError {
        AuthFailed,
        InvalidInput,
        IOError(std::io::Error),
    }
    impl std::convert::From<std::io::Error> for NaClError {
        fn from(e: std::io::Error) -> NaClError {
            NaClError::IOError(e)
        }
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

    pub fn crypto_secretbox(c: &mut[u8], m: &[u8], n: &Nonce, k: &[u8])
                            -> Result<(), NaClError> {
        let d = c.len() as u64;
        if d != m.len() as u64 {
            return Err(NaClError::InvalidInput);
        }
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
        for i in 0..16 {
            c[16+i] = h[i];
        }
        Ok(())
    }

    pub fn crypto_secretbox_open(m: &mut[u8], c: &[u8], n: &Nonce, k: &[u8])
                                 -> Result<(), NaClError> {
        let d = c.len() as u64;
        if m.len() as u64 != d {
            return Err(NaClError::InvalidInput);
        }
        if d < 32 {
            return Err(NaClError::InvalidInput);
        }
        println!("About to crypto_stream_32");
        let x = try!(crypto_stream_32(n,k));
        println!("About to verify");
        try!(crypto_onetimeauth_verify(&c[16..],&c[32..],d - 32,&x));
        try!(crypto_stream_xor(m,c,d,n,k));
        for i in 0..32 {
            m[i] = 0;
        }
        Ok(())
    }

    use std::vec;

    #[test]
    fn secretbox_works() {
        let plaintext: &[u8] = b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0This is only a test.";
        let secretkey: &[u8; 32] = b"This is my secret key. It is me.";
        let mut ciphertext: vec::Vec<u8> = vec![];
        for _ in 0..plaintext.len() {
            ciphertext.push(0);
        }
        let nonce = Nonce([0; 32]);
        crypto_secretbox(&mut ciphertext, plaintext, &nonce, secretkey).unwrap();
        // There has got to be a better way to allocate an array of
        // zeros with dynamically determined type.
        let mut decrypted: vec::Vec<u8> = vec::Vec::with_capacity(plaintext.len());
        for _ in 0..plaintext.len() {
            decrypted.push(0);
        }
        crypto_secretbox_open(&mut decrypted, &ciphertext, &nonce, secretkey).unwrap();
        for i in 0..decrypted.len() {
            assert!(decrypted[i] == plaintext[i])
        }
    }

    // FIXME the following should be eliminated, since assignment
    // between arrays is permitted in rust.  For now I'm leaving it to
    // ease translation of C code.
    fn set25519(r: &mut GF, a: &GF) {
        *r = *a;
    }

    fn car25519(o: &mut GF) {
        for i in 0..16 {
            o[i] += 1<<16;
            let c: i64 = o[i]>>16;
            let iis15 = if i == 15 {1} else {0};
            let ilt15 = if i < 15 {1} else {0};
            o[(i+1)*ilt15] += c-1+37*(c-1)*iis15;
            o[i] -= c<<16;
        }
    }

    fn sel25519(p: &mut GF, q: &mut GF, b: i64) {
        let c = !(b-1);
        for i in 0..16 {
            let t= c&(p[i]^q[i]);
            p[i]^=t;
            q[i]^=t;
        }
    }

    fn pack25519(o: &mut[u8], n: &GF) {
        let mut t = *n;
        car25519(&mut t);
        car25519(&mut t);
        car25519(&mut t);
        let mut m = [0; 16];
        for _ in 0..1 {
            m[0]=t[0]-0xffed;
            for i in 1..15 {
                m[i]=t[i]-0xffff-((m[i-1]>>16)&1);
                m[i-1]&=0xffff;
            }
            m[15]=t[15]-0x7fff-((m[14]>>16)&1);
            let b=(m[15]>>16)&1;
            m[14]&=0xffff;
            sel25519(&mut t,&mut m,1-b);
        }
        for i in 0..16 {
            o[2*i]= (t[i]&0xff) as u8;
            o[2*i+1]= (t[i]>>8) as u8;
        }
    }

    fn neq25519(a: &GF, b: &GF) -> Result<(), NaClError> {
        let mut c: [u8; 32] = [0; 32];
        let mut d: [u8; 32] = [0; 32];
        pack25519(&mut c,a);
        pack25519(&mut d,b);
        crypto_verify_32(&c,&d)
    }

    fn par25519(a: &GF) -> u8 {
        let mut d: [u8; 32] = [0; 32];
        pack25519(&mut d,a);
        d[0]&1
    }

    fn unpack25519(n: &[u8]) -> GF {
        let mut o = GF0;
        for i in 0..16 {
            o[i]=n[2*i] as i64 + ((n[2*i+1] as i64) << 8);
        }
        o[15]&=0x7fff;
        o
    }

    #[allow(non_snake_case)]
    fn A(a: &GF, b: &GF) -> GF {
        let mut out: GF = *a;
        for i in 0..16 {
            out[i] += b[i];
        }
        out
    }

    #[allow(non_snake_case)]
    fn Z(a: &GF, b: &GF) -> GF {
        let mut out: GF = *a;
        for i in 0..16 {
            out[i] -= b[i];
        }
        out
    }

    #[allow(non_snake_case)]
    fn M(a: &GF, b: &GF) -> GF {
        let mut o: GF = *a;
        let mut t: [i64; 31] = [0; 31];
        for i in 0..16 {
            for j in 0..16 {
                t[i+j] += a[i]*b[j];
            }
        }
        for i in 0..15 {
            t[i]+=38*t[i+16];
        }
        for i in 0..16 {
            o[i]=t[i];
        }
        car25519(&mut o);
        car25519(&mut o);
        o
    }

    #[allow(non_snake_case)]
    fn S(a: &GF) -> GF {
        M(a,a)
    }

    fn inv25519(i: &GF) -> GF {
        let mut c = *i;
        for a in (0..254).rev() {
            c = S(&c);
            if a!=2 && a!=4 {
                c = M(&c,i)
            }
        }
        c
    }

    fn pow2523(i: &GF) -> GF {
        let mut c = *i;
        for a in (0..251).rev() {
            c = S(&c);
            if a != 1 {
                c = M(&c, i);
            }
        }
        c
    }

    fn crypto_scalarmult(q: &mut[u8], n: &[u8], p: &[u8]) -> Result<(), NaClError> {
        let mut z: [u8; 32] = [0; 32];
        for i in 0..31 {
            z[i] = n[i];
        }
        z[31]=(n[31]&127)|64;
        z[0]&=248;
        let mut x: [GF; 5] = [unpack25519(p), [0;16], [0;16], [0;16], [0;16]];
        let mut b = x[0];
        let mut d = GF0;
        let mut a = GF0;
        let mut c = GF0;
        a[0]=1;
        d[0]=1;
        for i in (0..255).rev() {
            let r: i64 = ((z[i>>3]>>(i&7))&1) as i64;
            sel25519(&mut a, &mut b,r);
            sel25519(&mut c, &mut d,r);
            let mut e = A(&a,&c);
            a = Z(&a,&c);
            c = A(&b,&d);
            b = Z(&b,&d);
            d = S(&e);
            let f = S(&a);
            a = M(&c,&a);
            c = M(&b,&e);
            e = A(&a,&c);
            a = Z(&a,&c);
            b = S(&a);
            c = Z(&d,&f);
            a = M(&c,&_121665);
            a = A(&a,&d);
            c = M(&c,&a);
            a = M(&d,&f);
            d = M(&b,&x[0]);
            b = S(&e);
            sel25519(&mut a, &mut b,r);
            sel25519(&mut c, &mut d,r);
        }
        x[1] = a;
        x[2] = c;
        x[3] = b;
        x[4] = d;
        x[2] = inv25519(&x[2]);
        x[1] = M(&x[1],&x[2]);
        pack25519(q,&x[1]);
        Ok(())
    }

    fn crypto_scalarmult_base(q: &mut[u8], n: &[u8]) -> Result<(), NaClError> {
        crypto_scalarmult(q,n,&_9)
    }

    use rand::{OsRng,Rng};

    pub struct PublicKey([u8; 32]);
    pub struct SecretKey([u8; 32]);
    pub struct Nonce([u8; 32]);

    pub fn crypto_box_keypair() -> Result<(PublicKey, SecretKey), NaClError> {
        let mut rng = try!(OsRng::new());
        let mut pk: [u8; 32] = [0; 32];
        let mut sk: [u8; 32] = [0; 32];
        rng.fill_bytes(&mut sk);
        try!(crypto_scalarmult_base(&mut pk, &sk));
        Ok((PublicKey(pk), SecretKey(sk)))
    }

    pub fn crypto_random_nonce() -> Result<Nonce, NaClError> {
        let mut rng = try!(OsRng::new());
        let mut n = Nonce([0; 32]);
        rng.fill_bytes(&mut n.0);
        Ok(n)
    }

    pub fn crypto_box_beforenm(y: &PublicKey, x: &SecretKey) -> Result<[u8; 32], NaClError> {
        let mut s: [u8; 32] = [0; 32];
        try!(crypto_scalarmult(&mut s,&x.0,&y.0));
        crypto_core_hsalsa20(&_0,&s,SIGMA)
    }

    pub fn crypto_box_afternm(c: &mut[u8], m: &[u8], n: &Nonce, k: &[u8; 32])
                          -> Result<(), NaClError> {
        crypto_secretbox(c, m, n, k)
    }

    pub fn crypto_box(c: &mut[u8], m: &[u8], n: &Nonce, y: &PublicKey, x: &SecretKey)
                  -> Result<(), NaClError> {
        let k = try!(crypto_box_beforenm(y,x));
        crypto_box_afternm(c, m, n, &k)
    }

    pub fn crypto_box_open_afternm(m: &mut[u8], c: &[u8], n: &Nonce, k: &[u8; 32])
                               -> Result<(), NaClError> {
        crypto_secretbox_open(m,c,n,k)
    }

    pub fn crypto_box_open(m: &mut[u8], c: &[u8], n: &Nonce, y: &PublicKey, x: &SecretKey)
                       -> Result<(), NaClError> {
        let k = try!(crypto_box_beforenm(y,x));
        crypto_box_open_afternm(m, c, n, &k)
    }

    #[test]
    fn box_works() {
        let plaintext: &[u8] = b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0This is only a test.";
        let (pk1, sk1) = crypto_box_keypair().unwrap();
        let (pk2, sk2) = crypto_box_keypair().unwrap();
        let mut ciphertext: vec::Vec<u8> = vec![];
        for _ in 0..plaintext.len() {
            ciphertext.push(0);
        }
        let nonce = Nonce([0; 32]);
        crypto_box(&mut ciphertext, plaintext, &nonce, &pk1, &sk2).unwrap();
        // There has got to be a better way to allocate an array of
        // zeros with dynamically determined type.
        let mut decrypted: vec::Vec<u8> = vec::Vec::with_capacity(plaintext.len());
        for _ in 0..plaintext.len() {
            decrypted.push(0);
        }
        crypto_box_open(&mut decrypted, &ciphertext, &nonce, &pk2, &sk1).unwrap();
        for i in 0..decrypted.len() {
            assert!(decrypted[i] == plaintext[i])
        }
    }
}
