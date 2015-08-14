pub const PACKET_LENGTH: usize = 1024;

pub const BUFSIZE: usize = PACKET_LENGTH + 16 - 32 + super::ROUTING_OVERHEAD;

use super::crypto;

pub trait SelfDocumenting {
    fn move_bytes(&mut self, from: usize, to: usize, length: usize);
    fn set_bytes(&mut self, to: usize, length: usize, bytes: &[u8], name: &str);
    fn sillybox_afternm(&mut self, auth_length: usize, n: &crypto::Nonce,
                        key: &[u8; 32], name: &str);
    fn sillybox_open_afternm(&mut self, auth_length: usize, n: &crypto::Nonce,
                             key: &[u8; 32])
                             -> Result<(), crypto::NaClError>;
    fn get_bytes(&mut self, from: usize, length: usize) -> Vec<u8>;

    fn annotate(&mut self, message: &str);
    fn clear(&mut self);
}

impl SelfDocumenting for [u8; BUFSIZE] {
    fn annotate(&mut self, message: &str) {
    }
    fn clear(&mut self) {
    }
    fn move_bytes(&mut self, from: usize, to: usize, length: usize) {
        if to < from || from+length < to {
            // non-overlapping or overlapping the right way
            for i in 0..length {
                self[to+i] = self[from+i];
                self[from+i] = 0;
            }
        } else {
            // go backwards
            for i in (0..length).rev() {
                self[to+i] = self[from+i];
                self[from+i] = 0;
            }
        }
    }
    fn set_bytes(&mut self, to: usize, length: usize, bytes: &[u8], _name: &str) {
        assert!(length == bytes.len());
        for i in 0..length {
            self[i] = bytes[i];
        }
    }
    fn sillybox_afternm(&mut self, auth_length: usize, n: &crypto::Nonce,
                        key: &[u8; 32], name: &str) {
        unimplemented!();
    }
    fn sillybox_open_afternm(&mut self, auth_length: usize, n: &crypto::Nonce,
                             key: &[u8; 32])
                             -> Result<(), crypto::NaClError> {
        unimplemented!();
    }
    fn get_bytes(&mut self, from: usize, length: usize) -> Vec<u8> {
        unimplemented!();
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Diagram {
    blocks: Vec<Block>,
    postscript: String,
    postscript_height: isize,
    asciiart: String,
}


#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Block {
    length: usize,
    oldx: isize,
    name: String,
    encryptions: Vec<[u8; 32]>,
    encryption_names: Vec<String>,
    bytes: Vec<u8>,
}

impl Block {
    fn split(&self, at: usize) -> (Block, Block) {
        let mut left = self.clone();
        let mut right = self.clone();
        left.length = at;
        left.bytes = Vec::from(&left.bytes[..at]);
        right.length -= at;
        right.bytes = Vec::from(&right.bytes[at..]);
        if right.oldx >= 0 {
            right.oldx += at as isize;
        }
        assert_eq!(left.length + right.length, self.length);
        (left, right)
    }
    fn zeros(length: usize) -> Block {
        Block {
            length: length,
            oldx: -1,
            name: "0".into(),
            encryptions: Vec::new(),
            encryption_names: Vec::new(),
            bytes: vec![0; length],
        }
    }
}

fn blockslen(blocks: &[Block]) -> usize {
    let mut x = 0;
    for b in blocks.iter() {
        x += b.length;
    }
    x
}

fn split2(blocks: &[Block], at: usize) -> (Vec<Block>, Vec<Block>) {
    let mut before = Vec::new();
    let mut after = Vec::new();
    let mut x = 0;
    assert!(blockslen(blocks) >= at);
    for i in 0..blocks.len() {
        if x + blocks[i].length <= at {
            before.push(blocks[i].clone());
        } else if x >= at {
            after.push(blocks[i].clone());
        } else {
            // need to split block
            let (b,a) = blocks[i].split(at - x);
            before.push(b);
            after.push(a);
        }
        x += blocks[i].length;
    }
    assert_eq!(blockslen(&before), at);
    assert_eq!(blockslen(&before) + blockslen(&after), blockslen(blocks));
    (before, after)
}
fn split3(blocks: &[Block], from: usize, length: usize)
              -> (Vec<Block>, Vec<Block>, Vec<Block>) {
    assert!(blockslen(blocks) >= from+length);
    let (before, later) = split2(blocks, from);
    let (inside, after) = split2(&later, length);
    assert_eq!(blockslen(&before) + blockslen(&inside) + blockslen(&after),
               blockslen(blocks));
    assert_eq!(blockslen(&before), from);
    assert_eq!(blockslen(&inside), length);
    (before, inside, after)
}

impl Diagram {
    pub fn new() -> Diagram {
        let mut x = Diagram {
            blocks: vec![Block::zeros(BUFSIZE)],
            postscript: String::new(),
            postscript_height: 0,
            asciiart: String::new(),
        };
        x.postscript_reset();
        assert_eq!(x.len(), BUFSIZE);
        x
    }
    pub fn postscript(&self) -> String {
        self.postscript_header() + &self.postscript
    }
    pub fn asciiart(&self) -> String {
        self.asciiart.clone()
    }
    fn postscript_reset(&mut self) {
        self.postscript = String::new();
        self.postscript_height = 10;
    }
    fn postscript_header(&self) -> String {
        "%!PS-Adobe-2.0 EPSF-2.0
%%BoundingBox: -10 -{height} {width} 10

0 setlinewidth

/Times-Roman 12 selectfont

/show-ctr {
gsave
    ( ) = (start) stack pop
    newpath 0 0 moveto
    dup false charpath flattenpath pathbbox
    ( ) = (pathbbox) stack pop
    exch
    3 -2 roll
    add -2 div
    3 -2 roll
    add -2 div
    exch
    ( ) = (moving) stack pop
    moveto
    3 -2 roll rmoveto
    gsave
        1 1 1 setrgbcolor
        3 setlinewidth
        dup false charpath flattenpath stroke
    grestore
    show
grestore
} def

/r {
  rectstroke
} def

"           .replace("{height}", &format!("{}", self.postscript_height))
            .replace("{width}", &format!("{}", BUFSIZE+10))
    }
    fn display(&mut self, annotation: &str) {
        let dy = 72/2;
        let rheight = dy/2;
        self.postscript_height += dy;
        let mut psnew = String::new();
        let mut ascii = String::new();
        let mut x = 0;

        let y = self.postscript_height - 10;
        for b in self.blocks.iter() {
            let thickness = 1;
            let centerx = (x + b.length/2) as isize;
            let centery = -y + rheight/2;
            if b.oldx != x as isize && b.oldx >= 0 {
                psnew = psnew + &format!("gsave 0 setlinewidth\n");
                psnew = psnew + &format!("gsave 0.5 setgray\n");
                psnew = psnew + &format!("{} {} moveto {} {} lineto stroke\n",
                                         x as isize + thickness,
                                         -y + rheight,
                                         b.oldx + thickness,
                                         -y + dy);
                psnew = psnew + &format!("{} {} moveto {} {} lineto stroke\n",
                                         (x + b.length) as isize - thickness,
                                         -y + rheight,
                                         b.oldx + b.length as isize - thickness,
                                         -y + dy);
                psnew = psnew + &format!("grestore\n");
            } else if b.oldx == -1 && b.name != "0" {
                let braceheight = rheight + (dy-rheight)/2;
                psnew = psnew + &format!("gsave\n");
                psnew = psnew + &format!("{} {} moveto\n",
                                         x as isize + thickness,
                                         -y + rheight);
                psnew = psnew + &format!("{} {} {} {} {} {} curveto\n",
                                         x as isize + thickness,
                                         -y + braceheight,
                                         x + b.length/2,
                                         -y + rheight - (braceheight-rheight)/2,
                                         x + b.length/2,
                                         -y + (braceheight*3/4+rheight/4));
                psnew = psnew + &format!("{} {} {} {} {} {} curveto\n",
                                         x + b.length/2,
                                         -y + rheight - (braceheight-rheight)/2,
                                         (x + b.length) as isize - thickness,
                                         -y + braceheight,
                                         (x + b.length) as isize - thickness,
                                         -y + rheight);
                psnew = psnew + &format!("stroke grestore\n");
            }
            psnew = psnew + &format!("gsave {} {} {} {} 4 copy r rectclip\n",
            //psnew = psnew + &format!("gsave {} {} {} {} r\n",
                                     x as isize +thickness, -y,
                                     b.length as isize -2*thickness, rheight);
            for kindex in 0..b.encryptions.len() {
                let k = b.encryptions[kindex];
                psnew = psnew + &format!("{} {} {} setrgbcolor\n",
                                         k[2] as f64/256.0,
                                         k[3] as f64/256.0,
                                         k[4] as f64/256.0);
                psnew = psnew + &format!("{} setlinewidth\n", kindex as f64/4.0);
                let teenyx = -(k[1] as f64)/256.0;
                let angle = (k[0] as f64 - 128.0)/128.0 * 0.8; // not quite pi/2
                let dx = rheight as f64 * angle.tan();
                let w = rheight as f64 /6.0;
                let xshift = w  / angle.cos();
                let nfirst = if dx < 0.0 { 0 } else { - (dx / xshift) as isize - 1 };
                let nlast = (b.length as f64/xshift) as isize + 1
                    + if dx > 0.0 { 0 } else { - (dx / xshift) as isize + 1 };
                psnew = psnew + &format!("newpath {} {} moveto {} {{\n",
                                         x as f64 + nfirst as f64*xshift + teenyx, -y,
                                         // x as f64 + nfirst as f64 * xshift, y,
                                         nlast - nfirst);
                psnew = psnew + &format!("  {} {} rlineto {} {} rmoveto\n",
                                         dx, rheight, -dx + xshift, -rheight);
                psnew = psnew + &format!("}} repeat stroke\n");
            }
            if b.encryptions.len() > 0 {
                psnew = psnew + &format!("{} {} {} setrgbcolor\n",
                                         b.encryptions[b.encryptions.len()-1][2] as f64/1024.0,
                                         b.encryptions[b.encryptions.len()-1][3] as f64/1024.0,
                                         b.encryptions[b.encryptions.len()-1][4] as f64/1024.0);
            }
            psnew = psnew + &format!("{} {} ({}) show-ctr grestore\n",
                                     centerx, centery, &b.name);
            if b.encryptions.len() > 0 {
                ascii = ascii + &format!("{:❁^1$.1$}|", &b.name, b.length/8-1);
            } else {
                ascii = ascii + &format!("{:-^1$.1$}|", &b.name, b.length/8-1);
            }
            x += b.length;
        }
        psnew = psnew + &format!("{} {} ({}) show-ctr\n",
                                 BUFSIZE/2, -y + rheight + (dy-rheight)/2, annotation);

        ascii.push('\n');
        self.asciiart = self.asciiart.clone() + &ascii;
        self.postscript = self.postscript.clone() + &psnew;

        x = 0;
        for i in 0 .. self.blocks.len() {
            self.blocks[i].oldx = x as isize;
            x += self.blocks[i].length;
        }
    }
    pub fn len(&self) -> usize {
        let mut tot = 0;
        for b in self.blocks.iter() {
            tot += b.length;
        }
        tot
    }
}

impl SelfDocumenting for Diagram {
    fn move_bytes(&mut self, from: usize, to: usize, length: usize) {
        if from + length < to {
            let (pre, moved, middle_) = split3(&self.blocks, from, length);
            let (middle, gone, rest) = split3(&middle_, to-from-length, length);
            self.blocks = pre;
            self.blocks.push(Block::zeros(length));
            self.blocks.extend(middle);
            self.blocks.extend(moved);
            self.blocks.extend(rest);
        } else if from < to {
            let (pre, moved, gone_) = split3(&self.blocks, from, length);
            let (gone, rest) = split2(&gone_, to-from);
            self.blocks = pre;
            self.blocks.push(Block::zeros(to-from));
            self.blocks.extend(moved);
            self.blocks.extend(rest);
        } else if from < to + length {
            let (pre, gone, moved_) = split3(&self.blocks, to, from-to);
            let (moved, rest) = split2(&moved_, length);
            self.blocks = pre;
            self.blocks.extend(moved);
            self.blocks.push(Block::zeros(from-to));
            self.blocks.extend(rest);
        } else {
            let (pre, gone, middle_) = split3(&self.blocks, to, length);
            let (middle, moved, rest) = split3(&middle_, from-to-length, length);
            self.blocks = pre;
            self.blocks.extend(moved);
            self.blocks.extend(middle);
            self.blocks.push(Block::zeros(length));
            self.blocks.extend(rest);
        }
        assert_eq!(self.len(), BUFSIZE);
    }
    fn set_bytes(&mut self, to: usize, length: usize, bytes: &[u8], name: &str) {
        assert!(length == bytes.len());
        assert_eq!(self.len(), BUFSIZE);
        let (before, gone, after) = split3(&self.blocks, to, length);
        assert_eq!(blockslen(&gone), length);
        self.blocks = before;
        self.blocks.push(Block {
            name: name.into(),
            oldx: -1,
            length: length,
            encryptions: Vec::new(),
            encryption_names: Vec::new(),
            bytes: Vec::from(bytes),
        });
        self.blocks.extend(after);
        assert_eq!(self.len(), BUFSIZE);
    }
    fn sillybox_afternm(&mut self, auth_length: usize, n: &crypto::Nonce,
                        key: &[u8; 32], name: &str) {
        for i in 0..self.blocks.len() {
            if self.blocks[i].encryptions.contains(key) {
                for j in 0..self.blocks[i].encryptions.len() {
                    if self.blocks[i].encryptions[j] == *key {
                        self.blocks[i].encryptions.remove(j);
                        self.blocks[i].encryption_names.remove(j);
                        break;
                    }
                }
            } else {
                self.blocks[i].encryptions.push(*key);
                self.blocks[i].encryption_names.push(name.into());
            }
        }
        assert!(self.len() == BUFSIZE);
        self.set_bytes(16,16,&key[0..16], &format!("A{}", name));
        self.set_bytes(0,16,&[0;16], "0");
        self.blocks[1].encryptions.push(*key);
        self.blocks[1].encryption_names.push(name.into());
        assert!(self.len() == BUFSIZE);
    }
    fn sillybox_open_afternm(&mut self, auth_length: usize, n: &crypto::Nonce,
                             key: &[u8; 32])
                             -> Result<(), crypto::NaClError> {
        if self.blocks.len() < 2 {
            return Err(crypto::NaClError::AuthFailed);
        }
        if self.blocks[1].encryptions != vec![*key] {
            return Err(crypto::NaClError::AuthFailed);
        }
        self.blocks[1].encryptions = Vec::new();
        let name = self.blocks[1].encryption_names[0].clone();
        self.blocks[1].encryption_names = Vec::new();
        let auth: &[u8] = &self.get_bytes(16, 16);
        for i in 0..16 {
            if auth[i] != key[i] {
                return Err(crypto::NaClError::AuthFailed);
            }
        }
        self.sillybox_afternm(auth_length, n, key, &name);
        self.set_bytes(0,32,&[0;32], "0");
        Ok(())
    }
    fn get_bytes(&mut self, from: usize, length: usize) -> Vec<u8> {
        let mut x = 0;
        let mut blocklocations = Vec::new();
        for i in 0..self.blocks.len() {
            if x == from && length == self.blocks[i].length && self.blocks[i].encryptions.len() == 0 {
                let bytes = self.blocks[i].bytes.clone();
                self.set_bytes(from, length, &vec![0; length], "0");
                return bytes;
            }
            blocklocations.push((x, self.blocks[i].length));
            x += self.blocks[i].length;
        }
        panic!("I am disturbed by the bytes you seek. {} and {}\n{:?}",
               from, length, blocklocations);
    }

    fn annotate(&mut self, message: &str) {
        self.asciiart = format!("{}\n{}\n\n", self.asciiart, message);
        self.display(message);
    }
    fn clear(&mut self) {
        self.postscript_reset();
    }
}
