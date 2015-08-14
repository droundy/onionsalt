pub const PACKET_LENGTH: usize = 1024;

pub const BUFSIZE: usize = PACKET_LENGTH + 16 + super::ROUTING_OVERHEAD;

use super::crypto;

pub trait SelfDocumenting {
    fn move_bytes(&mut self, from: usize, to: usize, length: usize);
    fn set_bytes(&mut self, to: usize, length: usize, bytes: &[u8], name: &str);
    fn sillybox_afternm(&mut self, auth_length: usize, n: &crypto::Nonce,
                        key: &[u8; 32], name: &str);
    fn sillybox_open_afternm(&mut self, auth_length: usize, n: &crypto::Nonce,
                             key: &[u8; 32], name: &str)
                             -> Result<(), crypto::NaClError>;
    fn get_bytes(&mut self, from: usize, length: usize) -> Box<[u8]>;

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
                             key: &[u8; 32], name: &str)
                             -> Result<(), crypto::NaClError> {
        unimplemented!();
    }
    fn get_bytes(&mut self, from: usize, length: usize) -> Box<[u8]> {
        unimplemented!();
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Diagram {
    blocks: Vec<Block>,
    old: Vec<Block>,
    postscript: String,
    postscript_height: isize,
    asciiart: String,
}


#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Block {
    length: usize,
    name: String,
    encryptions: Vec<[u8; 32]>,
    encryption_names: Vec<String>,
}

impl Block {
    fn split(&self, at: usize) -> (Block, Block) {
        let mut left = self.clone();
        let mut right = self.clone();
        left.length = at;
        right.length -= at;
        assert_eq!(left.length + right.length, self.length);
        (left, right)
    }
    fn zeros(length: usize) -> Block {
        Block {
            length: length,
            name: "0".into(),
            encryptions: Vec::new(),
            encryption_names: Vec::new(),
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
            blocks: vec![Block{ length: BUFSIZE,
                                name: "0".into(),
                                encryption_names: Vec::new(),
                                encryptions: Vec::new()}],
            old: vec![Block{ length: BUFSIZE,
                             name: "0".into(),
                             encryption_names: Vec::new(),
                             encryptions: Vec::new()}],
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

gsave
  1 0 0 setrgbcolor
  100 100 moveto
  200 100 lineto
  150 150 lineto
  closepath
  fill
grestore
gsave
1 0 0 setrgbcolor
2 setlinewidth
stroke
grestore

0 setlinewidth

/Times-Roman 12 selectfont
100 100 moveto
(Hello) show

currentpoint pop 100 sub 2 add
99 99 moveto
0 rlineto 0 12 rlineto 99 111 lineto
closepath stroke

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
        2 setlinewidth
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
        psnew = psnew + &format!("{} {} ({}) show-ctr\n",
                                 BUFSIZE/2, -y + rheight + (dy-rheight)/2, annotation);
        for b in self.blocks.iter() {
            let thickness = 4;
            let centerx = (x + b.length/2) as isize;
            let centery = -y + rheight/2;
            psnew = psnew + &format!("gsave {} {} {} {} 4 copy r rectclip\n",
            //psnew = psnew + &format!("gsave {} {} {} {} r\n",
                                     x as isize +thickness, -y,
                                     b.length as isize -thickness, rheight);
            for kindex in 0..b.encryptions.len() {
                let k = b.encryptions[kindex];
                psnew = psnew + &format!("{} {} {} setrgbcolor\n",
                                         k[2] as f64/256.0,
                                         k[3] as f64/256.0,
                                         k[4] as f64/256.0);
                psnew = psnew + &format!("{} setlinewidth\n", kindex as f64/6.0);
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
                                         b.encryptions[b.encryptions.len()-1][2] as f64/512.0,
                                         b.encryptions[b.encryptions.len()-1][3] as f64/512.0,
                                         b.encryptions[b.encryptions.len()-1][4] as f64/512.0);
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
        ascii.push('\n');
        self.asciiart = self.asciiart.clone() + &ascii;
        self.postscript = self.postscript.clone() + &psnew;

        self.old = self.blocks.clone();
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
            length: length,
            encryptions: Vec::new(),
            encryption_names: Vec::new(),
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
        self.set_bytes(16,16,&[0;16], &format!("A{}", name));
        self.set_bytes(0,16,&[0;16], "0");
        assert!(self.len() == BUFSIZE);
    }
    fn sillybox_open_afternm(&mut self, auth_length: usize, n: &crypto::Nonce,
                             key: &[u8; 32], name: &str)
                             -> Result<(), crypto::NaClError> {
        unimplemented!();
    }
    fn get_bytes(&mut self, from: usize, length: usize) -> Box<[u8]> {
        unimplemented!();
    }

    fn annotate(&mut self, message: &str) {
        self.asciiart = format!("{}\n{}\n\n", self.asciiart, message);
        self.display(message);
    }
    fn clear(&mut self) {
        self.postscript = String::new();
    }
}
