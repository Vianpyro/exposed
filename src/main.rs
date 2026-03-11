use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use libc::{c_char, c_int, fflush, fgets, printf, puts};

extern "C" {
    static mut stdin: *mut libc::FILE;
    static mut stdout: *mut libc::FILE;
}

// FLAG 1  – Easy
static FLAG1: &[u8] = b"RkxBR3tiNHMzXzFzX24wdF8zbmNyeXB0MTBufQ==\0";

unsafe fn check_flag1(buf: &[u8; 128]) -> bool {
    let b64_str = &FLAG1[..FLAG1.len() - 1];
    let flag = B64.decode(b64_str).unwrap_or_default();
    let flag_len = flag.len();
    let mut i = 0usize;
    while i < flag_len {
        let a = buf[i];
        if a == b'\n' || a == b'\r' || a == 0 {
            return i == flag_len;
        }
        if a != flag[i] {
            return false;
        }
        i += 1;
    }
    let next = buf[flag_len];
    next == b'\n' || next == b'\r' || next == 0
}

// FLAG 2  – Intermediate
const FLAG2_TRANSFORMED: [u8; 33] = [
    0x1f, 0x19, 0x1e, 0x20, 0x24, 0x25, 0x6d, 0x2b, 0x08, 0x30, 0x6e, 0x31, 0x35, 0x08, 0x2b,
    0x6d, 0x31, 0x71, 0x31, 0x6e, 0x6d, 0x37, 0x08, 0x6e, 0x2c, 0x08, 0x3b, 0x6c, 0x31, 0x31,
    0x6c, 0x2b, 0x2a,
];

unsafe fn check_flag2(buf: &[u8; 128]) -> bool {
    let mut i = 0usize;
    while i < FLAG2_TRANSFORMED.len() {
        let a = buf[i];
        if a == b'\n' || a == b'\r' || a == 0 {
            return i == FLAG2_TRANSFORMED.len();
        }
        if ((a ^ 0x5Au8) as u16 + 3) as u8 != FLAG2_TRANSFORMED[i] {
            return false;
        }
        i += 1;
    }
    let next = buf[FLAG2_TRANSFORMED.len()];
    next == b'\n' || next == b'\r' || next == 0
}

// FLAG 3  – Hard
#[link_section = ".rodata.p0lo"]
static RAW_A_LO: [u8; 4] = [0x32, 0x35, 0x0f, 0x1c];
#[link_section = ".rodata.p0hi"]
static RAW_A_HI: [u8; 4] = [0x38, 0x33, 0x03, 0x47];

#[link_section = ".rodata.p1lo"]
static RAW_B_LO: [u8; 4] = [0x10, 0x0c, 0x21, 0x4d];
#[link_section = ".rodata.p1hi"]
static RAW_B_HI: [u8; 4] = [0x21, 0x4e, 0x13, 0x4d];

#[link_section = ".rodata.p2lo"]
static RAW_C_LO: [u8; 3] = [0x97, 0xbc, 0xce];
#[link_section = ".rodata.p2hi"]
static RAW_C_HI: [u8; 3] = [0x90, 0x95, 0x97];

#[link_section = ".rodata.p3lo"]
static RAW_D_LO: [u8; 3] = [0x10, 0x1d, 0x02];
#[link_section = ".rodata.p3hi"]
static RAW_D_HI: [u8; 3] = [0x13, 0x42, 0x0c];

#[repr(C)]
struct FatPtr {
    _data: *const (),
    vtable: *const (),
}

fn vtable_mix(p: &dyn Piece) -> u8 {
    let fp: FatPtr = unsafe { core::mem::transmute(p) };
    let bytes = (fp.vtable as usize).to_ne_bytes();
    bytes.iter().fold(0u8, |acc, &b| acc ^ b)
}

trait Piece: Send + Sync {
    fn halves(&self) -> (&'static [u8], &'static [u8]);
    fn rotation_seed(&self) -> u8;

    fn check_against(&self, dyn_self: &dyn Piece, input: &[u8], offset: usize) -> Option<usize> {
        let (lo, hi) = self.halves();
        let k = vtable_mix(dyn_self).wrapping_add(self.rotation_seed());
        for i in 0..lo.len() {
            let p = offset + i * 2;
            if (input[p] ^ k) != lo[i] || (input[p + 1] ^ k) != hi[i] {
                return None;
            }
        }
        Some(lo.len() * 2)
    }
}

struct PieceA;
impl Piece for PieceA {
    fn halves(&self) -> (&'static [u8], &'static [u8]) { (&RAW_A_LO, &RAW_A_HI) }
    fn rotation_seed(&self) -> u8 { 0xA3 }
}

struct PieceB;
impl Piece for PieceB {
    fn halves(&self) -> (&'static [u8], &'static [u8]) { (&RAW_B_LO, &RAW_B_HI) }
    fn rotation_seed(&self) -> u8 { 0x5C }
}

struct PieceC;
impl Piece for PieceC {
    fn halves(&self) -> (&'static [u8], &'static [u8]) { (&RAW_C_LO, &RAW_C_HI) }
    fn rotation_seed(&self) -> u8 { 0x71 }
}

struct PieceD;
impl Piece for PieceD {
    fn halves(&self) -> (&'static [u8], &'static [u8]) { (&RAW_D_LO, &RAW_D_HI) }
    fn rotation_seed(&self) -> u8 { 0x2F }
}

unsafe fn check_flag3(buf: &[u8; 128]) -> bool {
    let a: &dyn Piece = &PieceA;
    let b: &dyn Piece = &PieceB;
    let c: &dyn Piece = &PieceC;
    let d: &dyn Piece = &PieceD;
    let pieces: [&dyn Piece; 4] = [a, b, c, d];

    let mut offset = 0usize;
    for &piece in &pieces {
        match piece.check_against(piece, buf, offset) {
            Some(n) => offset += n,
            None => return false,
        }
    }
    let next = buf[offset];
    next == b'\n' || next == b'\r' || next == 0
}

macro_rules! cstr {
    ($s:expr) => {
        concat!($s, "\0").as_ptr() as *const c_char
    };
}

unsafe fn print_banner() {
    puts(cstr!("Hey!\n"));
    puts(cstr!("There are three flags hidden in this binary."));
    puts(cstr!("I tried to make them different enough that "));
    puts(cstr!("there's something for everyone"));
    puts(cstr!("whether you're just starting out "));
    puts(cstr!("or you know your way around a disassembler.\n"));
    puts(cstr!("Good luck."));
    puts(cstr!("  -- Vianpyro\n"));
    puts(cstr!("------------------------------------------------------\n"));
}

unsafe fn read_line(buf: &mut [u8; 128]) {
    buf.fill(0);
    fgets(buf.as_mut_ptr() as *mut c_char, 128, stdin);
}

unsafe fn prompt_flag(n: c_int, label: *const c_char, checker: unsafe fn(&[u8; 128]) -> bool) {
    loop {
        printf(cstr!("> FLAG %d  -  %s: "), n, label);
        fflush(stdout);

        let mut buf = [0u8; 128];
        read_line(&mut buf);

        if checker(&buf) {
            printf(cstr!("  [+] Correct! Flag %d validated.\n\n"), n);
            break;
        } else {
            printf(cstr!("  [-] Wrong. Try again.\n\n"));
        }
    }
}

fn main() {
    unsafe {
        print_banner();
        prompt_flag(1, cstr!("Easy        "), check_flag1);
        prompt_flag(2, cstr!("Intermediate"), check_flag2);
        prompt_flag(3, cstr!("Hard        "), check_flag3);
        puts(cstr!("\nYou found all three!"));
        puts(cstr!("Honestly didn't expect that -- nice work."));
        puts(cstr!("  -- Vianpyro\n"));
    }
}
