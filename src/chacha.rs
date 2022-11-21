#[inline]
fn qr(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32) {
    *a = a.wrapping_add(*b);
    *d = (*d ^ *a).rotate_left(16);

    *c = c.wrapping_add(*d);
    *b = (*b ^ *c).rotate_left(12);

    *a = a.wrapping_add(*b);
    *d = (*d ^ *a).rotate_left(8);

    *c = c.wrapping_add(*d);
    *b = (*b ^ *c).rotate_left(7);
}

#[inline]
unsafe fn qr_diag(s: &mut [u32; 16], i: usize) {
    qr(
        &mut *(s.get_unchecked_mut(i) as *mut _),
        &mut *(s.get_unchecked_mut(4 | i + 1 & 3) as *mut _),
        &mut *(s.get_unchecked_mut(8 | i + 2 & 3) as *mut _),
        &mut *(s.get_unchecked_mut(12 | i + 3 & 3) as *mut _),
    );
}

#[inline]
unsafe fn qr_col(s: &mut [u32; 16], i: usize) {
    qr(
        &mut *(s.get_unchecked_mut(i) as *mut _),
        &mut *(s.get_unchecked_mut(4 | i) as *mut _),
        &mut *(s.get_unchecked_mut(8 | i) as *mut _),
        &mut *(s.get_unchecked_mut(12 | i) as *mut _),
    );
}

#[inline]
fn chacha_odd_round(s: &mut [u32; 16]) {
    unsafe {
        qr_col(s, 0);
        qr_col(s, 1);
        qr_col(s, 2);
        qr_col(s, 3);
    }
}

#[inline]
fn chacha_even_round(s: &mut [u32; 16]) {
    unsafe {
        qr_diag(s, 0);
        qr_diag(s, 1);
        qr_diag(s, 2);
        qr_diag(s, 3);
    }
}

const CHACHA_CONST: [u32; 4] = [
    // expand 32-byte k
    u32::from_le_bytes(*b"expa"),
    u32::from_le_bytes(*b"nd 3"),
    u32::from_le_bytes(*b"2-by"),
    u32::from_le_bytes(*b"te k"),
];

pub fn chacha(k: &[u32; 8], pos: u64, nonce: &[u32; 2], out: &mut [u32; 16], rounds: usize) {
    // let state = mem::transmute((CHACHA_CONST, *k, pos, nonce));

    let pos = pos.to_ne_bytes();
    let pos = [
        u32::from_ne_bytes([pos[0], pos[1], pos[2], pos[3]]),
        u32::from_ne_bytes([pos[4], pos[5], pos[6], pos[7]]),
    ];

    #[rustfmt::skip]
    let state: [u32; 16] = [
        CHACHA_CONST[0], CHACHA_CONST[1], CHACHA_CONST[2], CHACHA_CONST[3],
        k[0], k[1], k[2], k[3],
        k[4], k[5], k[6], k[7],
        pos[0], pos[1], nonce[0], nonce[1],
    ];

    *out = state;
    for _ in 0..rounds / 2 {
        chacha_odd_round(out);
        chacha_even_round(out);
    }
    for i in 0..16 {
        out[i] = out[i].wrapping_add(state[i]);
    }
}

pub fn xchacha(k: &[u32; 8], pos: u64, nonce: &[u32; 6], out: &mut [u32; 16], rounds: usize) {
    #[rustfmt::skip]
    let mut state: [u32; 16] = [
        CHACHA_CONST[0], CHACHA_CONST[1], CHACHA_CONST[2], CHACHA_CONST[3],
        k[0], k[1], k[2], k[3],
        k[4], k[5], k[6], k[7],
        nonce[0], nonce[1], nonce[2], nonce[3],
    ];

    for _ in 0..rounds / 2 {
        chacha_odd_round(&mut state);
        chacha_even_round(&mut state);
    }

    chacha(
        &[
            state[0], state[1], state[2], state[3], state[12], state[13], state[14], state[15],
        ],
        pos,
        &[nonce[4], nonce[5]],
        out,
        rounds,
    )
}

macro_rules! impl_chacha_fn {
    ($name:ident, $rounds:expr $(,)?) => {
        #[inline]
        pub fn $name(k: &[u32; 8], pos: u64, nonce: &[u32; 2], out: &mut [u32; 16]) {
            chacha(k, pos, nonce, out, $rounds)
        }
    };
    (x, $name:ident, $rounds:expr $(,)?) => {
        #[inline]
        pub fn $name(k: &[u32; 8], pos: u64, nonce: &[u32; 6], out: &mut [u32; 16]) {
            xchacha(k, pos, nonce, out, $rounds)
        }
    };
}
impl_chacha_fn!(chacha20, 20);
impl_chacha_fn!(chacha12, 12);
impl_chacha_fn!(chacha8, 8);

impl_chacha_fn!(x, xchacha20, 20);
impl_chacha_fn!(x, xchacha12, 12);
impl_chacha_fn!(x, xchacha8, 8);

pub struct ChaCha<const N: usize> {
    key: [u32; 8],
    nonce: [u32; 2],
    pos: u64,
    out_pos: u8,
    out: [u32; 16],
}

pub type ChaCha8 = ChaCha<8>;
pub type ChaCha12 = ChaCha<12>;
pub type ChaCha20 = ChaCha<20>;

impl<const N: usize> ChaCha<N> {
    pub fn new(key: [u32; 8], nonce: [u32; 2]) -> Self {
        Self {
            key,
            nonce,
            pos: 0,
            out_pos: 0,
            out: [0; 16],
        }
    }
    pub fn get32(&mut self) -> u32 {
        if let Some(&x) = self.out.get(self.out_pos as usize) {
            x
        } else {
            chacha(&self.key, self.pos, &self.nonce, &mut self.out, N);
            self.out_pos = 1;
            self.out[0]
        }
    }
}

pub struct XChaCha<const N: usize> {
    key: [u32; 8],
    nonce: [u32; 6],
    pos: u64,
    out_pos: u8,
    out: [u32; 16],
}

pub type XChaCha8 = XChaCha<8>;
pub type XChaCha12 = XChaCha<12>;
pub type XChaCha20 = XChaCha<20>;

impl<const N: usize> XChaCha<N> {
    pub fn new(key: [u32; 8], nonce: [u32; 6]) -> Self {
        Self {
            key,
            nonce,
            pos: 0,
            out_pos: 0,
            out: [0; 16],
        }
    }
    pub fn get32(&mut self) -> u32 {
        if let Some(&x) = self.out.get(self.out_pos as usize) {
            x
        } else {
            xchacha(&self.key, self.pos, &self.nonce, &mut self.out, N);
            self.out_pos = 1;
            self.out[0]
        }
    }
}
