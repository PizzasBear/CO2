use digest::{Digest, FixedOutputReset};
use num::{one, zero, BigInt, BigUint, Integer};

/// Computes the modular inverse of x mod n such that:
/// x * mod_inv(x) % n = gcd(x, n)
pub fn mod_inv(x: &BigInt, n: &BigInt) -> BigInt {
    let mut r = x.clone();
    let mut r_old = n.clone();
    let mut y: BigInt = one();
    let mut y_old = zero();
    while r != zero() {
        let (q, r_new) = r_old.div_mod_floor(&r);
        r_old = r;
        r = r_new;

        let tmp = y_old;
        y_old = y.clone();
        y = tmp - q * &y;
    }
    y_old.mod_floor(n)
}

pub fn mod_div(x: &BigInt, y: &BigInt, n: &BigInt) -> BigInt {
    (x.mod_floor(n) * mod_inv(&y.mod_floor(n), n)).mod_floor(n)
}

// pub fn hash_ubigint<D: Digest + FixedOutputReset>(n: &BigUint, h: &mut D) -> BigUint {
//     for digit in n.iter_u64_digits() {
//         Digest::update(h, &digit.to_ne_bytes());
//     }
//     BigUint::from_bytes_le(&h.finalize_reset())
// }

pub fn hash_bigint<D: Digest + FixedOutputReset>(n: &BigInt, h: &mut D) -> BigInt {
    Digest::update(h, &[n.sign() as u8]);
    for digit in n.iter_u64_digits() {
        Digest::update(h, &digit.to_ne_bytes());
    }
    BigUint::from_bytes_le(&h.finalize_reset()).into()
}
