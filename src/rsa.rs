use digest::{Digest, FixedOutputReset};
// use generic_array::{arr, typenum::*};
use crate::common::{hash_bigint, mod_inv};
use num::{
    bigint::{RandBigInt, Sign},
    one, zero, BigInt, Integer,
};
use rand::prelude::*;
use serde::{Deserialize, Serialize};
// use std::mem::replace;

const BITS: u64 = 3072;
const PRIME_BITS: u64 = BITS >> 1;

/// The first 60 primes
const FIRST_PRIMES: [u32; 60] = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
    197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
];

/// The miller rabin primallity test.
/// for k greater than or equal to 40 the test is my be considered as completely accurate.
fn miller_rabin<R: RandBigInt>(n: &BigInt, k: usize, rng: &mut R) -> bool {
    if *n == 2.into() || *n == 3.into() {
        true
    } else if n & &one() == zero() {
        false
    } else {
        let mut d: BigInt = n >> 1;
        let mut r: BigInt = one();
        while d.is_even() {
            d >>= 1;
            r <<= 1;
        }
        'outer_loop: for _ in 0..k {
            let a: BigInt = rng.gen_bigint_range(&2.into(), &(n - 1));
            let mut x = a.modpow(&d, n);
            if x == one() || x == n - 1u32 {
                continue;
            }
            while r != zero() {
                x = (&x * &x) % n;
                if x == n - 1 {
                    continue 'outer_loop;
                }
                r -= 1;
            }
            return false;
        }
        true
    }
}

/// Quick primallity test, loads of false positives and no false negatives.
/// Should be used before the miller rabin test for efficiancy.
fn quick_prime_check(n: &BigInt) -> bool {
    for p in FIRST_PRIMES.iter().copied() {
        if *n == p.into() {
            return true;
        } else if n % p == zero() {
            return false;
        }
    }
    true
}

fn is_prime<R: RandBigInt>(n: &BigInt, rng: &mut R) -> bool {
    quick_prime_check(n) && miller_rabin(n, 40, rng)
}

fn gen_secure_prime<R: RandBigInt, CR: CryptoRng + RandBigInt>(
    rng: &mut R,
    crng: &mut CR,
) -> BigInt {
    let mut n = BigInt::from_biguint(Sign::Plus, crng.gen_biguint(PRIME_BITS));
    while !is_prime(&n, rng) {
        n += 1;
    }
    n
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PublicRsaKey(BigInt, BigInt);
#[derive(Clone, Serialize, Deserialize)]
pub struct SecretRsaKey(BigInt, PublicRsaKey);

pub fn gen_rsa_key<R: RandBigInt, CR: RandBigInt + CryptoRng>(
    rng: &mut R,
    crng: &mut CR,
) -> SecretRsaKey {
    let p = gen_secure_prime(rng, crng);
    let q = gen_secure_prime(rng, crng);
    let n = &p * &q;
    let lam = (p - one::<BigInt>()).lcm(&(q - one::<BigInt>()));
    let e = loop {
        let out = crng.gen_bigint_range(&one(), &lam);
        if lam.gcd(&out) == one() {
            break out;
        }
    };
    let d = mod_inv(&e, &lam);
    SecretRsaKey(e, PublicRsaKey(d, n))
}

impl PublicRsaKey {
    pub fn enc(&self, m: &BigInt) -> Option<BigInt> {
        if &one::<BigInt>() < m && m < &(&self.1 - 1) {
            Some(m.modpow(&self.0, &self.1))
        } else {
            None
        }
    }

    pub fn verify<D: Digest + FixedOutputReset>(
        &self,
        h: &mut D,
        m: &BigInt,
        ds: &BigInt,
    ) -> Option<bool> {
        Some(self.enc(ds)? == hash_bigint(m, h))
    }
}

impl SecretRsaKey {
    pub fn dec(&self, c: &BigInt) -> Option<BigInt> {
        if &one::<BigInt>() < c && c < &(&self.1 .1 - 1) {
            Some(c.modpow(&self.0, &self.1 .1))
        } else {
            None
        }
    }

    pub fn pub_key(&self) -> PublicRsaKey {
        self.1.clone()
    }

    pub fn sign<D: Digest + FixedOutputReset>(&self, h: &mut D, m: &BigInt) -> Option<BigInt> {
        self.dec(&hash_bigint(m, h))
    }
}
// (define (sign-rsa hash m sk)
//   (rsa (hash m) sk))
//
// (define (verify-rsa hash m ds pk)
//   (= (rsa ds pk) (hash m)))
