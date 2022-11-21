use crate::common::{hash_bigint, mod_div, mod_inv};
use digest::{Digest, FixedOutputReset};
use lazy_static::lazy_static;
use num::{bigint::RandBigInt, one, zero, BigInt, Integer};
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use std::ops::{Add, Mul, Neg, Sub};

pub trait AddGroup: PartialEq + Eq + 'static {
    type Point: Clone + Eq + PartialEq + 'static;
    fn identity(&self) -> Self::Point;
    fn generator(&self) -> &Self::Point;
    fn order(&self) -> &BigInt;
    fn add(&self, p: &Self::Point, q: &Self::Point) -> Self::Point;
    fn sub(&self, p: &Self::Point, q: &Self::Point) -> Self::Point {
        self.add(p, &self.neg(q))
    }
    fn neg(&self, p: &Self::Point) -> Self::Point;
    fn double(&self, p: &Self::Point) -> Self::Point {
        self.add(p, p)
    }
    fn mul(&self, k: &BigInt, p: &Self::Point) -> Self::Point {
        let mut out = self.identity();
        let mut p = p.clone();
        let mut k = k.clone();
        while zero::<BigInt>() < k {
            if k == one() {
                out = self.add(&out, &p);
            } else {
                if k.is_odd() {
                    out = self.add(&out, &p);
                }
                p = self.double(&p);
            }
            k >>= 1;
        }
        out
    }
    fn validate(&self, p: &Self::Point) -> bool;
    fn to_bigint(p: &Self::Point) -> &BigInt;
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Pos {
    x: BigInt,
    y: BigInt,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Point<C: AddGroup + 'static> {
    pub curve: &'static C,
    pub pos: C::Point,
}

lazy_static! {
    pub static ref CURVE25519: MontgomeryCurve = MontgomeryCurve {
        a: 486662.into(),
        b: one(),
        p: (one::<BigInt>() << 255) - 19,
        g: Some(Pos {
            x: 9.into(),
            y: BigInt::parse_bytes(
                b"43114425171068552920764898935933967039370386198203806730763910166200978582548",
                10
            )
            .unwrap(),
        }),
        n: (one::<BigInt>() << 252)
            + BigInt::parse_bytes(b"27742317777372353535851937790883648493", 10).unwrap(),
    };
    pub static ref ED25519: TwistedEdwardsCurve = TwistedEdwardsCurve {
        a: (-1).into(),
        d: mod_div(&(-121665).into(), &121666.into(), &CURVE25519.p),
        p: CURVE25519.p.clone(),
        b: Pos {
            x: BigInt::parse_bytes(
                b"15112221349535400772501151409588531511454012693041857206046113283949847762202",
                10
            )
            .unwrap(),
            y: mod_div(&4.into(), &5.into(), &CURVE25519.p),
        },
        l: CURVE25519.n.clone(),
    };
    pub static ref SECP256K1: EllipticCurve = EllipticCurve {
        a: zero(),
        b: 7.into(),
        p: BigInt::parse_bytes(
            b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
            16
        )
        .unwrap(),
        g: Some(Pos {
            x: BigInt::parse_bytes(
                b"79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
                16
            )
            .unwrap(),
            y: BigInt::parse_bytes(
                b"483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
                16
            )
            .unwrap(),
        }),
        n: BigInt::parse_bytes(
            b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
            16
        )
        .unwrap(),
    };
    pub static ref P256: EllipticCurve = EllipticCurve {
        a: (-3).into(),
        b: BigInt::parse_bytes(
            b"41058363725152142129326129780047268409114441015993725554835256314039467401291",
            10
        )
        .unwrap(),
        p: (one::<BigInt>() << 256) - (one::<BigInt>() << 224)
            + (one::<BigInt>() << 192)
            + (one::<BigInt>() << 96)
            - 1,
        g: Some(Pos {
            x: BigInt::parse_bytes(
                b"6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
                16
            )
            .unwrap(),
            y: BigInt::parse_bytes(
                b"4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
                16
            )
            .unwrap(),
        }),
        n: BigInt::parse_bytes(
            b"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
            16
        )
        .unwrap(),
    };
    pub static ref SECP256R1: &'static EllipticCurve = &*P256;
}

/// y² ≡ x³ + ax + b (mod p)
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EllipticCurve {
    a: BigInt,
    b: BigInt,
    /// Prime dividor
    p: BigInt,
    /// Generator point
    pub g: Option<Pos>,
    /// Generator's multiplicative order
    n: BigInt,
}

/// by² ≡ x³ + ax² + x (mod p)
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MontgomeryCurve {
    a: BigInt,
    b: BigInt,
    /// Prime dividor
    p: BigInt,
    /// Generator point
    pub g: Option<Pos>,
    /// Generator's multiplicative order
    n: BigInt,
}

/// ax² + y² ≡ 1 + dx²y² (mod p)
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TwistedEdwardsCurve {
    a: BigInt,
    d: BigInt,
    /// Prime dividor
    p: BigInt,
    /// Base Point
    pub b: Pos,
    /// Base's multiplicative order
    l: BigInt,
}

pub fn ecdh<D: Digest + FixedOutputReset, C: AddGroup>(
    sk: &BigInt,
    other_pk: &Point<C>,
    h: &mut D,
) -> BigInt {
    hash_bigint(&(sk * other_pk).to_bigint(), h)
}

pub fn ecdsa_sign<D: Digest + FixedOutputReset, C: AddGroup, CR: RandBigInt + CryptoRng>(
    m: &BigInt,
    sk: &BigInt,
    curve: &'static C,
    crng: &mut CR,
    h: &mut D,
) -> (BigInt, BigInt) {
    let g = Point::<C> {
        pos: curve.generator().clone(),
        curve,
    };
    let n = curve.order();

    let z = hash_bigint(m, h).mod_floor(n);
    let k = crng.gen_bigint_range(&one(), n);
    let r = C::to_bigint(&(&k * g).pos).mod_floor(n);
    let s = mod_div(&(z + &r * sk), &k, n);
    (r, s)
}

pub fn ecdsa_verify<D: Digest + FixedOutputReset, C: AddGroup>(
    m: &BigInt,
    pk: &C::Point,
    ds: &(BigInt, BigInt),
    curve: &'static C,
    h: &mut D,
) -> bool {
    let g = Point::<C> {
        pos: curve.generator().clone(),
        curve,
    };
    let n = curve.order();
    let pk = Point::<C> {
        pos: pk.clone(),
        curve,
    };
    if pk.validate() && pk.pos != curve.identity() && (curve.order() * &pk).pos == curve.identity()
    {
        let (r, s) = ds;
        let z = hash_bigint(m, h).mod_floor(n);
        let inv_s = mod_inv(&s, n);
        let u1 = (z * &inv_s).mod_floor(n);
        let u2 = (r * &inv_s).mod_floor(n);
        *r == (u1 * g + u2 * pk).to_bigint().mod_floor(n)
    } else {
        false
    }
}

pub fn eddsa_sign<D: Digest + FixedOutputReset, C: AddGroup, CR: RandBigInt + CryptoRng>(
    m: &BigInt,
    sk: &BigInt,
    curve: &'static C,
    crng: &mut CR,
    h: &mut D,
) -> (C::Point, BigInt) {
    let g = Point::<C> {
        pos: curve.generator().clone(),
        curve,
    };
    let n = curve.order();

    let k = crng.gen_bigint_range(&zero(), n);
    let r = &k * g;
    let z = hash_bigint(m, h).mod_floor(n);
    let s = (k + z * sk).mod_floor(n);
    (r.pos, s)
}

pub fn eddsa_verify<D: Digest + FixedOutputReset, C: AddGroup>(
    m: &BigInt,
    pk: &C::Point,
    ds: &(C::Point, BigInt),
    curve: &'static C,
    h: &mut D,
) -> bool {
    let g = Point::<C> {
        pos: curve.generator().clone(),
        curve,
    };
    let pk = Point::<C> {
        pos: pk.clone(),
        curve,
    };
    if pk.validate() && pk.pos != curve.identity() && (curve.order() * &pk).pos == curve.identity()
    {
        let (r, s) = ds;
        let r = Point {
            pos: r.clone(),
            curve,
        };
        let z = hash_bigint(m, h).mod_floor(curve.order());
        s * g == r + z * pk
    } else {
        false
    }
}

impl AddGroup for EllipticCurve {
    type Point = Option<Pos>;
    fn identity(&self) -> Self::Point {
        None
    }
    fn generator(&self) -> &Self::Point {
        &self.g
    }
    fn order(&self) -> &BigInt {
        &self.n
    }
    fn add(&self, p: &Self::Point, q: &Self::Point) -> Self::Point {
        if let (Some(Pos { x: x1, y: y1 }), Some(Pos { x: x2, y: y2 })) = (p, q) {
            let s;
            if *x1 == *x2 && *y1 == -y2 {
                return None;
            } else if *x1 == *x2 && *y1 == *y2 {
                s = mod_div(&(3 * x1 * x1 + &self.a), &(2 * y1), &self.p);
            } else {
                s = mod_div(&(y1 - y2), &(x1 - x2), &self.p);
            }
            let x_new = (&s * &s - x1 - x2).mod_floor(&self.p);
            let y_new = (&s * (x1 - &x_new) - y1).mod_floor(&self.p);
            Some(Pos { x: x_new, y: y_new })
        } else if *p == self.identity() {
            q.clone()
        } else {
            p.clone()
        }
    }
    fn neg(&self, p: &Self::Point) -> Self::Point {
        match p {
            Some(Pos { x, y }) => Some(Pos {
                x: x.clone(),
                y: -y,
            }),
            None => None,
        }
    }
    fn validate(&self, p: &Self::Point) -> bool {
        match p {
            None => true,
            Some(Pos { x, y }) => {
                (y * y).mod_floor(&self.p)
                    == ((x * x * x).mod_floor(&self.p) + (&self.a * x).mod_floor(&self.p) + &self.b)
                        .mod_floor(&self.p)
            }
        }
    }
    fn to_bigint(p: &Self::Point) -> &BigInt {
        &p.as_ref().unwrap().x
    }
}

impl AddGroup for MontgomeryCurve {
    type Point = Option<Pos>;
    fn identity(&self) -> Self::Point {
        None
    }
    fn generator(&self) -> &Self::Point {
        &self.g
    }
    fn order(&self) -> &BigInt {
        &self.n
    }
    fn add(&self, p: &Self::Point, q: &Self::Point) -> Self::Point {
        if let (Some(Pos { x: x1, y: y1 }), Some(Pos { x: x2, y: y2 })) = (p, q) {
            let s;
            if *x1 == *x2 && *y1 == -y2 {
                return None;
            } else if *x1 == *x2 && *y1 == *y2 {
                s = mod_div(
                    &(3 * x1 * x1 + 2 * &self.a * x1 + 1),
                    &(2 * &self.b * y1),
                    &self.p,
                );
            } else {
                s = mod_div(&(y1 - y2), &(x1 - x2), &self.p);
            }
            let x_new = (&self.b * &s * &s - &self.a - x1 - x2).mod_floor(&self.p);
            let y_new = (&s * (x1 - &x_new) - y1).mod_floor(&self.p);
            Some(Pos { x: x_new, y: y_new })
        } else if *p == self.identity() {
            q.clone()
        } else {
            p.clone()
        }
    }
    fn neg(&self, p: &Self::Point) -> Self::Point {
        match p {
            Some(Pos { x, y }) => Some(Pos {
                x: x.clone(),
                y: -y,
            }),
            None => None,
        }
    }
    fn validate(&self, p: &Self::Point) -> bool {
        match p {
            None => true,
            Some(Pos { x, y }) => {
                (&self.b * y * y).mod_floor(&self.p)
                    == ((x * x * x).mod_floor(&self.p) + (&self.a * x * x).mod_floor(&self.p) + x)
                        .mod_floor(&self.p)
            }
        }
    }
    fn to_bigint(p: &Self::Point) -> &BigInt {
        &p.as_ref().unwrap().x
    }
}

impl AddGroup for TwistedEdwardsCurve {
    type Point = Pos;
    fn identity(&self) -> Self::Point {
        Pos {
            x: zero(),
            y: one(),
        }
    }
    fn generator(&self) -> &Self::Point {
        &self.b
    }
    fn order(&self) -> &BigInt {
        &self.l
    }
    fn double(&self, p: &Self::Point) -> Self::Point {
        let Pos { x, y } = p;
        Pos {
            x: mod_div(&(2 * x * y), &(&self.a * x * x + y * y), &self.p),
            y: mod_div(
                &(y * y - &self.a * x * x),
                &(2 - &self.a * x * x - y * y),
                &self.p,
            ),
        }
    }
    fn add(&self, p: &Self::Point, q: &Self::Point) -> Self::Point {
        if *p == *q {
            self.double(p)
        } else {
            let f = |n| BigInt::mod_floor(&n, &self.p);
            let Pos { x: x1, y: y1 } = p;
            let Pos { x: x2, y: y2 } = q;
            Pos {
                x: mod_div(
                    &(x1 * y2 + x2 * y1),
                    &(1 + f(&self.d * x1 * x2) * y1 * y2),
                    &self.p,
                ),
                y: mod_div(
                    &(y1 * y2 - &self.a * x1 * x2),
                    &(1 - f(&self.d * x1 * x2) * y1 * y2),
                    &self.p,
                ),
            }
        }
    }
    fn neg(&self, p: &Self::Point) -> Self::Point {
        Pos {
            x: -&p.x,
            y: p.y.clone(),
        }
    }
    fn validate(&self, p: &Self::Point) -> bool {
        let Pos { x, y } = p;
        (&self.a * x * x + y * y).mod_floor(&self.p)
            == (one::<BigInt>() + (&self.d * x * x).mod_floor(&self.p) * y * y).mod_floor(&self.p)
    }
    fn to_bigint(p: &Self::Point) -> &BigInt {
        &p.y
    }
}

impl<C: AddGroup> Point<C> {
    pub fn validate(&self) -> bool {
        self.curve.validate(&self.pos)
    }
    pub fn to_bigint(&self) -> &BigInt {
        C::to_bigint(&self.pos)
    }
}

impl<'a, 'b, C: AddGroup> Add<&'b Point<C>> for &'a Point<C> {
    type Output = Point<C>;
    fn add(self, other: &'b Point<C>) -> Point<C> {
        Point::<C> {
            curve: self.curve,
            pos: self.curve.add(&self.pos, &other.pos),
        }
    }
}
impl<'a, C: AddGroup> Add<&'a Point<C>> for Point<C> {
    type Output = Point<C>;
    fn add(self, other: &Point<C>) -> Point<C> {
        &self + other
    }
}
impl<'a, C: AddGroup> Add<Point<C>> for &'a Point<C> {
    type Output = Point<C>;
    fn add(self, other: Point<C>) -> Point<C> {
        self + &other
    }
}
impl<C: AddGroup> Add<Point<C>> for Point<C> {
    type Output = Point<C>;
    fn add(self, other: Point<C>) -> Point<C> {
        &self + &other
    }
}

impl<'a, 'b, C: AddGroup> Mul<&'b BigInt> for &'a Point<C> {
    type Output = Point<C>;
    fn mul(self, n: &BigInt) -> Point<C> {
        Point::<C> {
            curve: self.curve,
            pos: self.curve.mul(n, &self.pos),
        }
    }
}
impl<'a, C: AddGroup> Mul<&'a BigInt> for Point<C> {
    type Output = Point<C>;
    fn mul(self, n: &BigInt) -> Point<C> {
        &self * n
    }
}
impl<'a, C: AddGroup> Mul<BigInt> for &'a Point<C> {
    type Output = Point<C>;
    fn mul(self, n: BigInt) -> Point<C> {
        self * &n
    }
}
impl<C: AddGroup> Mul<BigInt> for Point<C> {
    type Output = Point<C>;
    fn mul(self, n: BigInt) -> Point<C> {
        &self * &n
    }
}
impl<'a, 'b, C: AddGroup> Mul<&'b Point<C>> for &'a BigInt {
    type Output = Point<C>;
    fn mul(self, p: &Point<C>) -> Point<C> {
        p * self
    }
}
impl<'a, C: AddGroup> Mul<&'a Point<C>> for BigInt {
    type Output = Point<C>;
    fn mul(self, p: &Point<C>) -> Point<C> {
        p * &self
    }
}
impl<'a, C: AddGroup> Mul<Point<C>> for &'a BigInt {
    type Output = Point<C>;
    fn mul(self, p: Point<C>) -> Point<C> {
        &p * self
    }
}
impl<C: AddGroup> Mul<Point<C>> for BigInt {
    type Output = Point<C>;
    fn mul(self, p: Point<C>) -> Point<C> {
        &p * &self
    }
}

impl<'a, C: AddGroup> Neg for &'a Point<C> {
    type Output = Point<C>;
    fn neg(self) -> Point<C> {
        Point::<C> {
            curve: self.curve,
            pos: self.curve.neg(&self.pos),
        }
    }
}
impl<C: AddGroup> Neg for Point<C> {
    type Output = Point<C>;
    fn neg(self) -> Point<C> {
        -&self
    }
}

impl<'a, 'b, C: AddGroup> Sub<&'b Point<C>> for &'a Point<C> {
    type Output = Point<C>;
    fn sub(self, other: &Point<C>) -> Point<C> {
        Point::<C> {
            curve: self.curve,
            pos: self.curve.sub(&self.pos, &other.pos),
        }
    }
}
impl<'a, C: AddGroup> Sub<&'a Point<C>> for Point<C> {
    type Output = Point<C>;
    fn sub(self, other: &Point<C>) -> Point<C> {
        &self - other
    }
}
impl<'a, C: AddGroup> Sub<Point<C>> for &'a Point<C> {
    type Output = Point<C>;
    fn sub(self, other: Point<C>) -> Point<C> {
        self - &other
    }
}
impl<C: AddGroup> Sub<Point<C>> for Point<C> {
    type Output = Point<C>;
    fn sub(self, other: Point<C>) -> Point<C> {
        &self - &other
    }
}

// impl<C: AddGroup> PartialEq for Point<C> {
//     fn eq(&self, other: &Self) -> bool {
//         self.curve == other.curve && self.pos == other.pos
//     }
// }
// impl<C: AddGroup> Eq for Point<C> {}
