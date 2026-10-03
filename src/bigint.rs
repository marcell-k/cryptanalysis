use std::cmp::Ordering;
use std::fs::File;
use std::io::Read;

/// Unsigned big integer. Little-endian u32 limbs, no trailing zero limbs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BigUint {
    limbs: Vec<u32>,
}

impl BigUint {
    pub fn zero() -> Self {
        BigUint { limbs: Vec::new() }
    }

    pub fn from_u32(n: u32) -> Self {
        let mut r = BigUint { limbs: vec![n] };
        r.trim();
        r
    }

    fn trim(&mut self) {
        while self.limbs.last() == Some(&0) {
            self.limbs.pop();
        }
    }

    pub fn is_zero(&self) -> bool {
        self.limbs.is_empty()
    }

    pub fn bits(&self) -> usize {
        match self.limbs.last() {
            None => 0,
            Some(&top) => (self.limbs.len() - 1) * 32 + (32 - top.leading_zeros() as usize),
        }
    }

    fn bit(&self, i: usize) -> bool {
        self.limbs
            .get(i / 32)
            .is_some_and(|l| (l >> (i % 32)) & 1 == 1)
    }

    // --- conversions ---

    pub fn from_bytes_be(bytes: &[u8]) -> Self {
        let limbs = bytes
            .rchunks(4)
            .map(|c| c.iter().fold(0u32, |v, &b| (v << 8) | b as u32))
            .collect();
        let mut r = BigUint { limbs };
        r.trim();
        r
    }

    pub fn to_bytes_be(&self) -> Vec<u8> {
        let mut out: Vec<u8> = self
            .limbs
            .iter()
            .rev()
            .flat_map(|l| l.to_be_bytes())
            .collect();
        let first = out.iter().position(|&b| b != 0).unwrap_or(out.len());
        out.drain(..first);
        out
    }

    /// Whitespace is ignored, so RFC text can be pasted directly.
    pub fn from_hex(s: &str) -> Option<Self> {
        let digits: Vec<u32> = s
            .chars()
            .filter(|c| !c.is_whitespace())
            .map(|c| c.to_digit(16))
            .collect::<Option<_>>()?;
        let limbs = digits
            .rchunks(8)
            .map(|c| c.iter().fold(0u32, |v, &d| (v << 4) | d))
            .collect();
        let mut r = BigUint { limbs };
        r.trim();
        Some(r)
    }

    // --- arithmetic ---

    pub fn add(&self, other: &Self) -> Self {
        let (a, b) = if self.limbs.len() >= other.limbs.len() {
            (&self.limbs, &other.limbs)
        } else {
            (&other.limbs, &self.limbs)
        };
        let mut out = Vec::with_capacity(a.len() + 1);
        let mut carry = 0u64;
        for (i, v) in a.iter().enumerate() {
            let s = *v as u64 + *b.get(i).unwrap_or(&0) as u64 + carry;
            out.push(s as u32);
            carry = s >> 32;
        }
        out.push(carry as u32);
        let mut r = BigUint { limbs: out };
        r.trim();
        r
    }

    pub fn sub(&self, other: &Self) -> Self {
        assert!(self >= other, "BigUint subtraction underflow");
        let mut out = Vec::with_capacity(self.limbs.len());
        let mut borrow = 0i64;
        for i in 0..self.limbs.len() {
            let mut t = self.limbs[i] as i64 - *other.limbs.get(i).unwrap_or(&0) as i64 - borrow;
            if t < 0 {
                t += 1 << 32;
                borrow = 1;
            } else {
                borrow = 0;
            }
            out.push(t as u32);
        }
        let mut r = BigUint { limbs: out };
        r.trim();
        r
    }

    pub fn mul(&self, other: &Self) -> Self {
        if self.is_zero() || other.is_zero() {
            return Self::zero();
        }
        let (a, b) = (&self.limbs, &other.limbs);
        let mut res = vec![0u32; a.len() + b.len()];
        for i in 0..a.len() {
            let mut carry = 0u64;
            for j in 0..b.len() {
                // max (2^32-1)^2 + 2(2^32-1) = 2^64-1, fits
                let t = a[i] as u64 * b[j] as u64 + res[i + j] as u64 + carry;
                res[i + j] = t as u32;
                carry = t >> 32;
            }
            res[i + b.len()] = carry as u32;
        }
        let mut r = BigUint { limbs: res };
        r.trim();
        r
    }

    /// Returns (quotient, remainder). Knuth TAOCP vol. 2, Algorithm D.
    pub fn divrem(&self, d: &Self) -> (Self, Self) {
        assert!(!d.is_zero(), "division by zero");
        if self < d {
            return (Self::zero(), self.clone());
        }

        // single-limb divisor: simple long division
        if d.limbs.len() == 1 {
            let dv = d.limbs[0] as u64;
            let mut q = vec![0u32; self.limbs.len()];
            let mut rem = 0u64;
            for i in (0..self.limbs.len()).rev() {
                let cur = (rem << 32) | self.limbs[i] as u64;
                q[i] = (cur / dv) as u32;
                rem = cur % dv;
            }
            let mut q = BigUint { limbs: q };
            q.trim();
            return (q, Self::from_u32(rem as u32));
        }

        const B: u64 = 1 << 32;
        let n = d.limbs.len();
        let m = self.limbs.len() - n;

        // D1: normalize so the top bit of the divisor's top limb is set
        let s = d.limbs[n - 1].leading_zeros();
        let mut u = shl_bits(&self.limbs, s); // len = self.len + 1
        let mut v = shl_bits(&d.limbs, s);
        v.pop(); // top limb is 0 after normalization

        let mut q = vec![0u32; m + 1];

        for j in (0..=m).rev() {
            // D3: estimate quotient digit
            let num = ((u[j + n] as u64) << 32) | u[j + n - 1] as u64;
            let mut qhat = num / v[n - 1] as u64;
            let mut rhat = num % v[n - 1] as u64;
            while qhat >= B || qhat * v[n - 2] as u64 > ((rhat << 32) | u[j + n - 2] as u64) {
                qhat -= 1;
                rhat += v[n - 1] as u64;
                if rhat >= B {
                    break;
                }
            }

            // D4: multiply and subtract
            let mut borrow = 0i64;
            let mut carry = 0u64;
            for i in 0..n {
                let p = qhat * v[i] as u64 + carry;
                carry = p >> 32;
                let t = u[i + j] as i64 - borrow - (p & 0xFFFF_FFFF) as i64;
                u[i + j] = t as u32;
                borrow = if t < 0 { 1 } else { 0 };
            }
            let t = u[j + n] as i64 - borrow - carry as i64;
            u[j + n] = t as u32;

            // D5/D6: if we subtracted too much, add back once
            if t < 0 {
                qhat -= 1;
                let mut c = 0u64;
                for i in 0..n {
                    let sum = u[i + j] as u64 + v[i] as u64 + c;
                    u[i + j] = sum as u32;
                    c = sum >> 32;
                }
                u[j + n] = (u[j + n] as u64 + c) as u32;
            }
            q[j] = qhat as u32;
        }

        // D8: denormalize remainder
        let mut r = vec![0u32; n];
        for i in 0..n {
            r[i] = if s == 0 {
                u[i]
            } else {
                (u[i] >> s) | (u[i + 1] << (32 - s))
            };
        }
        let mut q = BigUint { limbs: q };
        let mut r = BigUint { limbs: r };
        q.trim();
        r.trim();
        (q, r)
    }

    pub fn rem(&self, m: &Self) -> Self {
        self.divrem(m).1
    }

    /// self^exp mod m, left-to-right square-and-multiply.
    pub fn modpow(&self, exp: &Self, m: &Self) -> Self {
        let mut result = Self::from_u32(1).rem(m);
        let base = self.rem(m);
        for i in (0..exp.bits()).rev() {
            result = result.mul(&result).rem(m);
            if exp.bit(i) {
                result = result.mul(&base).rem(m);
            }
        }
        result
    }

    /// Uniform-ish random value in [lo, hi). Draws 64 extra bits so modulo bias is negligible.
    pub fn random_range(lo: &Self, hi: &Self) -> Self {
        let span = hi.sub(lo);
        let nbytes = span.bits().div_ceil(8) + 8;
        let mut buf = vec![0u8; nbytes];
        File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut buf))
            .expect("failed to read /dev/urandom");
        Self::from_bytes_be(&buf).rem(&span).add(lo)
    }
}

/// Shift limbs left by `s` (< 32) bits. Output has one extra limb.
fn shl_bits(a: &[u32], s: u32) -> Vec<u32> {
    let mut out = vec![0u32; a.len() + 1];
    if s == 0 {
        out[..a.len()].copy_from_slice(a);
        return out;
    }
    for i in 0..a.len() {
        out[i] |= a[i] << s;
        out[i + 1] = a[i] >> (32 - s);
    }
    out
}

impl PartialOrd for BigUint {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BigUint {
    fn cmp(&self, other: &Self) -> Ordering {
        self.limbs
            .len()
            .cmp(&other.limbs.len())
            .then_with(|| self.limbs.iter().rev().cmp(other.limbs.iter().rev()))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn n(s: &str) -> BigUint {
        BigUint::from_hex(s).unwrap()
    }

    #[test]
    fn test_hex_and_bytes_roundtrip() {
        let x = n("0123456789ABCDEF0011223344556677");
        assert_eq!(BigUint::from_bytes_be(&x.to_bytes_be()), x);
        assert_eq!(x.to_bytes_be()[0], 0x01);
    }

    #[test]
    fn test_modpow_toy_dh() {
        let p = BigUint::from_u32(23);
        let g = BigUint::from_u32(5);
        assert_eq!(g.modpow(&BigUint::from_u32(6), &p), BigUint::from_u32(8));
        assert_eq!(g.modpow(&BigUint::from_u32(15), &p), BigUint::from_u32(19));
    }

    #[test]
    fn test_divrem_identity() {
        // a == q*d + r and r < d, including cases that trigger the add-back step
        let cases = [
            ("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "FFFFFFFF00000001"),
            (
                "80000000000000000000000000000000",
                "800000000000000000000001",
            ),
            (
                "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
                "FEDCBA9876543210FEDCBA98",
            ),
            (
                "FFFFFFFF00000000FFFFFFFF00000000",
                "FFFFFFFF0000000100000000",
            ),
        ];
        for (a, d) in cases {
            let (a, d) = (n(a), n(d));
            let (q, r) = a.divrem(&d);
            assert!(r < d);
            assert_eq!(q.mul(&d).add(&r), a);
        }
    }
}
