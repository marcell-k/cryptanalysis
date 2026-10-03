use crate::bigint::BigUint;
use crate::sha256::sha256;

// RFC 3526 group 14 (2048-bit MODP). `[link](https://www.rfc-editor.org/info/rfc3526/#section-3)`
const P_HEX: &str = "
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08 8A67CC74
020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B 302B0A6D F25F1437
4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D C2007CB8 A163BF05
98DA4836 1C55D39A 69163FA8 FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB
9ED52907 7096966D 670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718
3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AACAA68 FFFFFFFF FFFFFFFF";

fn prime() -> BigUint {
    BigUint::from_hex(P_HEX).expect("valid hex")
}

pub struct Party {
    private: BigUint,
    pub public: BigUint,
}

impl Default for Party {
    fn default() -> Self {
        Self::new()
    }
}

impl Party {
    pub fn new() -> Self {
        let p = prime();
        let one = BigUint::from_u32(1);
        // a in [2, p-2]
        let a = BigUint::random_range(&BigUint::from_u32(2), &p.sub(&one));
        let public = BigUint::from_u32(2).modpow(&a, &p); // g = 2
        Party { private: a, public }
    }

    pub fn shared_key(&self, other_public: &BigUint) -> Option<[u8; 32]> {
        let p = prime();
        let one = BigUint::from_u32(1);
        // reject 0, 1, p-1 and out-of-range values
        if *other_public <= one || *other_public >= p.sub(&one) {
            return None;
        }
        let s = other_public.modpow(&self.private, &p);
        Some(sha256(&s.to_bytes_be())) // stand-in KDF
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_prime_looks_right() {
        let p = prime();
        assert_eq!(p.bits(), 2048);
        // Fermat check: catches a typo in the pasted hex
        let one = BigUint::from_u32(1);
        assert_eq!(BigUint::from_u32(2).modpow(&p.sub(&one), &p), one);
    }

    #[test]
    fn test_both_sides_agree() {
        let alice = Party::new();
        let bob = Party::new();
        assert_eq!(alice.shared_key(&bob.public), bob.shared_key(&alice.public));
    }
}
