// public prime `p` and generator `g`
// A secret `a` and sends `A = g^a mod p`
// B secret `b` and sends `B = g^b mod p`
// A computes `s = B^a mod p`, and B computes `s = A^b mod p`
fn mod_pow(mut base: u128, mut exp: u128, m: u128) -> u128 {
    let mut result = 1u128;
    base %= m;
    while exp > 0 {
        if exp & 1 == 1 {
            result = result * base % m;
        }
        base = base * base % m;
        exp >>= 1;
    }
    result
}

pub fn public_key(g: u128, private: u128, p: u128) -> u128 {
    mod_pow(g, private, p)
}

pub fn shared_secret(their_public: u128, private: u128, p: u128) -> u128 {
    mod_pow(their_public, private, p)
}

#[cfg(test)]
mod test {
    use crate::cipher::diffie_hellman::mod_pow;

    #[test]
    fn test_mod_pow() {
        let p = 23;
        let g = 5;
        assert_eq!(mod_pow(g, 6, p), 8);
        assert_eq!(mod_pow(g, 15, p), 19);
    }
}
