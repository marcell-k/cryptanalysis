use std::collections::BinaryHeap;

use crate::util::{ALPHABET, chi_square_score, load_or_build_common};

// y ≡ αx + β (mod 26)
pub fn affine_encrypt(message: String, a: usize, b: usize) -> anyhow::Result<String> {
    let mut out = String::with_capacity(message.len());

    for ch in message.chars() {
        if ALPHABET.contains(&ch) {
            let mut idx = ALPHABET.iter().position(|c| c == &ch).unwrap();
            idx = (idx * a + b) % 26;
            out.push(ALPHABET[idx]);
        } else {
            out.push(ch);
        }
    }
    println!("Encoded message  : {}, using affine", out);

    Ok(out)
}

// --- decryption ---
#[derive(Clone, Debug)]
struct Res(String, (usize, usize), f64);

impl Eq for Res {}

impl PartialEq for Res {
    // SAFETY: Res value cannot be NAN
    fn eq(&self, other: &Self) -> bool {
        (self.2 - other.2).abs() < 1e-6
    }
}

impl PartialOrd for Res {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Res {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.2.total_cmp(&other.2)
    }
}

pub fn affine_decrypt(cipher: String) -> anyhow::Result<String> {
    let common = load_or_build_common().unwrap();

    // `(decrypted message, key, value)`
    // MinHeap
    let mut results: BinaryHeap<Res> = BinaryHeap::with_capacity(6);

    let search_space = affine_search_space(26);

    for (a, b) in search_space {
        let a_inv = match mod_inverse(a, 26) {
            Some(v) => v,
            None => continue,
        };
        let mut decrypted_message = String::with_capacity(cipher.len());

        for ch in cipher.chars() {
            if ALPHABET.contains(&ch) {
                let mut idx = ALPHABET.iter().position(|c| c == &ch).unwrap();
                idx = (a_inv * (idx + 26 - (b % 26))) % 26;
                decrypted_message.push(ALPHABET[idx]);
            } else {
                decrypted_message.push(ch);
            }
        }

        let likelihood = chi_square_score(&decrypted_message, &common);
        results.push(Res(decrypted_message, (a, b), likelihood));
        if results.len() > 5 {
            results.pop();
        }
    }

    let r: Vec<Res> = results.into_vec();

    let best = r.iter().min_by(|a, b| a.2.total_cmp(&b.2)).unwrap().clone();

    println!("Decrypted message: {}, using Affine", best.0.clone());
    println!("Key: {:?}", best.1);
    Ok(best.0.clone())
}

// TODO: for performance use Euclidean or source [link](https://cp-algorithms.com/algebra/module-inverse.html)
fn mod_inverse(a: usize, m: usize) -> Option<usize> {
    (1..m).find(|&x| (a * x) % m == 1)
}

fn gcd(a: usize, b: usize) -> usize {
    if b == 0 { a } else { gcd(b, a % b) }
}

fn affine_search_space(n: usize) -> Vec<(usize, usize)> {
    let mut search_space: Vec<(usize, usize)> = Vec::new();
    for a in 1..n {
        if gcd(a, n) == 1 {
            for i in 0..n {
                search_space.push((a, i));
            }
        }
    }

    search_space
}
