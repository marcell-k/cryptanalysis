use std::collections::HashMap;

use crate::Result;
use crate::util::{english_frequencies, key_indices};

pub const ALPHABET: [char; 20] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'V',
    'X',
];

// for each character: `(w[i] + k[i]) % 20`
pub fn bellaso_encrypt(message: String, key: String) -> Result<String> {
    let key = key_indices(&key, &ALPHABET)?;
    let mut out = String::with_capacity(message.len());
    let mut key_pos = 0usize;
    for ch in message.chars() {
        if let Some(idx) = ALPHABET.iter().position(|c| *c == ch) {
            out.push(ALPHABET[(idx + key[key_pos % key.len()]) % 20]);
            key_pos += 1;
        } else {
            out.push(ch);
        }
    }
    println!("Encoded message  : {}, using bellaso", out);
    Ok(out)
}

// for each character `(c[i] - k[i] + 20) % 20 == m[i]`
pub fn bellaso_decrypt(cipher: String, key: String) -> Result<String> {
    let key = key_indices(&key, &ALPHABET)?;
    let mut out = String::with_capacity(cipher.len());

    let mut key_pos = 0usize;
    for ch in cipher.chars() {
        if let Some(cipher_idx) = ALPHABET.iter().position(|c| *c == ch) {
            out.push(ALPHABET[(cipher_idx + 20 - key[key_pos % key.len()]) % 20]);
            key_pos += 1;
        } else {
            out.push(ch);
        }
    }
    println!("Decrypted message: {}, using bellaso", out);

    Ok(out)
}

pub fn key_lengths(cipher: String) -> Vec<usize> {
    let cipher: String = cipher.chars().filter(|c| ALPHABET.contains(c)).collect();
    let chars: Vec<char> = cipher.chars().collect();

    let mut out = HashMap::new();

    for i in 2..cipher.len() / 2 {
        let indexes = ngram_distances(&chars, i);
        for (k, v) in indexes {
            out.entry(k).and_modify(|c| *c += v).or_insert(v * i);
        }
    }
    // eprintln!("{:?}", out);
    let mut out: Vec<(&usize, &usize)> = out.iter().collect();
    out.sort_by_key(|(_, v)| *v);
    out.reverse();
    out.iter().map(|&(&k, _)| k).collect()
}

fn ngram_distances(chars: &[char], length: usize) -> Vec<(usize, usize)> {
    let mut occurancies: HashMap<String, usize> = HashMap::new();
    // values are the first occurancies of the ngram
    let mut map: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, window) in chars.windows(length).enumerate() {
        let gram: String = window.iter().collect();
        occurancies
            .entry(gram.clone())
            .and_modify(|counter| *counter += 1)
            .or_insert(1);
        map.entry(gram).or_default().push(i);
    }

    let mut indexes: Vec<usize> = Vec::new();
    for value in map.values() {
        if value.len() > 1 {
            for window in value.windows(2) {
                indexes.push(window[1] - window[0]);
            }
        }
    }
    possible_key_lengths(&indexes)
}

pub fn possible_key_lengths(indexes: &[usize]) -> Vec<(usize, usize)> {
    // key = common divisor, value = occurency
    let mut occ: HashMap<usize, usize> = HashMap::new();

    for index in indexes {
        let divs = divisors(*index);
        for div in divs {
            occ.entry(div).and_modify(|c| *c += 1).or_insert(1);
        }
    }
    let mut out: Vec<(&usize, &usize)> = occ.iter().collect();
    out.sort_by_key(|(_, v)| *v);
    out.iter().map(|&(k, v)| (*k, *v)).collect()
}

fn divisors(n: usize) -> Vec<usize> {
    if n < 2 {
        return Vec::with_capacity(0);
    }
    (2..=n).filter(|&i| n.is_multiple_of(i)).collect()
}

fn crack_column(column: &str, common: &HashMap<char, usize>) -> (usize, f64) {
    let n = ALPHABET.len();
    let idxs: Vec<usize> = column
        .chars()
        .filter_map(|c| ALPHABET.iter().position(|a| *a == c))
        .collect();
    if idxs.is_empty() {
        return (0, 0.0);
    }
    let total = idxs.len() as f64;
    let exp_total: f64 = ALPHABET
        .iter()
        .map(|c| *common.get(c).unwrap_or(&0) as f64 + 0.5)
        .sum();

    let mut best = (0, f64::MAX);
    for shift in 0..n {
        let mut counts = [0usize; 20];
        for &i in &idxs {
            counts[(i + n - shift) % n] += 1;
        }
        let mut score = 0.0;
        for (j, ch) in ALPHABET.iter().enumerate() {
            let observed = counts[j] as f64 / total;
            let expected = (*common.get(ch).unwrap_or(&0) as f64 + 0.5) / exp_total;
            score += (observed - expected).powi(2) / expected;
        }
        if score < best.1 {
            best = (shift, score);
        }
    }
    best
}

fn crack_single_shift(cipher: &str, length: usize, common: &HashMap<char, usize>) -> (String, f64) {
    let filtered: Vec<char> = cipher.chars().filter(|c| ALPHABET.contains(c)).collect();
    let mut key = String::with_capacity(length);
    let mut value = 0.;
    for l in 0..length {
        let column: String = filtered.iter().skip(l).step_by(length).collect();
        let (shift, v) = crack_column(&column, common);
        key.push(ALPHABET[shift]);
        value += v;
    }
    (key, value / length as f64)
}

pub fn bellaso_crack(cipher: String) -> Result<String> {
    // 1. find repeating substrings - the key length can be assumed from the distance,
    // `ABC...ABC`factor here is 6, meaning the key length can be 1,2,3,6
    let lengths = key_lengths(cipher.clone());
    let common = english_frequencies();
    let mut lengths: Vec<usize> = lengths.iter().filter(|&v| *v < 10).copied().collect();
    if lengths.is_empty() {
        lengths = (1..10).collect();
    }

    const K: usize = 5;
    let mut possibilites: Vec<(String, f64)> = Vec::with_capacity(K);
    for length in lengths.iter().take(K) {
        let (key, value) = crack_single_shift(&cipher, *length, common);
        possibilites.push((key, value));
    }
    possibilites.sort_by(|a, b| a.1.total_cmp(&b.1));
    let decoded_mesage = bellaso_decrypt(cipher.clone(), possibilites[0].0.clone()).unwrap();
    println!(
        "Key: {}, value: {}",
        possibilites[0].0.clone(),
        possibilites[0].1.clone()
    );

    Ok(decoded_mesage)
}
