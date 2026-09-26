use std::collections::HashMap;

use crate::cipher::caesar::caesar_crack;
use crate::util::ALPHABET;

// for each character: `(w[i] + k[i]) % 26`
pub fn vigenere_encrypt(message: String, key: String) -> anyhow::Result<String> {
    let mut out = String::with_capacity(message.len());
    for (i, ch) in message.chars().enumerate() {
        let kch = key.chars().nth(i % key.len()).unwrap();
        if ALPHABET.contains(&ch) {
            let idx = ALPHABET.iter().position(|c| c == &ch).unwrap();
            let key_idx = ALPHABET.iter().position(|c| c == &kch).unwrap();
            let idx = (idx + key_idx) % 26;
            out.push(ALPHABET[idx]);
        } else {
            out.push(ch);
        }
    }
    println!("Encoded message  : {}, using Vigenere", out);
    Ok(out)
}

// for each character `(c[i] - k[i] + 26) % 26 == m[i]`
pub fn vigenere_decrypt(cipher: String, key: String) -> anyhow::Result<String> {
    let mut out = String::with_capacity(cipher.len());

    for (i, ch) in cipher.chars().enumerate() {
        let kch = key.chars().nth(i % key.len()).unwrap();
        if ALPHABET.contains(&ch) {
            let cipher_idx = ALPHABET.iter().position(|c| c == &ch).unwrap();
            let key_idx = ALPHABET.iter().position(|c| c == &kch).unwrap();
            let idx = (cipher_idx - key_idx + 26) % 26;
            out.push(ALPHABET[idx]);
        } else {
            out.push(ch);
        }
    }
    println!("Decrypted message: {}, using Viginere", out);

    Ok(out)
}

pub fn key_lengths(cipher: String) -> Vec<usize> {
    let cipher = cipher.replace(' ', "");
    let chars: Vec<char> = cipher.chars().collect();

    let mut out = HashMap::new();

    for i in 2..cipher.len() / 2 {
        let indexes = ngram_distances(&chars, i);
        for (k, v) in indexes {
            out.entry(k).and_modify(|c| *c += v).or_insert(v);
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
    if n <= 2 {
        return Vec::with_capacity(0);
    }
    (2..=n).filter(|&i| n.is_multiple_of(i)).collect()
}

fn crack_single_shift(cipher: String, length: usize) -> (String, f64) {
    let mut key = String::with_capacity(length);
    let mut value = 0.;
    for l in 0..length {
        let chars_seq: String = cipher
            .chars()
            .enumerate()
            .filter(|(i, _)| i % length == l)
            .map(|(_, c)| c)
            .collect();

        let (_s, v, rotation) = caesar_crack(chars_seq).unwrap();

        key.push(*ALPHABET.get(rotation).unwrap());
        value += v;
    }
    (key, value / length as f64)
}

pub fn vigenere_crack(cipher: String) -> anyhow::Result<String> {
    // 1. find repeating substrings - the key length can be assumed from the distance,
    // `ABC...ABC`factor here is 6, meaning the key length can be 1,2,3,6
    let lengths = key_lengths(cipher.clone());
    let lengths: Vec<usize> = lengths.iter().filter(|&v| *v < 10).copied().collect();

    const K: usize = 5;
    let mut possibilites: Vec<(String, f64)> = Vec::with_capacity(K);
    for length in lengths.iter().take(K) {
        let (key, value) = crack_single_shift(cipher.clone(), *length);
        possibilites.push((key, value));
    }
    possibilites.sort_by(|a, b| a.1.total_cmp(&b.1));
    let decoded_mesage = vigenere_decrypt(cipher.clone(), possibilites[0].0.clone()).unwrap();
    println!(
        "Key: {}, value: {}",
        possibilites[0].0.clone(),
        possibilites[0].1.clone()
    );

    Ok(decoded_mesage)
}
