use std::collections::HashMap;

use crate::util::{count_chars, load_or_build_common};

// Alberti disks
pub const OUTER_DISKS: [char; 24] = [
    '1', '2', '3', '4', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'I', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
    'S', 'T', 'V', 'X', 'Z',
];
pub const INNER_DISKS: [char; 24] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
    'V', 'X', 'Y', 'Z', '&',
];

pub fn alberti_encrypt(
    message: String,
    inital_char: char,
    period: usize,
) -> anyhow::Result<String> {
    let mut out = String::with_capacity(message.len());
    let initial_shift = INNER_DISKS
        .iter()
        .position(|ch| ch == &inital_char)
        .unwrap();
    let mut pos = 0usize;
    let period_step = 2;

    for ch in message.chars() {
        let outer_idx = match OUTER_DISKS.iter().position(|c| c == &ch) {
            Some(idx) => idx,
            None => {
                out.push(ch);
                continue;
            }
        };
        let mut idx = (outer_idx + initial_shift) % OUTER_DISKS.len();
        idx = ((pos / period) * period_step + idx) % INNER_DISKS.len();
        out.push(*INNER_DISKS.get(idx).unwrap());
        pos += 1;
    }

    println!("Encoded message  : {}, using alberti", out);
    Ok(out)
}

// NOTE: assumptions we know OUTER_DISKS, and INNER_DISKS
pub fn alberti_decrypt(cipher: String) -> anyhow::Result<String> {
    let common = load_or_build_common().unwrap();

    let periods: Vec<usize> = (1..=cipher.len()).collect();
    let period_steps: Vec<usize> = (1..=INNER_DISKS.len()).collect();
    let initial_chars: Vec<char> = INNER_DISKS.to_vec();

    let mut best_value = f64::MAX;
    let mut best = String::with_capacity(cipher.len());

    for init_char in initial_chars.iter() {
        for period in periods.iter() {
            for period_step in period_steps.iter() {
                let decoded_message =
                    alberti_crack(&cipher, *init_char, *period, *period_step).unwrap();
                let value = chi_square_score(&decoded_message, &common);
                if value < best_value {
                    best_value = value;
                    eprintln!("{}", decoded_message);
                    best = decoded_message
                }
            }
        }
    }

    eprintln!("{}", best_value);
    Ok(best)
}

fn alberti_crack(
    cipher: &str,
    initial_char: char,
    period: usize,
    period_step: usize,
) -> anyhow::Result<String> {
    let mut message = String::with_capacity(cipher.len());
    let mut pos = 0usize;
    let initial_shift = INNER_DISKS
        .iter()
        .position(|ch| ch == &initial_char)
        .unwrap();

    for ch in cipher.chars() {
        let mut idx = match INNER_DISKS.iter().position(|c| c == &ch) {
            Some(idx) => idx,
            None => {
                message.push(ch);
                continue;
            }
        };
        let shift_amount = (pos / period * period_step) % INNER_DISKS.len();
        idx = (idx + INNER_DISKS.len() - initial_shift) % INNER_DISKS.len();
        idx = (idx + INNER_DISKS.len() - shift_amount) % INNER_DISKS.len();
        message.push(*OUTER_DISKS.get(idx).unwrap());
        pos += 1;
    }

    Ok(message)
}

fn chi_square_score(message: &str, common: &HashMap<char, usize>) -> f64 {
    let map = count_chars(message);
    let msg_len = message.len() as f64;
    let common_total = common.values().sum::<usize>() as f64;
    // add smoothing , so near-zero expected chars are  not infinitely penalized
    let smoothing = 0.5;
    let num_symbols = OUTER_DISKS.len() as f64; // 24

    let mut score = 0.;
    for ch in OUTER_DISKS.iter().chain(INNER_DISKS.iter()) {
        let observed = *map.get(ch).unwrap_or(&0) as f64 / msg_len;
        let expected = (*common.get(ch).unwrap_or(&0) as f64 + smoothing)
            / (common_total + smoothing * num_symbols);
        score += (observed - expected).powi(2) / expected;
    }
    score
}

#[cfg(test)]
mod test {
    use crate::{alberti_decrypt, alberti_encrypt, cipher::alberti::alberti_crack};

    #[test]
    fn test_alberti_encrypt() {
        assert_eq!(
            "EFGHI".to_string(),
            alberti_encrypt("ABCDE".to_string(), 'A', 8).unwrap()
        );
        assert_eq!(
            "GKDGKNK&".to_string(),
            alberti_encrypt("DE1234XG".to_string(), '&', 1).unwrap()
        );
    }

    #[test]
    fn test_alberti_roundtrip() {
        let message = "SENDGOLDANDSILVERTOROMEATNOON".to_string();
        let encrypted = alberti_encrypt(message.clone(), '&', 1).unwrap();
        let decrypted = alberti_crack(&encrypted, '&', 1, 2).unwrap();
        let decoded_message = alberti_decrypt(encrypted).unwrap();
        assert_eq!(message, decrypted);
        assert_eq!(message, decoded_message);
    }

    #[test]
    fn test_alberti_crack() {
        let cipher = String::from("GKDGKNK&");
        assert_eq!(
            "DE1234XG".to_string(),
            alberti_crack(&cipher, '&', 1, 2).unwrap()
        );
    }
}
