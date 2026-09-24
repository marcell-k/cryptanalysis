use std::{collections::HashMap, fs, io};

pub const ALPHABET: [char; 26] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
];
pub const BIGRAMS: [&str; 10] = ["TH", "HE", "IN", "ER", "AN", "RE", "ON", "AT", "EN", "ND"];
pub const TRIGRAMS: [&str; 8] = ["THE", "AND", "ING", "ENT", "ION", "HER", "FOR", "THA"];

// word shapes: ABAC, ABBC, ABCCD, ABCADB, ABBCDE
// Word shapes become especially useful when combined with frequency clues. If a common four-letter ciphertext word has the shape ABBC, and the surrounding partial plaintext suggests a verb or noun, the list of possibilities narrows quickly.

const COMMON_FILE: &str = "common.txt";
pub(crate) const COMMON_ENGLISH: &str = "I WOKE UP EARLY TODAY SHE LIKES COFFEE IN THE MORNING WE WENT TO THE STORE YESTERDAY HE IS WATCHING TV RIGHT NOW THEY LIVE IN A SMALL APARTMENT CAN YOU HELP ME WITH THIS I DONT UNDERSTAND THE QUESTION SHE WORKS AT A HOSPITAL WERE PLANNING A TRIP NEXT MONTH ILL CALL YOU LATER TONIGHT JACK FIXED THE BROKEN ZIPPER QUICKLY THE LAZY FOX JUMPED OVER SIX BOXES MY UNCLE OWNS A DOZEN ANTIQUE CLOCKS WE WATCHED FIREWORKS EXPLODE AT MIDNIGHT ZEBRAS GRAZED NEXT TO THE OLD JUNKYARD";
pub fn count_chars(cipher: &str) -> HashMap<char, u16> {
    let mut map = HashMap::new();
    for c in cipher.replace(' ', "").chars() {
        map.entry(c)
            .and_modify(|counter| *counter += 1)
            .or_insert(1);
    }
    map
}

// IC range 0.038 (random) to 0.067 (English). Close to 0.067 = valid English or mono-alphabetic cipher.
pub fn index_of_coincidence(cipher: &str) -> f64 {
    let counts = count_chars(cipher);
    let n: u64 = counts.values().map(|&c| c as u64).sum();
    let numerator: u64 = counts.values().map(|&c| (c as u64) * (c as u64 - 1)).sum();
    let n = n as f64;
    numerator as f64 / (n * (n - 1.))
}

pub fn load_or_build_common() -> io::Result<HashMap<char, u16>> {
    if fs::exists(COMMON_FILE)? {
        let data = fs::read_to_string(COMMON_FILE)?;
        let common: HashMap<char, u16> = serde_json::from_str(&data)?;
        Ok(common)
    } else {
        let common = count_chars(COMMON_ENGLISH);
        let serialized = serde_json::to_string(&common)?;
        fs::write(COMMON_FILE, serialized)?;
        Ok(common)
    }
}

pub fn chi_square_scoring(res: &str, common: &HashMap<char, u16>) -> f64 {
    let map = count_chars(res);
    let res_total: f64 = map.values().sum::<u16>() as f64;
    let common_total: f64 = common.values().sum::<u16>() as f64;
    let mut score = 0.0;
    for ch in ALPHABET {
        let observed = *map.get(&ch).unwrap_or(&0) as f64 / res_total;
        let expected = *common.get(&ch).unwrap_or(&1) as f64 / common_total;
        score += (observed - expected).powi(2) / expected;
    }
    score
}

pub fn count_ngrams(res: &str, ngrams: &[&str]) -> f64 {
    let n = ngrams[0].len();
    assert!(ngrams.iter().all(|ngram| ngram.len() == n));
    let mut count_map: HashMap<String, u16> = HashMap::new();

    if res.len() < n {
        return 0.0;
    }

    let chars: Vec<char> = res.chars().collect();
    for window in chars.windows(n) {
        let gram: String = window.iter().collect();
        count_map
            .entry(gram)
            .and_modify(|counter| *counter += 1)
            .or_insert(1);
    }

    let total: u16 = count_map.values().sum::<u16>();
    let mut hits = 0u16;
    for gram in ngrams {
        hits += count_map.get(*gram).copied().unwrap_or(0);
    }
    hits as f64 / total as f64
}
