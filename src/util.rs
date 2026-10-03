use std::collections::HashMap;
use std::sync::LazyLock;

pub const ALPHABET: [char; 26] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
];
pub const BIGRAMS: [&str; 10] = ["TH", "HE", "IN", "ER", "AN", "RE", "ON", "AT", "EN", "ND"];
pub const TRIGRAMS: [&str; 8] = ["THE", "AND", "ING", "ENT", "ION", "HER", "FOR", "THA"];

// word shapes: ABAC, ABBC, ABCCD, ABCADB, ABBCDE
// Word shapes become especially useful when combined with frequency clues. If a common four-letter ciphertext word has the shape ABBC, and the surrounding partial plaintext suggests a verb or noun, the list of possibilities narrows quickly.

const ENGLISH_FREQ: [(char, usize); 26] = [
    ('A', 82),
    ('B', 15),
    ('C', 28),
    ('D', 43),
    ('E', 127),
    ('F', 22),
    ('G', 20),
    ('H', 61),
    ('I', 70),
    ('J', 2),
    ('K', 8),
    ('L', 40),
    ('M', 24),
    ('N', 67),
    ('O', 75),
    ('P', 19),
    ('Q', 1),
    ('R', 60),
    ('S', 63),
    ('T', 91),
    ('U', 28),
    ('V', 10),
    ('W', 24),
    ('X', 2),
    ('Y', 20),
    ('Z', 1),
];

pub fn count_chars(cipher: &str) -> HashMap<char, usize> {
    let mut map = HashMap::new();
    for c in cipher.replace(' ', "").chars() {
        map.entry(c)
            .and_modify(|counter| *counter += 1)
            .or_insert(1);
    }
    map
}

static COMMON: LazyLock<HashMap<char, usize>> =
    LazyLock::new(|| ENGLISH_FREQ.iter().copied().collect());

pub fn english_frequencies() -> &'static HashMap<char, usize> {
    &COMMON
}

pub fn chi_square_score(res: &str, common: &HashMap<char, usize>) -> f64 {
    let filtered: String = res.chars().filter(|c| ALPHABET.contains(c)).collect();
    let map = count_chars(&filtered);
    let res_total = map.values().sum::<usize>() as f64;
    let common_total = common.values().sum::<usize>() as f64;
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
    let mut count_map: HashMap<String, usize> = HashMap::new();

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

    let total: usize = count_map.values().sum::<usize>();
    let mut hits = 0usize;
    for gram in ngrams {
        hits += count_map.get(*gram).copied().unwrap_or(0);
    }
    hits as f64 / total as f64
}
