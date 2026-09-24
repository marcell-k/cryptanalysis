use std::{collections::HashMap, fs, io};

pub const ALPHABET: [char; 26] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
];
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
    let mut res = 0.0;
    for ch in ALPHABET {
        let value = (*map.get(&ch).unwrap() as f64 - *common.get(&ch).unwrap() as f64)
            / *common.get(&ch).unwrap() as f64;
        res += value.powi(2);
    }
    res
}
