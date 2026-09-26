use crate::util::{BIGRAMS, TRIGRAMS, count_ngrams};

// Decryption requires to know the number N of letters by turn of the band (the size of the cylinder), or L the number of turns around the cylinder.
pub fn scytale_encrypt(message: String, l: usize) -> anyhow::Result<String> {
    let mut out = String::with_capacity(message.len());

    let n = message.len().div_ceil(l);
    for i in 0..n {
        for j in 0..l {
            let c = message.chars().nth(j * n + i).unwrap_or('X');
            // eprintln!("c:{} i:{} j:{} t:{}", c, i, j, j * n + i);
            out.push(c);
        }
    }

    println!("Encoded message  : {}, using scytale", out);
    Ok(out)
}

// TODO: find efficient way to calc `search_space`
// TODO: improve score calcualtion
pub fn scytale_decrypt(cipher: String) -> anyhow::Result<String> {
    let search_space: Vec<usize> = (1..=cipher.len()).collect();
    let mut best_score = f64::MIN;
    let mut message = String::with_capacity(cipher.len());

    for l in search_space {
        let decoded_message = scytale_crack(&cipher, l).unwrap();
        // eprintln!("{}", decoded_message);
        let bi = count_ngrams(&decoded_message, &BIGRAMS);
        let tri = count_ngrams(&decoded_message, &TRIGRAMS);
        let score = bi * 10. + tri * 15.;
        if score > best_score {
            best_score = score;
            message = decoded_message;
        }
    }
    Ok(message)
}

fn scytale_crack(cipher: &str, l: usize) -> anyhow::Result<String> {
    let chars: Vec<char> = cipher.chars().collect();
    let n = chars.len() / l;
    let mut out = String::with_capacity(chars.len());

    for j in 0..l {
        for i in 0..n {
            // eprintln!("c:{}, i:{}, j:{}, t:{}", chars[i * l + j], i, j, i * l + j);
            out.push(chars[i * l + j]);
        }
    }

    Ok(out)
}

#[cfg(test)]
mod test {
    use crate::cipher::scytale_encrypt;

    #[test]
    fn test_scytale_encrypt() {
        assert_eq!(
            scytale_encrypt(String::from("ABCDE"), 2).unwrap(),
            String::from("ADBECX")
        );

        assert_eq!(
            scytale_encrypt(String::from("ABCDEFGH"), 3).unwrap(),
            String::from("ADGBEHCFX")
        )
    }
}
