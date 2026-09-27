use freq_analysis::*;

fn assert_roundtrip(
    label: &str,
    message: &str,
    encrypt: impl FnOnce(String) -> anyhow::Result<String>,
    decrypt: impl FnOnce(String) -> anyhow::Result<String>,
) {
    let cipher =
        encrypt(message.to_string()).unwrap_or_else(|e| panic!("[{label}] encrypt failed: {e}"));
    let recovered =
        decrypt(cipher.clone()).unwrap_or_else(|e| panic!("[{label}] decrypt failed: {e}"));
    assert_eq!(
        message, recovered,
        "[{label}] roundtrip mismatch\n  cipher: {cipher}"
    );
}

const MESSAGE: &str = "BE PATIENT TILL THE LAST ROMANS COUNTRYMEN AND LOVERS HEAR ME FOR MY CAUSE";

#[test]
fn caesar_roundtrip() {
    assert_roundtrip(
        "caesar",
        MESSAGE,
        |m| caesar_encrypt(m, 7),
        |c| caesar_crack(c).map(|(msg, _, _)| msg),
    );
}

#[test]
fn affine_roundtrip() {
    assert_roundtrip(
        "affine",
        MESSAGE,
        |m| affine_encrypt(m, 7, 2),
        affine_decrypt,
    );
}

#[test]
fn vigenere_roundtrip() {
    let key = "KEYWORD".to_string();
    let key2 = key.clone();
    assert_roundtrip(
        "vigenere",
        MESSAGE,
        move |m| vigenere_encrypt(m, key),
        move |c| vigenere_decrypt(c, key2),
    );
}

#[test]
fn scytale_roundtrip() {
    let cipher = scytale_encrypt(MESSAGE.to_string(), 4).unwrap();
    let recovered = scytale_decrypt(cipher).unwrap();
    assert_eq!(MESSAGE, &recovered[..MESSAGE.len()]);
}

#[test]
fn alberti_roundtrip() {
    assert_roundtrip(
        "alberti",
        "SEND MORE GOLD AND SILVER TO ROME AT NOON",
        |m| alberti_encrypt(m, 'A', 3),
        alberti_decrypt,
    );
}
