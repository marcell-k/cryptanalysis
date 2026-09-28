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
    const LONG_ENGLISH: &str = "BE PATIENT TILL THE LAST ROMANS COUNTRYMEN AND LOVERS HEAR ME FOR MY CAUSE AND BE SILENT THAT YOU MAY HEAR BELIEVE ME FOR MINE HONOUR AND HAVE RESPECT TO MINE HONOUR THAT YOU MAY BELIEVE CENSURE ME IN YOUR WISDOM AND AWAKE YOUR SENSES THAT YOU MAY THE BETTER JUDGE";
    let key = "KEYWORD".to_string();
    let key2 = key.clone();
    assert_roundtrip(
        "vigenere",
        LONG_ENGLISH,
        move |m| vigenere_encrypt(m, key),
        move |c| vigenere_decrypt(c, key2),
    );

    let key = "KEYWORD".to_string();
    assert_roundtrip(
        "vigenere",
        LONG_ENGLISH,
        move |m| vigenere_encrypt(m, key),
        vigenere_crack,
    );
}

#[test]
fn bellaso_roundtrip() {
    let key = "BELLASO".to_string();
    let key2 = key.clone();

    const LONG_BELLASO: &str = "AT NIGHTFALL THE ARMIES MET BESIDE THE RIVER AND BEGAN THE BATTLE THE ENEMIES RETREATED INTO THE HILLS AND THE CAPTAINS CHOSE TO PRESS ON MESSENGERS CARRIED ORDERS ACROSS THE FIELDS BEFORE THE MORNING STARS FADED THE GENERAL SENT MORE SOLDIERS TO HOLD THE BRIDGE AND ORDERED THE ENGINEERS TO DEMOLISH THE ROAD BEHIND THEM IN THE END THE CITADEL OPENED ITS GATES AND THE STORM PASSED";
    assert_roundtrip(
        "bellaso",
        LONG_BELLASO,
        move |m| bellaso_encrypt(m, key),
        move |c| bellaso_decrypt(c, key2),
    );

    let key = "BELLASO".to_string();
    assert_roundtrip(
        "bellaso",
        LONG_BELLASO,
        move |m| bellaso_encrypt(m, key),
        bellaso_crack,
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
