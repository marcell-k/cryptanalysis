//! Frequency analysis
//! is the study of how often letters, symbols, pairs of letters, triples of letters,
//! and other patterns occur in a ciphertext. It does not necessarily require the key. It does not always
//! require knowing the exact cipher. It begins with a simpler question: **what does this ciphertext do often**?

use freq_analysis::decode;

fn main() -> anyhow::Result<()> {
    let cipher = String::from("WKH TXLFN EURZQ IRA MXPSV RYHU WKH ODCB GRJ");
    decode(cipher)
}
