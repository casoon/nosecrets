//! Offline checksum validation for tokens that end in a CRC32 of their body.

/// The one supported algorithm name, as written in `validate.checksum`.
pub const CRC32_BASE62_SUFFIX6: &str = "crc32-base62-suffix6";

const BASE62: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const SUFFIX_LEN: usize = 6;

const CRC_TABLE: [u32; 256] = {
    let mut table = [0_u32; 256];
    let mut index = 0;
    while index < 256 {
        let mut value = index as u32;
        let mut bit = 0;
        while bit < 8 {
            value = if value & 1 == 1 {
                (value >> 1) ^ 0xEDB8_8320
            } else {
                value >> 1
            };
            bit += 1;
        }
        table[index] = value;
        index += 1;
    }
    table
};

/// CRC-32 (IEEE 802.3, as in zlib and PNG).
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFF_u32;
    for byte in data {
        crc = CRC_TABLE[((crc ^ u32::from(*byte)) & 0xFF) as usize] ^ (crc >> 8);
    }
    !crc
}

/// Base62 with the digits first, then upper case, then lower case, left-padded with `0`.
pub fn base62_padded(mut value: u32, width: usize) -> String {
    let mut digits = Vec::new();
    while value > 0 {
        digits.push(BASE62[(value % 62) as usize]);
        value /= 62;
    }
    while digits.len() < width {
        digits.push(BASE62[0]);
    }
    digits.reverse();
    String::from_utf8(digits).expect("base62 digits are ASCII")
}

/// The six-character suffix for `payload`: its CRC-32, base62 encoded and padded.
pub fn suffix6(payload: &str) -> String {
    base62_padded(crc32(payload.as_bytes()), SUFFIX_LEN)
}

/// True if `body` (a token without its prefix) ends in the checksum of everything before it.
pub fn is_valid_suffix6(body: &str) -> bool {
    if body.len() <= SUFFIX_LEN || !body.is_ascii() {
        return false;
    }
    let (payload, suffix) = body.split_at(body.len() - SUFFIX_LEN);
    suffix6(payload) == suffix
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_matches_the_standard_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn base62_is_padded_and_ordered() {
        assert_eq!(base62_padded(0, 6), "000000");
        assert_eq!(base62_padded(61, 6), "00000z");
        assert_eq!(base62_padded(62, 6), "000010");
        assert_eq!(base62_padded(u32::MAX, 6), "4gfFC3");
    }

    #[test]
    fn matches_a_published_example() {
        // Example token from a third-party wiki (prefix tk_, same 30 + 6 layout as GitHub's
        // tokens); not a GitHub token. Reproduced with zlib's crc32 and the alphabet 0-9A-Za-z.
        assert_eq!(suffix6("GNrRoBa1p9nuwm7XrWkrhYUNQ7edOw"), "4GUp8I");
        assert!(is_valid_suffix6("GNrRoBa1p9nuwm7XrWkrhYUNQ7edOw4GUp8I"));
        assert!(!is_valid_suffix6("GNrRoBa1p9nuwm7XrWkrhYUNQ7edOw4GUp8J"));
    }

    #[test]
    fn suffix_round_trip() {
        let payload = "abcdefghijklmnopqrstuvwxyz0123";
        let body = format!("{payload}{}", suffix6(payload));
        assert!(is_valid_suffix6(&body));
        let mut broken = body.into_bytes();
        broken[3] = b'X';
        assert!(!is_valid_suffix6(&String::from_utf8(broken).unwrap()));
        assert!(!is_valid_suffix6("short"));
    }
}
