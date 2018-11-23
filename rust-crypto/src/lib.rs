#[cfg(test)]
mod tests {
    use crypto;
    use hex;
    use base64;

    #[test]
    fn s1c1() {
        const IN: &str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        const OUT: &str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        assert_eq!(base64::encode(&hex::decode(IN).unwrap()), OUT);
    }

    #[test]
    fn s1c2() {
        const IN_1: &str = "1c0111001f010100061a024b53535009181c";
        const IN_2: &str = "686974207468652062756c6c277320657965";
        const OUT: &str = "746865206b696420646f6e277420706c6179";

        assert_eq!(crypto::fixed_xor(&hex::decode(IN_1).unwrap(), &hex::decode(IN_2).unwrap()),
                   hex::decode(OUT).unwrap());
    }

    #[test]
    fn s1c3() {
        const IN: &str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        const KEY: u8 = 88;
        const OUT: &str = "Cooking MC's like a pound of bacon";

        assert_eq!(crypto::find_key(&hex::decode(IN).unwrap()), KEY);
        assert_eq!(std::str::from_utf8(&crypto::decrypt(&hex::decode(IN).unwrap(), KEY)).unwrap(), OUT);
    }
}

pub mod crypto {
    static COMMON_UPPER: [char; 12] = [
        'E', 'T', 'A', 'O', 'I', 'N',
        'S', 'H', 'R', 'D', 'L', 'U',
    ];

    static COMMON_LOWER: [char; 12] = [
        'e', 't', 'a', 'o', 'i', 'n',
        's', 'h', 'r', 'd', 'l', 'u',
    ];

    pub fn fixed_xor(xs: &[u8], ys: &[u8]) -> Vec<u8> {
        Iterator::zip(xs.iter(), ys.iter())
            .map(|(x, y)| x ^ y)
            .collect()
    }

    pub fn repeating_xor(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
        Iterator::zip(key.iter().cycle(), plaintext.iter())
            .map(|(x, y)| x ^ y)
            .collect()
    }

    pub fn decrypt(bytes: &[u8], key: u8) -> Vec<u8> {
        let key: [u8; 1] = [key];
        repeating_xor(bytes, &key)
    }

    pub fn score_str(s: &str) -> usize {
        let mut score = 0;

        for c in s.bytes() {
            if COMMON_UPPER.contains(&(c as char)) || c == ' ' as u8 {
                score = score + 1;
            } else if COMMON_LOWER.contains(&(c as char)) {
                score = score + 2;
            }
        }

        score
    }

    pub fn find_key(bytes: &[u8]) -> u8 {
        let mut max_score = 0;
        let mut out = 0;

        for key in 1..128 {
            let d = decrypt(&bytes, key);

            let s = match std::str::from_utf8(&d) {
                Ok(v) => v,
                Err(_) => ""
            };

            let score = score_str(&s);

            if score > max_score {
                out = key;
                max_score = score;
            }
        }

        out
    }
}

pub mod hex {

    static TABLE: [char; 16] = [
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    ];

    pub fn decode(mut s: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
        let mut bytes = vec![];
        while !s.is_empty() {
            let (head, tail) = s.split_at(2);
            s = tail;

            bytes.push(u8::from_str_radix(head, 16)?);
        }

        Ok(bytes)
    }

    pub fn encode(bytes: &[u8]) -> String {
        let mut out = String::new();

        for byte in bytes {
            out.push(TABLE[(byte >> 4) as usize]);
            out.push(TABLE[(byte & 0b1111) as usize]);
        }

        out
    }
}

pub mod base64 {
    static TABLE: [char; 64] = [
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
        'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
        'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
        'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
        'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
        'w', 'x', 'y', 'z', '0', '1', '2', '3',
        '4', '5', '6', '7', '8', '9', '+', '/'
    ];

    pub fn encode(mut bytes: &[u8]) -> String {
        let mut s = String::new();

        while bytes.len() >= 3 {
            let (head, tail) = bytes.split_at(3);
            bytes = tail;

            s.push(TABLE[(head[0] >> 2) as usize]);
            s.push(TABLE[(((head[0] << 4) ^ (head[1] >> 4)) & 0b11_1111) as usize]);
            s.push(TABLE[(((head[1] << 2) ^ (head[2] >> 6)) & 0b11_1111) as usize]);
            s.push(TABLE[(head[2] & 0b11_1111) as usize]);
        }

        if bytes.len() == 2 {
            s.push(TABLE[(bytes[0] >> 2) as usize]);
            s.push(TABLE[(((bytes[0] << 4) ^ (bytes[1] >> 4)) & 0b11_1111) as usize]);
            s.push(TABLE[((bytes[1] << 2)  & 0b11_1111) as usize]);
            s.push('=');
        } else if bytes.len() == 1 {
            s.push(TABLE[(bytes[0] >> 2) as usize]);
            s.push(TABLE[((bytes[0] << 4) & 0b11_1111) as usize]);
            s.push('=');
            s.push('=');
        }

        s
    }
}
