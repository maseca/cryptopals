#[cfg(test)]
mod tests {
    use crypto;
    use hex;
    use base64;

    #[test]
    fn s1c1() {
        const IN: &str = "49276d206b696c6c696e6720796f757220627261696e206c696b\
                          65206120706f69736f6e6f7573206d757368726f6f6d";
        const OUT: &str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3V\
                           zIG11c2hyb29t";

        assert_eq!(base64::encode(&hex::decode(IN).unwrap()), OUT);
    }

    #[test]
    fn s1c2() {
        const IN_1: &str = "1c0111001f010100061a024b53535009181c";
        const IN_2: &str = "686974207468652062756c6c277320657965";
        const OUT: &str = "746865206b696420646f6e277420706c6179";

        assert_eq!(crypto::fixed_xor(&hex::decode(IN_1).unwrap(),
                                     &hex::decode(IN_2).unwrap()),
                   hex::decode(OUT).unwrap());
    }

    #[test]
    fn s1c3() {
        const IN: &str = "1b37373331363f78151b7f2b783431333d78397828372d363c783\
                          73e783a393b3736";
        const KEY: u8 = 88;
        const OUT: &str = "Cooking MC's like a pound of bacon";

        let key = crypto::find_key_score(&hex::decode(IN).unwrap()).0;

        assert_eq!(key, KEY);
        assert_eq!(std::str::from_utf8(&crypto::decrypt(&hex::decode(IN).unwrap(), KEY)).unwrap(), OUT);
    }

    #[test]
    fn s1c4() {
        const KEY: u8 = 53;
        const POS: usize = 170;
        const OUT: &str = "Now that the party is jumping\n";

        let test: Vec<Vec<u8>> = hex::ingest_file("./resources/s1c4.in");
        let (vec, key, pos) = crypto::detect_1c_xor(&test);

        assert_eq!(key, KEY);
        assert_eq!(pos, POS);
        assert_eq!(crypto::decrypt(&vec, key), OUT.as_bytes());
    }

    #[test]
    fn s1c5() {
        const IN: &str = "Burning 'em, if you ain't quick and nimble\n\
                          I go crazy when I hear a cymbal";
        const OUT: &str = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63\
                           343c2a26226324272765272a282b2f20430a652e2c652a312433\
                           3a653e2b2027630c692b20283165286326302e27282f";

        let key: &[u8] = "ICE".as_bytes();

        assert_eq!(crypto::repeating_xor(IN.as_bytes(), key), hex::decode(OUT).unwrap());
    }

    #[test]
    fn s1c6() {
        const B64: &str = "ABCDEFGHIJKLMNOPQRSTUVwxyz+";

        let d = base64::decode(B64);
        assert_eq!(base64::encode(&d), B64);
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

    pub fn fixed_xor(bytes: &[u8], key: &[u8]) -> Vec<u8> {
        Iterator::zip(bytes.iter(), key.iter())
            .map(|(x, y)| x ^ y)
            .collect()
    }

    pub fn repeating_xor(bytes: &[u8], key: &[u8]) -> Vec<u8> {
        Iterator::zip(key.iter().cycle(), bytes.iter())
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

    pub fn find_key_score(bytes: &[u8]) -> (u8, usize) {
        let mut max_score = 0;
        let mut out_key = 0;

        for key in 1..128 {
            let d = decrypt(&bytes, key);

            let s = match std::str::from_utf8(&d) {
                Ok(s) => s,
                Err(_) => ""
            };

            let score = score_str(&s);

            if score > max_score {
                out_key = key;
                max_score = score;
            }
        }

        (out_key, max_score)
    }

    pub fn detect_1c_xor(vv: &Vec<Vec<u8>>) -> (&Vec<u8>, u8, usize) {
        let mut max_score = 0;
        let mut out_key = 0;
        let mut pos = 0;

        for (k, v) in vv.iter().enumerate() {
            let (key, score) = find_key_score(v);
            if score > max_score {
                max_score = score;
                out_key = key;
                pos = k;
            }
        }

        (&vv[pos], out_key, pos)
    }
}

pub mod hex {
    static TABLE: [char; 16] = [
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    ];

    pub fn ingest_file(p: &str) -> Vec<Vec<u8>> {
        use std::io::prelude::*;

        let mut out: Vec<Vec<u8>> = vec![];

        let path = std::path::Path::new(p);
        let mut file = match std::fs::File::open(&path) {
            Err(_) => panic!("Failed to open file."),
            Ok(file) => file
        };

        let mut s = String::new();
        match file.read_to_string(&mut s) {
            Err(_) => panic!("Failed to read file."),
            Ok(_) => {
                for line in s.lines() {
                    out.push(decode(line).unwrap());
                }
            }
        }

        out
    }

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

    pub fn decode(s: &str) -> Vec<u8> {
        let mut out = vec![];
        let mut s_bytes = vec![];

        for c in s.trim_matches('=').bytes() {
            let c = match c {
                b'A'..=b'Z' => (c - b'A') as u8,
                b'a'..=b'z' => (c - b'a' + 26) as u8,
                b'+' => 62,
                b'/' => 63,
                _ => 0
            };

            s_bytes.push(c);
        }

        let mut extra = vec![];
        while s_bytes.len() % 4 != 0 {
            extra.push(s_bytes.pop().unwrap());
        }

        for bytes in s_bytes.chunks(4) {
            out.push((bytes[0] << 2) ^ (bytes[1] >> 6));
            out.push((bytes[1] << 4) ^ (bytes[2] >> 2));
            out.push((bytes[2] << 6) ^ bytes[3]);
        }

        if extra.len() == 3 {
            out.push((extra[2] << 2) ^ (extra[1] >> 6));
            out.push((extra[1] << 4) ^ (extra[0] >> 2));
            out.push(extra[0] << 6);
        } else if extra.len() == 2 {
            out.push((extra[1] << 2) ^ (extra[0] >> 6));
            out.push(extra[0] << 4);
        } else if extra.len() == 1 {
            out.push(extra[0] << 2);
        }

        out
    }

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
