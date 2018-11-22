#[cfg(test)]
mod tests {
    use hex;
    use base64;

    static S1C1_IN: &str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    static S1C1_OUT: &str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    static S1C2_IN_1: &str = "1c0111001f010100061a024b53535009181c";
    static S1C2_IN_2: &str = "686974207468652062756c6c277320657965";
    static S1C2_OUT: &str = "746865206b696420646f6e277420706c6179";

    #[test]
    fn s1c1() {
        assert_eq!(base64::encode(&hex::decode(&String::from(S1C1_IN)).unwrap()), S1C1_OUT);
    }

    #[test]
    fn s1c2() {
        assert_eq!(hex::xor(&hex::decode(S1C2_IN_1).unwrap(), &hex::decode(S1C2_IN_2).unwrap()),
                   hex::decode(S1C2_OUT).unwrap());
    }
}

pub mod hex {
    use std;
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

    pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
        let mut out = vec![];
        let c = a.iter().zip(b.iter());

        for i in c {
            out.push(i.0 ^ i.1);
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
