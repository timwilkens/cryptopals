extern crate crypto;
extern crate rand;
extern crate rustc_serialize as serialize;

pub mod util;
pub mod solutions;
pub mod block_cipher;

use rand::Rng;

use std::collections::HashMap;
use std::io::{BufReader, BufRead};
use std::fs::File;

pub fn break_repeating_key(encrypted: Vec<u8>) -> (String, String) {
    let mut best_key = String::new();
    let mut best_sim: f32 = 100000.0;
    let mut decrypted = String::new();

    for key_length in 2..40 {

        let mut block_number = 0;
        let mut byte_number = 0;
        let mut blocks: Vec<Vec<u8>> = Vec::new();

        while byte_number < encrypted.len() {
            blocks.push(Vec::new());
            for _ in 0..key_length {
                if byte_number < encrypted.len() {
                    blocks[block_number].push(encrypted[byte_number]);
                    byte_number += 1;
                }
            }
            block_number += 1;
        }

        let mut transposed: Vec<Vec<u8>> = Vec::new();
        for _ in 0..key_length {
            transposed.push(Vec::new());
        }

        for block in blocks.iter() {
            for byte in 0..key_length {
                // The last block might not be a multiple of the key_size
                if byte < block.len() {
                    transposed[byte].push(block[byte]);
                }
            }
        }

        let mut key = Vec::new();

        for block in transposed.iter() {
            let (_, char, _) = single_byte_decrypt(block.clone());
            key.push(char);
        }

        let key_as_string: String;

        // Only continue if the decoded key bytes are valid utf-8
        match String::from_utf8(key.clone()) {
            Ok(s) => key_as_string = s,
            Err(_) => continue,
        }

        let decoded = util::repeating_key_xor(encrypted.clone(), key);
        let sim = like_english(&decoded);
        let decoded_string: String;

        // Only continue if the decoded bytes are valid utf-8
        match String::from_utf8(decoded) {
            Ok(s) => decoded_string = s,
            Err(_) => continue,
        }

        if sim < best_sim {
            best_sim = sim;
            best_key = key_as_string;
            decrypted = decoded_string;
        }
    }

    (decrypted, best_key)
}

pub fn line_by_single_xor(filepath: &str) -> (String) {
    let f = File::open(filepath.to_string()).unwrap();
    let f = BufReader::new(f);

    let mut best_string = String::new();
    let mut distance: f32 = 3200000.0;

    for line in f.lines() {
        let content = line.unwrap();
        let (decrypted, _, val) = single_byte_decrypt(util::hex_to_bytes(&content));
        if val < distance {
            match String::from_utf8(decrypted) {
                // Only set the value if it is valid utf8
                Ok(_) => {
                    best_string = content.to_string();
                    distance = val;
                }
                Err(_) => {}
            }
        }
    }

    best_string
}

pub fn single_byte_decrypt(encrypted: Vec<u8>) -> (Vec<u8>, u8, f32) {

    let mut decoder: u8 = 0;
    let mut decoded: Vec<u8> = vec![];
    // Arbitrary large number
    let mut distance: f32 = 3200000.0;

    for charcode in 0..128 as u8 {
        let decrypted = util::single_byte_xor(encrypted.clone(), charcode);
        let val = like_english(&decrypted);
        match String::from_utf8(decrypted.clone()) {
            Ok(_) => {}
            Err(_) => continue,
        }
        if val < distance {
            distance = val;
            decoder = charcode;
            decoded = decrypted;
        }
    }
    (decoded, decoder, distance)
}

// Sum of |actual distribution - english distribution|
// Smaller is better
fn like_english(charpoints: &Vec<u8>) -> f32 {
    let mut frequencies: HashMap<char, f32> = HashMap::new();
    for c in charpoints {
        let lower = (*c as char).to_lowercase().next().unwrap();
        let insert_value: f32;
        if frequencies.contains_key(&lower) {
            insert_value = frequencies.get(&lower).unwrap() + 1.0;
        } else {
            insert_value = 1.0;
        }

        frequencies.insert(lower, insert_value);
    }

    let mut distance: f32 = 0.0;
    let string_length: f32 = charpoints.len() as f32;

    for (c, freq) in &frequencies {
        let english_freq = util::letter_frequency(c);
        distance += ((freq / string_length) * 100.0 - english_freq).abs();
    }
    distance
}

pub fn find_ecb_encrypted(possible: Vec<Vec<u8>>) -> Vec<u8> {
    let mut best_score: u32 = 0;
    let mut best_sequence: Vec<u8> = Vec::new();
    for candidate in possible {
        let mut block_map: HashMap<Vec<u8>, u32> = HashMap::new();
        let blocks = block_cipher::break_into_blocks(candidate.clone(), 16);
        for block in blocks {
            let mut insert_value = 1;
            if block_map.contains_key(&block) {
                insert_value = insert_value + block_map.get(&block).unwrap();
            }

            block_map.insert(block, insert_value);
        }
        let mut score: u32 = 0;
        for (_, occurrence) in &block_map {
            if occurrence > &1 {
                score = score + occurrence;
            }
        }
        if score > best_score {
            best_score = score;
            best_sequence = candidate;
        }
    }

    best_sequence
}

pub fn encrypt_with_ecb_or_cbc(message: Vec<u8>) -> (Vec<u8>, String) {
    let key = util::random_bytes(16);
    let iv = util::random_bytes(16);
    let mut rng = rand::thread_rng();
    let mut randomly_extended = Vec::new();

    let beginning_blocks: usize = (rng.gen::<u8>() % 5 + 5) as usize;
    randomly_extended.extend(util::random_bytes(beginning_blocks));

    randomly_extended.extend(message);

    let ending_blocks: usize = (rng.gen::<u8>() % 5 + 5) as usize;
    randomly_extended.extend(util::random_bytes(ending_blocks));

    let padded = block_cipher::add_pkcs7_padding(randomly_extended, 16);

    if rng.gen() {
        // CBC
        let encrypted = block_cipher::encrypt_aes_cbc_128(padded, key, iv);
        return (encrypted, "CBC".to_string());
    } else {
        // ECB
        let encrypted = block_cipher::encrypt_aes_ecb_128(&padded[..], &key[..]).unwrap();
        return (encrypted, "ECB".to_string());
    }
}

pub fn byte_at_a_time_ecb(plaintext: Vec<u8>) -> Vec<u8> {
    let secret = util::base64_to_bytes("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gb\
                                        XkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdm\
                                        luZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3Q\
                                        gZHJvdmUgYnkK");

    let key = "JIBBER JABBER!!!".to_string().into_bytes();

    let mut concat = plaintext.clone();
    concat.extend(secret);
    let padded = block_cipher::add_pkcs7_padding(concat.clone(), 16);

    block_cipher::encrypt_aes_ecb_128(&padded[..], &key[..]).unwrap()
}

// Use this instead of a closure to remember the random prefix
pub struct RandomECB {
    prefix: Vec<u8>,
}

impl RandomECB {

    fn new() -> RandomECB {
        let mut rng = rand::thread_rng();
        let num_random = (rng.gen::<u8>()) as usize;
        RandomECB { prefix: util::random_bytes(num_random) }
    }

    fn encrypt(&self, plaintext: Vec<u8>) -> Vec<u8> {
        let mut random_bytes = self.prefix.clone();
        random_bytes.extend(plaintext);
        byte_at_a_time_ecb(random_bytes)
    }

}

pub fn decrypt_prefix_ecb_byte_by_byte(encryptor: RandomECB) -> String {

    let block_size: u32 = 16;
    let test_char = "A";

    // Calculate length of prefix
    let dupe_blocks = util::repeat_str_to_bytes(test_char, block_size * 2);
    let mut padding_to_block = 0;
    let mut plaintext_start = 0;

    'outer: for extra in (0..block_size) {
        let mut plaintext = util::repeat_str_to_bytes(test_char, extra);
        plaintext.extend(dupe_blocks.clone());
        let encrypted = encryptor.encrypt(plaintext);
        let blocks = block_cipher::break_into_blocks(encrypted, block_size);
        for index in (0..blocks.len() - 1) {
            if blocks[index] == blocks[index + 1] {
                padding_to_block = extra;
                plaintext_start = index;
                break 'outer;
            }
        }
    }

    let prefix_padding = util::repeat_str_to_bytes("A", padding_to_block);
    let mut decrypted = Vec::new();
    let num_blocks = block_cipher::break_into_blocks(encryptor.encrypt(prefix_padding.clone()),
                                                     block_size)
                         .len();

    let mut block_to_decode = plaintext_start;
    loop {
        for length in (0..block_size).rev() {
            let mut message = prefix_padding.clone();
            let short_block = (0..length).map(|_| "A").collect::<String>().into_bytes();
            message.extend(short_block.clone());
            let encrypted_bytes = encryptor.encrypt(message);
            let encrypted_blocks = block_cipher::break_into_blocks(encrypted_bytes.clone(),
                                                                   block_size);
            let first_block = encrypted_blocks[block_to_decode].clone();

            for char in 0..127 as u8 {
                let mut plaintext = prefix_padding.clone();
                plaintext.extend(short_block.clone());
                plaintext.extend(decrypted.clone());
                plaintext.push(char);
                let blocks = block_cipher::break_into_blocks(encryptor.encrypt(plaintext),
                                                             block_size);
                if first_block == blocks[block_to_decode] {
                    decrypted.push(char);
                    break;
                }
            }
        }
        block_to_decode += 1;
        if block_to_decode >= num_blocks {
            break;
        }
    }

    String::from_utf8(block_cipher::strip_pkcs7_padding(decrypted.clone())).unwrap()
}

pub fn decrypt_ecb_byte_by_byte() -> String {
    let mut decrypted = Vec::new();
    let block_size = 16;
    // Determine how many blocks are in the encrypted plaintext
    let num_blocks = block_cipher::break_into_blocks(byte_at_a_time_ecb(Vec::new()), block_size)
                         .len();

    let mut block_to_decode = 0;
    loop {
        for length in (0..block_size).rev() {
            let short_block = (0..length).map(|_| "A").collect::<String>().into_bytes();
            let encrypted_bytes = byte_at_a_time_ecb(short_block.clone());
            let encrypted_blocks = block_cipher::break_into_blocks(encrypted_bytes.clone(),
                                                                   block_size);
            let first_block = encrypted_blocks[block_to_decode].clone();

            for char in 0..127 as u8 {
                let mut plaintext = short_block.clone();
                plaintext.extend(decrypted.clone());
                plaintext.push(char);
                let blocks = block_cipher::break_into_blocks(byte_at_a_time_ecb(plaintext),
                                                             block_size);
                if first_block == blocks[block_to_decode] {
                    decrypted.push(char);
                    break;
                }
            }
        }
        block_to_decode += 1;
        if block_to_decode >= num_blocks {
            break;
        }
    }
    String::from_utf8(block_cipher::strip_pkcs7_padding(decrypted.clone())).unwrap()
}

pub fn encrypt_user_profile(profile: HashMap<String, String>) -> Vec<u8> {
    let cookie = util::encode_cookie(profile.clone());
    let padded = block_cipher::add_pkcs7_padding(cookie.into_bytes(), 16);
    block_cipher::encrypt_aes_ecb_128(&padded[..], "YELLOW SUBMARINE".as_bytes()).unwrap()
}

pub fn decrypt_user_profile(encrypted: Vec<u8>) -> HashMap<String, String> {
    let decrypted = block_cipher::decrypt_aes_ecb_128(&encrypted[..],
                                                      "YELLOW SUBMARINE".as_bytes())
                        .unwrap();
    let stripped = block_cipher::strip_pkcs7_padding(decrypted.clone());
    match String::from_utf8(stripped) {
        Ok(s) => {
            return util::decode_cookie(s);
        }
        Err(e) => panic!(e),
    }
}

pub fn profile_for(email: String) -> Vec<u8> {
    let cleaned = email.replace("&", "").replace("=", "");
    let profile: String = "email=".to_string() + &cleaned + "&uid=10&role=user";
    let padded = block_cipher::add_pkcs7_padding(profile.into_bytes(), 16);
    block_cipher::encrypt_aes_ecb_128(&padded[..], "YELLOW SUBMARINE".as_bytes()).unwrap()
}

pub fn bit_flip_encrypt(plaintext: String) -> Vec<u8> {
    let prefix = "comment1=cooking%20MCs;userdata=".to_string().into_bytes();
    let suffix = ";comment2=%20like%20a%20pound%20of%20bacon".to_string().into_bytes();
    let cleaned = plaintext.replace(";", "%3B").replace("=", "%3D").into_bytes();

    let mut message = prefix.clone();
    message.extend(cleaned);
    message.extend(suffix);

    let padded = block_cipher::add_pkcs7_padding(message, 16);
    let key = "cryptopals key!?".to_string().into_bytes();
    let iv = [0; 16].to_vec();

    block_cipher::encrypt_aes_cbc_128(padded, key, iv)
}

pub fn bit_flip_is_admin(ciphertext: Vec<u8>) -> bool {
    let key = "cryptopals key!?".to_string().into_bytes();
    let iv = [0; 16].to_vec();
    let mut decrypted = block_cipher::decrypt_aes_cbc_128(ciphertext, key, iv);
    decrypted = block_cipher::strip_pkcs7_padding(decrypted);
    let admin_string = "admin=true".to_string();
    for section in decrypted.split(|&x| x == ';' as u8) {
        match String::from_utf8(section.to_vec()) {
            Ok(s) => {
                if s == admin_string {
                    return true;
                }
            }
            Err(_) => continue,
        }
    }

    false
}

pub fn break_bit_flip() -> Vec<u8> {
    let encrypted = bit_flip_encrypt(":admin<true".to_string());
    // The prefix before our plaintext is exactly two blocks (32 bytes)
    // So, we need to modify the second block to produce admin=true
    // in the third block
    // We need to modify byte 0 and byte 6 to change this string to
    // ;admin=true

    let mut modified_cipher: Vec<u8> = Vec::new();

    // Brute force the two bytes we need flipped
    'outer: for byte1 in 0..127 as u8 {
        for byte2 in 0..127 as u8 {
            let mut mask = util::repeat_str_to_bytes("\x00", 16);
            mask.extend([byte1; 1].to_vec());
            mask.extend(util::repeat_str_to_bytes("\x00", 5));
            mask.extend([byte2; 1].to_vec());
            let bytes_remaining: u32 = (encrypted.clone().len() - mask.len()) as u32;
            mask.extend(util::repeat_str_to_bytes("\x00", bytes_remaining));

            let flipped = util::xor_bytes(encrypted.clone(), mask);
            if bit_flip_is_admin(flipped.clone()) {
                modified_cipher = flipped.clone();
                break 'outer;
            }
        }
    }

    modified_cipher
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn week_1_challenge_1() {
        let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f75732\
                   06d757368726f6f6d";
        let base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        assert_eq!(util::hex_to_base64(hex), base64);
    }

    #[test]
    fn week_1_challenge_2() {
        let hex1 = "1c0111001f010100061a024b53535009181c";
        let hex2 = "686974207468652062756c6c277320657965";
        let result = "746865206b696420646f6e277420706c6179";
        assert_eq!(util::xor_hex(hex1, hex2), result);
    }

    #[test]
    fn week_1_challenge_3() {
        let hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let (decrypted, decryptor, _) = single_byte_decrypt(util::hex_to_bytes(hex));
        assert_eq!(String::from_utf8(decrypted).unwrap(),
                   solutions::challenge_3());
        let char_key = 88; // X
        assert_eq!(decryptor, char_key);
    }

    #[test]
    fn week_1_challenge_4() {
        let best_candidate = line_by_single_xor("4.txt");
        // nOWTHATTHEPARTYISJUMPING*
        let result = "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f".to_string();
        assert_eq!(best_candidate, result);
    }

    #[test]
    fn week_1_challenge_5() {
        let key = "ICE".to_string().into_bytes();
        let message = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
                          .to_string()
                          .into_bytes();
        let encrypt = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\
                       a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        let result = util::repeating_key_xor(message, key);
        assert_eq!(util::bytes_to_hex(result), encrypt);
    }

    #[test]
    fn hamming_distance_test() {
        let str1 = "this is a test".to_string().into_bytes();
        let str2 = "wokka wokka!!!".to_string().into_bytes();
        assert_eq!(util::hamming_distance(str1, str2), 37);
    }

    #[test]
    fn week_1_challenge_6() {
        let bytes = util::read_base64_from_file("6.txt");
        let (_, key) = break_repeating_key(bytes);
        assert_eq!(key, solutions::challenge_6());
    }

    #[test]
    fn week_1_challenge_7() {
        let bytes = util::read_base64_from_file("7.txt");
        let key = "YELLOW SUBMARINE";

        match block_cipher::decrypt_aes_ecb_128(&bytes, key.as_bytes()) {
            Ok(plain_bytes) => {
                match String::from_utf8(plain_bytes) {
                    Ok(plaintext) => {
                        assert_eq!(block_cipher::strip_pkcs7_padding(plaintext.into_bytes()),
                                   solutions::challenge_7().into_bytes());
                    }
                    Err(e) => panic!(e),
                }
            }
            Err(e) => panic!(e),
        }

    }

    #[test]
    fn week_1_challenge_8() {
        let lines = util::read_hex_lines("8.txt");
        let candidate = find_ecb_encrypted(lines);
        assert_eq!(util::bytes_to_hex(candidate), solutions::challenge_8());
    }

    #[test]
    fn week_2_challenge_9() {
        let bytes = "YELLOW SUBMARINE".to_string().into_bytes();
        let padded_20 = "YELLOW SUBMARINE\x04\x04\x04\x04".to_string().into_bytes();
        assert_eq!(block_cipher::add_pkcs7_padding(bytes.clone(), 20),
                   padded_20);

        // Test when the string to pad is longer than the block_size
        let padded_8 = "YELLOW SUBMARINE\x08\x08\x08\x08\x08\x08\x08\x08".to_string().into_bytes();
        assert_eq!(block_cipher::add_pkcs7_padding(bytes.clone(), 8), padded_8);
    }

    #[test]
    fn test_pkcs_padding() {
        let message = "secret message".to_string().into_bytes();
        let padded = block_cipher::add_pkcs7_padding(message.clone(), 16);
        assert_eq!(block_cipher::strip_pkcs7_padding(padded), message);
    }

    #[test]
    fn round_trip_aes_ecb() {
        let key = "YELLOW SUBMARINE".as_bytes();
        let plaintext = "SECRET MESSAGE".to_string().into_bytes();
        let padded_plaintext = block_cipher::add_pkcs7_padding(plaintext.clone(), 16);

        match block_cipher::encrypt_aes_ecb_128(&padded_plaintext[..], key) {
            Ok(encrypted) => {
                match block_cipher::decrypt_aes_ecb_128(&encrypted[..], key) {
                    Ok(decrypted) =>
                        assert_eq!(block_cipher::strip_pkcs7_padding(decrypted), plaintext),
                    Err(e) => panic!(e),
                }
            }
            Err(e) => panic!(e),
        }
    }

    #[test]
    fn week_2_challenge_10() {
        let key = "YELLOW SUBMARINE".to_string().into_bytes();
        let encrypted = util::read_base64_from_file("10.txt");
        let iv = [0; 16];
        let decrypted = block_cipher::decrypt_aes_cbc_128(encrypted.clone(),
                                                          key.clone(),
                                                          iv.to_vec());
        match String::from_utf8(block_cipher::strip_pkcs7_padding(decrypted)) {
            Ok(s) => assert_eq!(solutions::challenge_10(), s),
            Err(e) => panic!(e),
        }
    }

    #[test]
    fn round_trip_aes_cbc() {
        let key = "YELLOW SUBMARINE".to_string().into_bytes();
        let iv = [0; 16].to_vec();
        let plaintext = "SECRET MESSAGE".to_string().into_bytes();
        let padded_plaintext = block_cipher::add_pkcs7_padding(plaintext.clone(), 16);

        let encrypted = block_cipher::encrypt_aes_cbc_128(padded_plaintext,
                                                          key.clone(),
                                                          iv.clone());
        let decrypted = block_cipher::decrypt_aes_cbc_128(encrypted, key.clone(), iv.clone());
        assert_eq!(block_cipher::strip_pkcs7_padding(decrypted), plaintext);
    }

    #[test]
    fn identical_blocks_of_cbc() {
        let message = (0..32).map(|_| "Z").collect::<String>().into_bytes();
        let key = util::random_bytes(16);
        let encrypted1 = block_cipher::encrypt_aes_ecb_128(&message[..], &key[..]).unwrap();
        let encrypted2 = block_cipher::encrypt_aes_ecb_128(&message[..], &key[..]).unwrap();
        assert_eq!(block_cipher::break_into_blocks(encrypted1, 16)[0],
                   block_cipher::break_into_blocks(encrypted2, 16)[1]);
    }

    #[test]
    fn set_2_challenge_11() {
        // We know that identical blocks of plaintext will be encrypted into identical
        // blocks of ciphertext
        // under ecb but *not* under cbc.
        // Since the message is padded with 5-10 random bytes at the beginning and end
        // we put enough Z's
        // to fill the second and third blocks of the plaintext. This means when the
        // message is encrypted
        // under ECB the second and third block ciphertext blocks will be identical and
        // under CBC they should not be.
        let message = (0..(10 + 32 + 10)).map(|_| "Z").collect::<String>().into_bytes();
        let (encrypted, actual_mode) = encrypt_with_ecb_or_cbc(message);
        let blocks = block_cipher::break_into_blocks(encrypted.clone(), 16);
        let mode;
        if blocks[1] == blocks[2] {
            mode = "ECB".to_string();
        } else {
            mode = "CBC".to_string();
        }
        assert_eq!(mode, actual_mode);
    }

    #[test]
    fn set_2_challenge_12() {
        assert_eq!(decrypt_ecb_byte_by_byte(), solutions::challenge_12());
    }

    #[test]
    fn cookie_parsing() {
        let cookie = "foo=bar&baz=qux&zap=zazzle".to_string();
        let parsed = util::decode_cookie(cookie.clone());
        assert!(parsed.contains_key("foo"));
        assert_eq!(parsed.get("foo").unwrap(), "bar");
        assert!(parsed.contains_key("baz"));
        assert_eq!(parsed.get("baz").unwrap(), "qux");
        assert!(parsed.contains_key("zap"));
        assert_eq!(parsed.get("zap").unwrap(), "zazzle");
    }

    #[test]
    fn set_2_challenge_13() {

        // Specify an email with length so that we get 'role=' at the end of the second
        // block
        let encrypted_email_blocks = block_cipher::break_into_blocks(profile_for("foo12@foo.com"
                                                                                     .to_string()),
                                                                     16);
        // Specify an email so that 'admin' ends at the start of a block
        let encrypted_role_blocks = block_cipher::break_into_blocks(profile_for("XXXXXXXXXXadmin"
                                                                                    .to_string()),
                                                                    16);

        let mut ciphertext = Vec::new();
        ciphertext.extend(encrypted_email_blocks[0].clone());
        ciphertext.extend(encrypted_email_blocks[1].clone());
        ciphertext.extend(encrypted_role_blocks[1].clone());
        // Must have this block to have valid padding
        ciphertext.extend(encrypted_role_blocks[2].clone());

        // Produces this cookie string
        // email=foo12@foo.com&uid=10&role=admin&uid=10&role=user
        // We need duplicate keys to be resolved by first given
        let user_profile = decrypt_user_profile(ciphertext);
        assert_eq!(user_profile.get("email").unwrap(), "foo12@foo.com");
        assert_eq!(user_profile.get("role").unwrap(), "admin");
    }

    #[test]
    fn set_2_challenge_14() {
        let encryptor = RandomECB::new();
        let decrypted = decrypt_prefix_ecb_byte_by_byte(encryptor);
        assert_eq!(decrypted, solutions::challenge_12());
    }

    #[test]
    fn set_2_challenge_15() {
        assert!(block_cipher::valid_pkcs7_padding("ICE ICE BABY\x04\x04\x04\x04"
                                                      .to_string()
                                                      .into_bytes()));
        assert!(!block_cipher::valid_pkcs7_padding("ICE ICE BABY\x05\x05\x05\x05"
                                                       .to_string()
                                                       .into_bytes()));
        assert!(!block_cipher::valid_pkcs7_padding("ICE ICE BABY\x01\x02\x03\x04"
                                                       .to_string()
                                                       .into_bytes()));
    }

    #[test]
    fn set_2_challenge_16() {
        assert!(bit_flip_is_admin(break_bit_flip()));
    }
}
