extern crate rand;

use rand::{Rng, thread_rng};

use serialize::base64::{self, ToBase64, FromBase64};
use serialize::hex::{ToHex, FromHex};

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, BufRead};

pub fn hex_to_base64(hex: &str) -> String {
    let bytes = hex_to_bytes(hex);
    bytes_to_base64(bytes)
}

pub fn base64_to_hex(base64: &str) -> String {
    let bytes = base64_to_bytes(base64);
    bytes_to_hex(bytes)
}

pub fn xor_hex(str1: &str, str2: &str) -> String {
    let bytes1 = hex_to_bytes(str1);
    let bytes2 = hex_to_bytes(str2);
    if bytes1.len() != bytes2.len() {
        panic!("unequal arguments to xor_hex");
    } else {
        bytes_to_hex(xor_bytes(bytes1, bytes2))
    }
}

pub fn read_base64_from_file(filepath: &str) -> Vec<u8> {
    let f = File::open(filepath.to_string()).unwrap();
    let reader = BufReader::new(f);
    let mut base64 = String::new();

    for line in reader.lines() {
        let content = line.unwrap();
        base64 = base64 + &content;
    }

    base64_to_bytes(&base64)
}

pub fn single_byte_xor(bytes: Vec<u8>, byte: u8) -> Vec<u8> {

    let mut single_bytes = Vec::new();
    for _ in 0..bytes.len() {
        single_bytes.push(byte);
    }

    xor_bytes(bytes, single_bytes)
}

pub fn repeating_key_xor(bytes: Vec<u8>, key_bytes: Vec<u8>) -> Vec<u8> {
    let key_length = key_bytes.len();
    let mut repeating_key = Vec::new();
    let mut key_index = 0;

    for _ in 0..bytes.len() {
        repeating_key.push(key_bytes[key_index]);
        key_index = (key_index + 1) % key_length;
    }

    xor_bytes(bytes, repeating_key)
}

pub fn letter_frequency(c: &char) -> f32 {
    let lower = c.to_lowercase().next().unwrap();
    match lower {
        'a' => 8.167,
        'b' => 1.492,
        'c' => 2.782,
        'd' => 4.253,
        'e' => 12.702,
        'f' => 2.228,
        'g' => 2.015,
        'h' => 6.094,
        'i' => 6.966,
        'j' => 0.153,
        'k' => 0.772,
        'l' => 4.025,
        'm' => 2.406,
        'n' => 6.749,
        'o' => 7.507,
        'p' => 1.929,
        'q' => 0.095,
        'r' => 5.987,
        's' => 6.327,
        't' => 9.056,
        'u' => 2.758,
        'v' => 0.978,
        'w' => 2.361,
        'x' => 0.150,
        'y' => 1.974,
        'z' => 0.074,
        ' ' => 13.000,
        '.' => 8.500,
        ',' => 8.500,
        '\'' => 8.500,
        '0' => 8.500,
        '1' => 8.500,
        '2' => 8.500,
        '3' => 8.500,
        '4' => 8.500,
        '5' => 8.500,
        '6' => 8.500,
        '7' => 8.500,
        '8' => 8.500,
        '9' => 8.500,
        // Give non-alphabetic chars a high value
        _ => 20.0,
    }
}

pub fn xor_bytes(bytes1: Vec<u8>, bytes2: Vec<u8>) -> Vec<u8> {
    let mut result = Vec::new();
    for (x, y) in bytes1.iter().zip(bytes2) {
        result.push(x ^ y);
    }
    result
}

pub fn hamming_distance(bytes1: Vec<u8>, bytes2: Vec<u8>) -> u32 {
    let x = xor_bytes(bytes1, bytes2);

    let mut distance: u32 = 0;
    for mut b in x {
        while b != 0 {
            if b & 0x01 == 1 {
                distance += 1;
            }
            b >>= 1;
        }
    }

    distance
}

pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    hex.to_string().from_hex().unwrap()
}

pub fn bytes_to_hex(bytes: Vec<u8>) -> String {
    bytes.to_hex()
}

pub fn bytes_to_base64(bytes: Vec<u8>) -> String {
    bytes.to_base64(base64::STANDARD)
}

pub fn base64_to_bytes(base64: &str) -> Vec<u8> {
    base64.from_base64().unwrap()
}

pub fn read_hex_lines(filepath: &str) -> Vec<Vec<u8>> {
    let f = File::open(filepath.to_string()).unwrap();
    let f = BufReader::new(f);

    let mut byte_lines = Vec::new();

    for line in f.lines() {
        let content = hex_to_bytes(&line.unwrap());
        byte_lines.push(content);
    }

    byte_lines
}

pub fn random_bytes(length: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut rng = rand::thread_rng();
    for _ in 0..length {
        bytes.push(rng.gen::<u8>());
    }

    bytes
}

pub fn decode_cookie(cookie: String) -> HashMap<String, String> {
    let mut parsed: HashMap<String, String> = HashMap::new();
    for key_value_pair in cookie.split("&") {
        let components = key_value_pair.split("=").collect::<Vec<&str>>();
        if components.len() == 2 {
            // First given
            if !parsed.contains_key(components[0]) {
                parsed.insert(components[0].to_string(), components[1].to_string());
            }
        }
    }

    parsed
}

pub fn encode_cookie(data: HashMap<String, String>) -> String {
    let mut pairs = Vec::new();
    for (key, value) in &data {
        pairs.push(key.clone() + "=" + value);
    }

    pairs.join("&")
}
