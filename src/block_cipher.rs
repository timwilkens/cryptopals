use crypto::{symmetriccipher, buffer, aes, blockmodes};
use crypto::buffer::{ReadBuffer, WriteBuffer, BufferResult};

use util;

pub fn decrypt_aes_ecb_128(encrypted_data: &[u8],
                           key: &[u8])
                           -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut decryptor = aes::ecb_decryptor(aes::KeySize::KeySize128, key, blockmodes::NoPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = try!(decryptor.decrypt(&mut read_buffer, &mut write_buffer, true));
        final_result.extend(write_buffer.take_read_buffer().take_remaining());
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    Ok(final_result)
}

pub fn encrypt_aes_ecb_128(data: &[u8],
                           key: &[u8])
                           -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {

    let mut encryptor: Box<symmetriccipher::Encryptor> =
        aes::ecb_encryptor(aes::KeySize::KeySize128, key, blockmodes::NoPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = try!(encryptor.encrypt(&mut read_buffer, &mut write_buffer, true));
        final_result.extend(write_buffer.take_read_buffer().take_remaining());
        match result {
            buffer::BufferResult::BufferUnderflow => break,
            buffer::BufferResult::BufferOverflow => {}
        }
    }

    Ok(final_result)
}

pub fn break_into_blocks(bytes: Vec<u8>, block_size: u32) -> Vec<Vec<u8>> {
    let num_bytes = bytes.len();
    let mut blocks = Vec::new();
    let mut index = 0;
    while index < num_bytes {
        let mut block = Vec::new();
        let mut current_length = 0;
        while index < num_bytes && current_length < block_size {
            block.push(bytes[index]);
            current_length += 1;
            index += 1;
        }
        blocks.push(block);
    }

    blocks
}

pub fn add_pkcs7_padding(bytes: Vec<u8>, block_size: u8) -> Vec<u8> {
    let mut padded_bytes = bytes.clone();
    let mut padding_value: u8;
    if bytes.len() < block_size as usize {
        padding_value = block_size - bytes.len() as u8
    } else {
        padding_value = block_size as u8 - (bytes.len() as u32 % block_size as u32) as u8;
    }
    if padding_value == 0 {
        padding_value = block_size;
    }

    for _ in 0..padding_value {
        padded_bytes.push(padding_value);
    }

    padded_bytes
}

pub fn strip_pkcs7_padding(bytes: Vec<u8>) -> Vec<u8> {
    let padding_value = bytes[bytes.len() - 1];
    let mut stripped = bytes.clone();
    for _ in 0..padding_value {
        stripped.pop();
    }

    stripped
}

// Should probably pass in block_size and ensure
// the byte value is not larger than the block_size
pub fn valid_pkcs7_padding(bytes: Vec<u8>) -> bool {
    let padding_value = bytes[bytes.len() - 1];
    if padding_value as usize >= bytes.len() {
        return false;
    }
    if padding_value == 0 {
        return false;
    }
    let mut cloned = bytes.clone();
    for _ in 0..padding_value {
        let val = cloned.pop().unwrap();
        if val != padding_value {
            return false;
        }
    }

    true
}

pub fn decrypt_aes_cbc_128(encrypted: Vec<u8>, key: Vec<u8>, iv: Vec<u8>) -> Vec<u8> {

    let blocks = break_into_blocks(encrypted, 16);
    let mut decrypted_bytes: Vec<u8> = Vec::new();
    // Initially the iv
    let mut previous_block = iv;

    for index in 0..blocks.len() {
        let ciphertext_block = blocks[index].clone();
        match decrypt_aes_ecb_128(&ciphertext_block[..], &key[..]) {
            Ok(decrypted) => {
                decrypted_bytes.extend(util::xor_bytes(decrypted, previous_block));
                previous_block = ciphertext_block.clone();
            }
            Err(e) => panic!(e),
        }
    }

    decrypted_bytes
}

pub fn encrypt_aes_cbc_128(plaintext: Vec<u8>, key: Vec<u8>, iv: Vec<u8>) -> Vec<u8> {

    let blocks = break_into_blocks(plaintext, 16);
    let mut encrypted_bytes: Vec<u8> = Vec::new();
    // Initially the iv
    let mut previous_block = iv.clone();

    for index in 0..blocks.len() {
        let plaintext_xor = util::xor_bytes(blocks[index].clone(), previous_block);
        match encrypt_aes_ecb_128(&plaintext_xor[..], &key[..]) {
            Ok(encrypted) => {
                encrypted_bytes.extend(encrypted.clone());
                previous_block = encrypted.clone();
            }
            Err(e) => panic!(e),
        }
    }

    encrypted_bytes
}
