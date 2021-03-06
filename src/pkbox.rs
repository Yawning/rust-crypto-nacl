// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use rand::{Rng, OsRng};
use crypto::curve25519::{curve25519, curve25519_base};
use crypto::digest::Digest;
use crypto::salsa20::hsalsa20;
use crypto::sha2::Sha512Trunc256;

use secretbox::{crypto_secretbox, crypto_secretbox_open};

/// The length of the crypto_box public key in bytes.
#[allow(non_upper_case_globals)]
pub const crypto_box_PUBLICKEYBYTES: usize = 32;

/// The length of the crypto_box secret (private) key in bytes.
#[allow(non_upper_case_globals)]
pub const crypto_box_SECRETKEYBYTES: usize = 32;

/// The length of the crypto_box nonce in bytes.
#[allow(non_upper_case_globals)]
pub const crypto_box_NONCEBYTES: usize = 24;

/// The length of the crypto_box overhead in bytes.
#[allow(non_upper_case_globals)]
pub const crypto_box_OVERHEAD: usize = 16;

static ZERO_HSALSA_NONCE: [u8; 16] = [0u8; 16];

/// Public-key authenticated encryption/decryption keypair generation.
///
/// The crypto_box_keypair function randomly generates a secret key and
/// corresponding public key. It puts the secret key in sk and returns the
/// public key. This function asserts if sk.len() is not
/// crypto_box_SECRETKEYBYTES and guarantees that pk has
/// crypto_box_PUBLICKEYBYTES.
pub fn crypto_box_keypair(sk: &mut [u8]) -> [u8; crypto_box_PUBLICKEYBYTES] {
    assert!(sk.len() == crypto_box_PUBLICKEYBYTES);

    // Generate a curve25519 secret key, using a strong entropy source, and
    // extract the entropy using SHA512-256 to guard against poor OsRng
    // implementations.
    let mut rng = OsRng::new().ok().unwrap();
    rng.fill_bytes(sk);
    let mut sh = Sha512Trunc256::new();
    sh.input(sk);
    sh.result(sk);

    curve25519_base(sk)
}

/// Public-key authenticated encryption/decryption precomputation.
///
/// The crypto_box_beforenm function does the public key cryptography portion of
/// the crypto_box routines to speed up applications that send several messages
/// to the same receiver, or receive several messages from the same sender.
///
/// The key that is returned can be passed to crypto_secretbox or
/// crypto_secretbox_open, for results identical to calling crypto_box or
/// crypto_box_open. NaCl aliases the 2nd step as crypto_box_afternm and
/// crypto_box_open_afternm.
///
/// # Arguments
/// * pk - The public key.
/// * sk - The secret (private) key.
pub fn crypto_box_beforenm(pk: &[u8], sk: &[u8]) -> [u8; crypto_box_SECRETKEYBYTES] {
    assert!(pk.len() == crypto_box_PUBLICKEYBYTES);
    assert!(sk.len() == crypto_box_SECRETKEYBYTES);

    // Obtain the shared secret with a Curve25519 scalar mult.
    let curve_key = curve25519(sk, pk);

    // Derive the crypto_secretbox key with HSalsa20.
    let mut key = [0u8; 32];
    hsalsa20(&curve_key, &ZERO_HSALSA_NONCE, &mut key);

    key
}

/// Public-key authenticated encryption. 
///
/// The crypto_box function encrypts and authenticates a message, using the
/// sender's secret key, the receiver's public key, and a nonce, returning
/// the corresponding ciphertext. This function asserts if pk.len() is not
/// crypto_box_PUBLICKEYBYTES, sk.len() is not crypto_box_SECRETKEYBYTES,
/// or if nonce.len() is not crypto_secretbox_NONCEBYTES.
///
/// Nonces MUST NOT be reused with a given pk/sk pair. Nonces are long enough
/// that randomly generated nonces have negligible risk of collision.
///
/// # Arguments
/// * msg - The plaintext to encrypt/authenticate.
/// * nonce - The nonce to use for the encryption/authentication.
/// * pk - The receiver's public key.
/// * sk - The sender's secret (private) key.
pub fn crypto_box(msg: &[u8], nonce: &[u8], pk: &[u8], sk: &[u8]) -> Vec<u8> {
    assert!(nonce.len() == crypto_box_NONCEBYTES);

    let key = crypto_box_beforenm(pk, sk);
    crypto_secretbox(msg, nonce, &key)
}

/// Public-key authenticated decryption.
///
/// The crypto_box_open function authenticates and decrypts a ciphertext,
/// using the sender's public key, the receiver's secret key, and a nonce,
/// the corresponding plaintext. This function asserts if pk.len() is not
/// crypto_box_PUBLICKEYBYTES, sk.len() is not crypto_box_SECRETKEYBYTES,
/// or if nonce.len() is not crypto_secretbox_NONCEBYTES.
///
/// # Arguments
/// * ciphertext - The ciphertext to authenticate/decrypt.
/// * nonce - The nonce to use for the authentication/decryption.
/// * pk - The sender's public key.
/// * sk - The receiver's secret (private) key.
pub fn crypto_box_open(ciphertext: &[u8], nonce: &[u8], pk: &[u8], sk: &[u8]) -> Result<Vec<u8>, &'static str> {
    assert!(nonce.len() == crypto_box_NONCEBYTES);

    let key = crypto_box_beforenm(pk, sk);
    crypto_secretbox_open(ciphertext, nonce, &key)
}

#[cfg(test)]
mod test {
    use pkbox::{crypto_box, crypto_box_open};

    #[test]
    fn test_nacl_box_vectors() {
        let alicesk = vec![
            0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d,
            0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45,
            0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a,
            0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a ];
        let alicepk = vec![
            0x85,0x20,0xf0,0x09,0x89,0x30,0xa7,0x54,
            0x74,0x8b,0x7d,0xdc,0xb4,0x3e,0xf7,0x5a,
            0x0d,0xbf,0x3a,0x0d,0x26,0x38,0x1a,0xf4,
            0xeb,0xa4,0xa9,0x8e,0xaa,0x9b,0x4e,0x6a ];
        let bobsk = vec![
            0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,
            0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,
            0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,
            0x1c,0x2f,0x8b,0x27,0xff,0x88,0xe0,0xeb ];
        let bobpk = vec![
            0xde,0x9e,0xdb,0x7d,0x7b,0x7d,0xc1,0xb4,
            0xd3,0x5b,0x61,0xc2,0xec,0xe4,0x35,0x37,
            0x3f,0x83,0x43,0xc8,0x5b,0x78,0x67,0x4d,
            0xad,0xfc,0x7e,0x14,0x6f,0x88,0x2b,0x4f];
        let nonce = vec![
            0x69,0x69,0x6e,0xe9,0x55,0xb6,0x2b,0x73,
            0xcd,0x62,0xbd,0xa8,0x75,0xfc,0x73,0xd6,
            0x82,0x19,0xe0,0x03,0x6b,0x7a,0x0b,0x37 ];
        let msg = vec! [
            0xbe,0x07,0x5f,0xc5,0x3c,0x81,0xf2,0xd5,
            0xcf,0x14,0x13,0x16,0xeb,0xeb,0x0c,0x7b,
            0x52,0x28,0xc5,0x2a,0x4c,0x62,0xcb,0xd4,
            0x4b,0x66,0x84,0x9b,0x64,0x24,0x4f,0xfc,
            0xe5,0xec,0xba,0xaf,0x33,0xbd,0x75,0x1a,
            0x1a,0xc7,0x28,0xd4,0x5e,0x6c,0x61,0x29,
            0x6c,0xdc,0x3c,0x01,0x23,0x35,0x61,0xf4,
            0x1d,0xb6,0x6c,0xce,0x31,0x4a,0xdb,0x31,
            0x0e,0x3b,0xe8,0x25,0x0c,0x46,0xf0,0x6d,
            0xce,0xea,0x3a,0x7f,0xa1,0x34,0x80,0x57,
            0xe2,0xf6,0x55,0x6a,0xd6,0xb1,0x31,0x8a,
            0x02,0x4a,0x83,0x8f,0x21,0xaf,0x1f,0xde,
            0x04,0x89,0x77,0xeb,0x48,0xf5,0x9f,0xfd,
            0x49,0x24,0xca,0x1c,0x60,0x90,0x2e,0x52,
            0xf0,0xa0,0x89,0xbc,0x76,0x89,0x70,0x40,
            0xe0,0x82,0xf9,0x37,0x76,0x38,0x48,0x64,
            0x5e,0x07,0x05 ];
        let box_expected = vec![
            0xf3,0xff,0xc7,0x70,0x3f,0x94,0x00,0xe5,
            0x2a,0x7d,0xfb,0x4b,0x3d,0x33,0x05,0xd9,
            0x8e,0x99,0x3b,0x9f,0x48,0x68,0x12,0x73,
            0xc2,0x96,0x50,0xba,0x32,0xfc,0x76,0xce,
            0x48,0x33,0x2e,0xa7,0x16,0x4d,0x96,0xa4,
            0x47,0x6f,0xb8,0xc5,0x31,0xa1,0x18,0x6a,
            0xc0,0xdf,0xc1,0x7c,0x98,0xdc,0xe8,0x7b,
            0x4d,0xa7,0xf0,0x11,0xec,0x48,0xc9,0x72,
            0x71,0xd2,0xc2,0x0f,0x9b,0x92,0x8f,0xe2,
            0x27,0x0d,0x6f,0xb8,0x63,0xd5,0x17,0x38,
            0xb4,0x8e,0xee,0xe3,0x14,0xa7,0xcc,0x8a,
            0xb9,0x32,0x16,0x45,0x48,0xe5,0x26,0xae,
            0x90,0x22,0x43,0x68,0x51,0x7a,0xcf,0xea,
            0xbd,0x6b,0xb3,0x73,0x2b,0xc0,0xe9,0xda,
            0x99,0x83,0x2b,0x61,0xca,0x01,0xb6,0xde,
            0x56,0x24,0x4a,0x9e,0x88,0xd5,0xf9,0xb3,
            0x79,0x73,0xf6,0x22,0xa4,0x3d,0x14,0xa6,
            0x59,0x9b,0x1f,0x65,0x4c,0xb4,0x5a,0x74,
            0xe3,0x55,0xa5
        ];

        let boxed = crypto_box(&msg[], &nonce[], &bobpk[], &alicesk[]);
        assert!(boxed == box_expected);

        match crypto_box_open(&box_expected[], &nonce[], &alicepk[], &bobsk[]) {
            Ok(unboxed) => assert!(unboxed == msg),
            Err(_) => panic!()
        }
    }
}
