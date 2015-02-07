// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to this example, using the creative
// commons "cc0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

extern crate rand;
extern crate "crypto-nacl" as nacl;

use rand::{ Rng, OsRng };
use nacl::{ crypto_secretbox_KEYBYTES, crypto_secretbox_NONCEBYTES,
  crypto_secretbox, crypto_secretbox_open };

fn main() {
    //
    // Example symmetric authenticated encryption/decryption.
    //

    let mut rng = OsRng::new().ok().unwrap();
    let test_msg = "Example plaintext data.".as_bytes();

    // In a real program, the key should be determined using some other
    // mechanism. If public key cryptography is desired, the crypto_box
    // construct may be a better choice.
    let mut key = [0u8; crypto_secretbox_KEYBYTES];
    rng.fill_bytes(&mut key); // EXAMPLE: A randomly generated key.

    // The construct's security depends on the key/nonce pair being
    // unique per message. The NaCl documentation lists using a counter,
    // or randomly generating the nonce among possible options. In this
    // example, a randomly generated nonce is used.
    //
    // If random nonces are used, generating a new one on each call to
    // crypto_secretbox() should be sufficient to avoid unplesant
    // suprises, as long as a strong entropy source is used.
    let mut nonce = [0u8; crypto_secretbox_NONCEBYTES];
    rng.fill_bytes(&mut nonce);

    // Encrypt and Authenticate a message. The ciphertext will be a
    // vector containing the encrypted/authenticated message, and
    // will be crypto_secretbox_OVERHEADBYTES larger than the message.
    //
    // Note: The nonce must be communicated to the decrypting party
    // separately. How to do so is beyond the scope of this example,
    // but it is worth noting that unless there are reasons otherwise,
    // it does not need to be kept secret (Eg: Transmitting it in the
    // clear over the network is ok.).
    let ciphertext = crypto_secretbox(test_msg, &nonce, &key);

    // Authenticate and Decrypt a message. As this is symmetric
    // cryptography, the same key and nonce that was used to
    // encrypt/authenticate the message must be used for the
    // authenticate/decrypt.
    match crypto_secretbox_open(&ciphertext[], &nonce, &key) {
        Ok(plaintext) => {
            // The authenticate/decrypt was successful. The plaintext
            // is a byte vector that is crypto_secretbox_OVERHEAD bytes
            //shorter than the ciphertext.
            assert!(&plaintext[] == &test_msg[]);
        },
        Err(_) => {
            // The authenticate/decrypt failed. Either the ciphertext is
            // pathologically malformed (too short to be valid), or the
            // authentication failed for some reason.
            //
            // How to handle this situation is up to the application.
            panic!();
        }
    }
}
