// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to this example, using the creative
// commons "cc0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

extern crate rand;
extern crate "crypto-nacl" as nacl;

use rand::{ Rng, OsRng };
use nacl::{ crypto_box_SECRETKEYBYTES, crypto_box_NONCEBYTES,
  crypto_box_keypair, crypto_box, crypto_box_open };

fn main() {
    //
    // Example public-key authenticated encryption/decryption.
    //
    // For the purposes of the example, both Alice (the sender),
    // and Bob (the receiver) are shown, though real applications will
    // only do one side.

    let mut rng = OsRng::new().ok().unwrap();
    let test_msg = "Example plaintext data.".as_bytes();

    // Generate a keypair using a cryptographically strong entropy source.
    let mut alice_sk = [0u8; crypto_box_SECRETKEYBYTES];
    let alice_pk = crypto_box_keypair(&mut alice_sk);

    let mut bob_sk = [0u8; crypto_box_SECRETKEYBYTES];
    let bob_pk = crypto_box_keypair(&mut bob_sk);

    // (NOT SHOWN) Alice/Bob exchange alice_pk/bob_pk. How this is done
    // is left up to the application. Note that if the exchange takes
    // place over an insecure channel, then further steps must be taken
    // to thwart man-in-the-middle attacks.
    //
    // Alice should have: alice_pk, alice_sk, bob_pk
    // Bob should have: bob_pk, bob_sk, alice_pk

    // The construct's security depends on the key/nonce pair being
    // unique per message. The NaCl documentation lists using a counter,
    // or randomly generating the nonce among possible options. In this
    // example, a randomly generated nonce is used.
    //
    // If random nonces are used, generating a new one on each call to
    // crypto_secretbox() should be sufficient to avoid unplesant
    // suprises, as long as a strong entropy source is used.
    let mut nonce = [0u8; crypto_box_NONCEBYTES];
    rng.fill_bytes(&mut nonce);

    // Encrypt and Authenticate a message. The ciphertext will be a
    // vector containing the encrypted/authenticated message, and
    // will be crypto_box_OVERHEADBYTES larger than the message.
    //
    // Note: The nonce must be communicated to the decrypting party
    // separately. How to do so is beyond the scope of this example,
    // but it is worth noting that unless there are reasons otherwise,
    // it does not need to be kept secret (Eg: Transmitting it in the
    // clear over the network is ok.).
    let ciphertext = crypto_box(test_msg, &nonce, &bob_pk, &alice_sk);

    // Authenticate and Decrypt a message. The same nonce that was used to
    // encrypt/authenticate the message must be used for the
    // authenticate/decrypt.
    match crypto_box_open(&ciphertext[], &nonce, &alice_pk, &bob_sk) {
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
