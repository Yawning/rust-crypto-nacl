# Rust-Crypto-NaCl

A Rust-Crypto based implementation of selected NaCl primitives.

Rust-Crypto-NaCl seeks to provide selected high level primitives from the
popular NaCl/TweetNaCl/libsodium family of cryptographic libraries. With a
interface that is modeled after the C++ version of the API.

## Usage

To use Rust-Crypto-NaCl, add the following to your Cargo.toml:

```toml
[dependencies]
rust-crypto-nacl = "*"
```

and the following to your crate root:

```rust
extern crate "crypto-nacl" as nacl;
```

## License

Rust-Crypto-NaCl is dual licensed under the MIT and Apache 2.0 licenses, the
same licenses as the Rust-Crypto and the Rust compiler.

## Primitives

 * crypto_box ("crypto_box_curve25519xsalsa20poly1305")
 * crypto_secretbox ("crypto_secretbox_xsalsa20poly1305")

