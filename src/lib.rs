// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![crate_name = "crypto-nacl"]

#![feature(simd)]
#![cfg_attr(test, feature(test))]

extern crate rand;
extern crate crypto;
#[cfg(test)] extern crate test;

// The NaCl C++ library has a flat namespace, so mimic that for the API
// compatible routines.
pub use pkbox::*;
pub use secretbox::*;
mod pkbox;
mod secretbox;
