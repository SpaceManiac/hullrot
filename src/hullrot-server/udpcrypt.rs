/*
Hullrot is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Hullrot is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with Hullrot.  If not, see <http://www.gnu.org/licenses/>.
*/

// Rust implementation of Mumble's UDP crypto. Based on CryptState:
// https://github.com/mumble-voip/mumble/blob/0da917b892b5300f24ebc4607f1517f76a22766f/src/CryptState.h
// https://github.com/mumble-voip/mumble/blob/0da917b892b5300f24ebc4607f1517f76a22766f/src/CryptState.cpp

// Copyright 2005-2019 The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

/*
 * This code implements OCB-AES128.
 * In the US, OCB is covered by patents. The inventor has given a license
 * to all programs distributed under the GPL.
 * Mumble is BSD (revised) licensed, meaning you can use the code in a
 * closed-source program. If you do, you'll have to either replace
 * OCB with something else or get yourself a license.
 */

#![allow(dead_code, unused_variables, unused_mut)]  // TODO

const AES_KEY_SIZE_BYTES: usize = 16;
const AES_BLOCK_SIZE: usize = 16;

pub struct CryptState {
    raw_key: [u8; AES_KEY_SIZE_BYTES],
    encrypt_iv: [u8; AES_BLOCK_SIZE],
    decrypt_iv: [u8; AES_BLOCK_SIZE],
    decrypt_history: [u8; 0x100],
}

impl CryptState {
    pub fn generate() -> CryptState {
        let mut raw_key = [0; AES_KEY_SIZE_BYTES];
        let mut encrypt_iv = [0; AES_BLOCK_SIZE];
        let mut decrypt_iv = [0; AES_BLOCK_SIZE];

        openssl::rand::rand_bytes(&mut raw_key).expect("rand_bytes failed");
        openssl::rand::rand_bytes(&mut encrypt_iv).expect("rand_bytes failed");
        openssl::rand::rand_bytes(&mut decrypt_iv).expect("rand_bytes failed");

        CryptState {
            raw_key,
            encrypt_iv,
            decrypt_iv,
            decrypt_history: [0; 0x100],
        }
    }

    pub fn from_parameters(rkey: &[u8], eiv: &[u8], div: &[u8]) -> CryptState {
        unimplemented!()
    }

    fn decrypt(&mut self, source: &[u8], dst: &mut [u8]) -> bool {
        if source.len() < 4 {
            return false;
        }

        let plain_length = source.len() - 4;
        let mut saveiv = [0u8; AES_BLOCK_SIZE];
        let ivbyte = source[0];
        let mut restore = false;
        let mut tag = [0u8; AES_KEY_SIZE_BYTES];

        let mut lost = 0;
        let mut late = 0;

        saveiv.copy_from_slice(&self.decrypt_iv);

        if self.decrypt_iv[0].wrapping_add(1) == ivbyte {
            // In order as expected.
            if ivbyte > self.decrypt_iv[0] {
                self.decrypt_iv[0] = ivbyte;
            } else if ivbyte < self.decrypt_iv[0] {
                self.decrypt_iv[0] = ivbyte;
                increment_iv(&mut self.decrypt_iv[1..]);
            } else {
                return false;
            }
        } else {
            // This is either out of order or a repeat.
            unimplemented!();
        }

        unimplemented!()
    }
}

fn increment_iv(iv: &mut [u8]) {
    for each in iv.iter_mut() {
        match each.checked_add(1) {
            None => *each = 0,
            Some(x) => { *each = x; break; }
        }
    }
}

// ----------------------------------------------------------------------------
// OCB implementation

#[cfg(target_pointer_width = "64")]
mod platform {
    pub const BLOCKSIZE: usize = 2;
    pub const SHIFTBITS: u32 = 63;
    pub type Subblock = u64;
}

#[cfg(target_pointer_width = "32")]
mod platform {
    pub const BLOCKSIZE: usize = 4;
    pub const SHIFTBITS: u32 = 31;
    pub type Subblock = u32;
}

use self::platform::*;

type Keyblock = [Subblock; BLOCKSIZE];

#[inline]
fn swapped(x: Subblock) -> Subblock {
    x.to_be()
}

#[inline]
fn xor(dst: &mut Keyblock, a: &Keyblock, b: &Keyblock) {
    for ((dst_i, a_i), b_i) in dst.iter_mut().zip(a).zip(b) {
        *dst_i = *a_i ^ *b_i;
    }
}

#[inline]
fn s2(block: &mut Keyblock) {
    let carry = swapped(block[0]) >> SHIFTBITS;
    for i in 0..BLOCKSIZE-1 {
        block[i] = swapped((swapped(block[i]) << 1) | (swapped(block[i + 1]) >> SHIFTBITS));
    }
    block[BLOCKSIZE - 1] = swapped((swapped(block[BLOCKSIZE - 1]) << 1) ^ (carry * 0x87));
}

#[inline]
fn s3(block: &mut Keyblock) {
    let carry = swapped(block[0]) >> SHIFTBITS;
    for i in 0..BLOCKSIZE-1 {
        block[i] ^= swapped((swapped(block[i]) << 1) | (swapped(block[i + 1]) >> SHIFTBITS));
    }
    block[BLOCKSIZE - 1] ^= swapped((swapped(block[BLOCKSIZE - 1]) << 1) ^ (carry * 0x87));
}

#[inline]
fn zero(block: &mut Keyblock) {
    for block_i in block.iter_mut() {
        *block_i = 0;
    }
}

fn ocb_encrypt(plain: &[u8], encrypted: &mut [u8], nonce: &[u8], tag: &mut [u8]) {
    unimplemented!()
}

fn ocb_decrypt(encrypted: &[u8], plain: &mut [u8], nonce: &[u8], tag: &mut [u8]) {
    unimplemented!()
}
