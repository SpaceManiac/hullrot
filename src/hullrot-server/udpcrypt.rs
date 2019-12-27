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

use openssl::symm;

const AES_KEY_SIZE_BYTES: usize = 16;
const AES_BLOCK_SIZE: usize = 16;

type AesKey = symm::Crypter;

pub struct CryptState {
    raw_key: [u8; AES_KEY_SIZE_BYTES],
    encrypt_iv: [u8; AES_BLOCK_SIZE],
    decrypt_iv: [u8; AES_BLOCK_SIZE],
    decrypt_history: [u8; 0x100],

    encrypt_key: AesKey,
    decrypt_key: AesKey,
}

impl std::fmt::Debug for CryptState {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        fmt.write_str("CryptState")
    }
}

impl CryptState {
    pub fn generate() -> CryptState {
        let mut raw_key = [0; AES_KEY_SIZE_BYTES];
        let mut encrypt_iv = [0; AES_BLOCK_SIZE];
        let mut decrypt_iv = [0; AES_BLOCK_SIZE];

        openssl::rand::rand_bytes(&mut raw_key).expect("rand_bytes failed");
        openssl::rand::rand_bytes(&mut encrypt_iv).expect("rand_bytes failed");
        openssl::rand::rand_bytes(&mut decrypt_iv).expect("rand_bytes failed");

        let cipher = symm::Cipher::aes_128_ecb();
        let encrypt_key = symm::Crypter::new(cipher, symm::Mode::Encrypt, &raw_key, None).unwrap();
        let decrypt_key = symm::Crypter::new(cipher, symm::Mode::Decrypt, &raw_key, None).unwrap();

        CryptState {
            raw_key,
            encrypt_iv,
            decrypt_iv,
            decrypt_history: [0; 0x100],

            encrypt_key,
            decrypt_key,
        }
    }

    //pub fn from_parameters(rkey: &[u8], eiv: &[u8], div: &[u8]) -> CryptState;

    pub fn to_parameters(&self) -> mumble_protocol::CryptSetup {
        packet! { CryptSetup;
            set_key: self.raw_key.to_vec(),
            set_client_nonce: self.decrypt_iv.to_vec(),
            set_server_nonce: self.encrypt_iv.to_vec(),
        }
    }

    pub fn encrypt<'d>(&mut self, source: &[u8], dst: &'d mut [u8]) -> &'d mut [u8] {
        let mut tag = [0; AES_BLOCK_SIZE];

        // First, increase our IV.
        increment_iv(&mut self.encrypt_iv);

        ocb_encrypt(&mut self.encrypt_key, source, &mut dst[4..4 + source.len()], &self.encrypt_iv, &mut tag);

        dst[0] = self.encrypt_iv[0];
        dst[1] = tag[0];
        dst[2] = tag[1];
        dst[3] = tag[2];
        &mut dst[..4 + source.len()]
    }

    pub fn decrypt(&mut self, source: &[u8], dst: &mut [u8]) -> bool {
        if source.len() < 4 {
            return false;
        }

        let mut saveiv = [0u8; AES_BLOCK_SIZE];
        let ivbyte = source[0];
        let mut restore = false;
        let mut tag = [0u8; AES_KEY_SIZE_BYTES];

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

            let diff = ivbyte.wrapping_sub(self.decrypt_iv[0]) as i8;

            if ivbyte < self.decrypt_iv[0] && diff > -30 && diff < 0 {
                // Late packet, but no wraparound.
                //late = 1;
                //lost = -1;
                self.decrypt_iv[0] = ivbyte;
                restore = true;
            } else if ivbyte > self.decrypt_iv[0] && diff > -30 && diff < 0 {
                // Last was 0x02, here comes 0xff from last round
                //late = 1;
                //lost = -1;
                self.decrypt_iv[0] = ivbyte;
                decrement_iv(&mut self.decrypt_iv[1..]);
                restore = true;
            } else if ivbyte > self.decrypt_iv[0] && diff > 0 {
                // Lost a few packets, but beyond that we're good.
                //lost = (ivbyte as i32).wrapping_sub(self.decrypt_iv[0] as i32).wrapping_sub(1);
                self.decrypt_iv[0] = ivbyte;
            } else if ivbyte < self.decrypt_iv[0] && diff > 0 {
                // Lost a few packets, and wrapped around.
                //lost = 255i32.wrapping_sub(self.decrypt_iv[0] as i32).wrapping_add(ivbyte as i32);
                self.decrypt_iv[0] = ivbyte;
                increment_iv(&mut self.decrypt_iv[1..]);
            } else {
                return false;
            }
        }

        ocb_decrypt(&mut self.encrypt_key, &mut self.decrypt_key, &source[4..], dst, &self.decrypt_iv, &mut tag);

        if &tag[..3] != &source[1..4] {
            self.decrypt_iv.copy_from_slice(&saveiv);
            return false;
        }
        self.decrypt_history[self.decrypt_iv[0] as usize] = self.decrypt_iv[1];

        if restore {
            self.decrypt_iv.copy_from_slice(&saveiv);
        }

        // uiGood++;
        // uiLate += late;
        // uiLost += lost;

        // tLastGood.restart();
        true
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

fn decrement_iv(iv: &mut [u8]) {
    for each in iv.iter_mut() {
        match each.checked_sub(1) {
            None => *each = 255,
            Some(x) => { *each = x; break; }
        }
    }
}

// ----------------------------------------------------------------------------
// OCB implementation

/*
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
*/

const BLOCKSIZE: usize = 128 / 8;
const SHIFTBITS: u32 = 7;
type Subblock = u8;

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
fn xor_self(dst: &mut Keyblock, b: &Keyblock) {
    for (dst_i, b_i) in dst.iter_mut().zip(b) {
        *dst_i = *dst_i ^ *b_i;
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
fn zero<T: Default>(block: &mut [T]) {
    for block_i in block.iter_mut() {
        *block_i = Default::default();
    }
}

fn aes_encrypt(src: &[u8], dst: &mut [u8], key: &mut AesKey) {
    let mut dst2 = [0; 2 * AES_BLOCK_SIZE];
    let len = key.update(src, &mut dst2).unwrap();
    dst.copy_from_slice(&dst2[..len]);
}

fn aes_decrypt(src: &[u8], dst: &mut [u8], key: &mut AesKey) {
    aes_encrypt(src, dst, key)
}

use std::convert::TryInto;

fn ocb_encrypt(encrypt_key: &mut AesKey, mut plain: &[u8], mut encrypted: &mut [u8], nonce: &[u8], tag: &mut [u8]) {
    assert_eq!(plain.len(), encrypted.len());
    let mut len = plain.len();

    let mut delta = Keyblock::default();
    let mut tmp = Keyblock::default();
    let mut pad = Keyblock::default();

    // Initialize
    aes_encrypt(nonce, &mut delta, encrypt_key);
    let mut checksum = Keyblock::default();

    while len > AES_BLOCK_SIZE {
        s2(&mut delta);
        xor(&mut tmp, &delta, (&plain[..AES_BLOCK_SIZE]).try_into().unwrap());
        aes_encrypt(&tmp, &mut pad, encrypt_key);
        tmp.copy_from_slice(&pad);
        xor((&mut encrypted[..AES_BLOCK_SIZE]).try_into().unwrap(), &delta, &tmp);
        xor_self(&mut checksum, (&plain[..AES_BLOCK_SIZE]).try_into().unwrap());
        len -= AES_BLOCK_SIZE;
        plain = &plain[AES_BLOCK_SIZE..];
        encrypted = &mut encrypted[AES_BLOCK_SIZE..];
    }

    s2(&mut delta);
    zero(&mut tmp);
    tmp[BLOCKSIZE - 1] = swapped((len * 8) as Subblock);
    xor_self(&mut tmp, &delta);
    aes_encrypt(&tmp, &mut pad, encrypt_key);
    tmp[..len].copy_from_slice(plain);
    tmp[len..].copy_from_slice(&pad[len..]);
    xor_self(&mut checksum, &tmp);
    xor_self(&mut tmp, &pad);
    encrypted[..len].copy_from_slice(&tmp[..len]);

    s3(&mut delta);
    xor(&mut tmp, &delta, &checksum);
    aes_encrypt(&tmp, tag, encrypt_key);
}

fn ocb_decrypt(encrypt_key: &mut AesKey, decrypt_key: &mut AesKey, mut encrypted: &[u8], mut plain: &mut [u8], nonce: &[u8], tag: &mut [u8]) {
    assert_eq!(plain.len(), encrypted.len());
    let mut len = plain.len();

    let mut delta = Keyblock::default();
    let mut tmp = Keyblock::default();
    let mut pad = Keyblock::default();

    // Initialize
    aes_encrypt(nonce, &mut delta, encrypt_key);
    let mut checksum = Keyblock::default();

    while len > AES_BLOCK_SIZE {
        s2(&mut delta);
        xor(&mut tmp, &delta, (&encrypted[..AES_BLOCK_SIZE]).try_into().unwrap());
        aes_decrypt(&tmp, &mut pad, decrypt_key);
        tmp.copy_from_slice(&pad);
        xor((&mut plain[..AES_BLOCK_SIZE]).try_into().unwrap(), &delta, &tmp);
        xor_self(&mut checksum, (&plain[..AES_BLOCK_SIZE]).try_into().unwrap());
        len -= AES_BLOCK_SIZE;
        plain = &mut plain[AES_BLOCK_SIZE..];
        encrypted = &encrypted[AES_BLOCK_SIZE..];
    }

    s2(&mut delta);
    zero(&mut tmp);
    tmp[BLOCKSIZE - 1] = swapped((len * 8) as Subblock);
    xor_self(&mut tmp, &delta);
    aes_encrypt(&tmp, &mut pad, encrypt_key);
    zero(&mut tmp);
    tmp[..len].copy_from_slice(&encrypted[..len]);
    xor_self(&mut tmp, &pad);
    xor_self(&mut checksum, &tmp);
    plain[..len].copy_from_slice(&tmp[..len]);

    s3(&mut delta);
    xor(&mut tmp, &delta, &checksum);
    aes_encrypt(&tmp, tag, encrypt_key);
}
