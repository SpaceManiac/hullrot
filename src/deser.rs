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

//! Deserialization helpers to work around BYOND having no booleans and Gmod
//! having no integers.
// https://github.com/Facepunch/garrysmod-issues/issues/3403

use std::fmt;
use serde::*;
use Freq;

/// Deserialize 1 or 0 as true or false.
pub fn as_bool<'de, D: Deserializer<'de>>(de: D) -> Result<bool, D::Error> {
    struct BoolVisitor;
    impl<'de> de::Visitor<'de> for BoolVisitor {
        type Value = bool;

        fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
            fmt.write_str("boolish")
        }

        fn visit_i64<E: de::Error>(self, value: i64) -> Result<bool, E> {
            Ok(value != 0)
        }

        fn visit_u64<E: de::Error>(self, value: u64) -> Result<bool, E> {
            Ok(value != 0)
        }

        fn visit_f64<E: de::Error>(self, value: f64) -> Result<bool, E> {
            Ok(value != 0.)
        }

        fn visit_bool<E: de::Error>(self, value: bool) -> Result<bool, E> {
            Ok(value)
        }
    }
    de.deserialize_any(BoolVisitor)
}

/// Deserialize any number as an i32.
pub fn as_int<'de, D: Deserializer<'de>>(de: D) -> Result<i32, D::Error> {
    struct NumVisitor;
    impl<'de> de::Visitor<'de> for NumVisitor {
        type Value = i32;

        fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
            fmt.write_str("i32ish")
        }

        fn visit_i64<E: de::Error>(self, value: i64) -> Result<i32, E> {
            Ok(value as i32)
        }

        fn visit_u64<E: de::Error>(self, value: u64) -> Result<i32, E> {
            Ok(value as i32)
        }

        fn visit_f64<E: de::Error>(self, value: f64) -> Result<i32, E> {
            Ok(value as i32)
        }
    }
    de.deserialize_any(NumVisitor)
}

/// Deserialize any number as a u16.
impl<'de> Deserialize<'de> for Freq {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Freq, D::Error> {
        struct NumVisitor;
        impl<'de> de::Visitor<'de> for NumVisitor {
            type Value = u16;

            fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
                fmt.write_str("u16ish")
            }

            fn visit_i64<E: de::Error>(self, value: i64) -> Result<u16, E> {
                Ok(value as u16)
            }

            fn visit_u64<E: de::Error>(self, value: u64) -> Result<u16, E> {
                Ok(value as u16)
            }

            fn visit_f64<E: de::Error>(self, value: f64) -> Result<u16, E> {
                Ok(value as u16)
            }
        }
        de.deserialize_any(NumVisitor).map(Freq)
    }
}
