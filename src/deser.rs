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
use std::collections::HashMap;
use std::marker::PhantomData;
use std::hash::Hash;
use std::cmp::Eq;

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

impl<'de> Deserialize<'de> for ::Z {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<::Z, D::Error> {
        de.deserialize_any(NumVisitor).map(::Z)
    }
}

impl<'de> Deserialize<'de> for ::ZGroup {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<::ZGroup, D::Error> {
        de.deserialize_any(NumVisitor).map(::ZGroup)
    }
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

/// Deserialize the empty sequence `[]` as the empty map `{}`.
pub fn as_map<'de, D, K, V>(de: D) -> Result<HashMap<K, V>, D::Error> where
    D: Deserializer<'de>,
    K: Deserialize<'de> + Hash + Eq,
    V: Deserialize<'de>,
{
    struct MapVisitor<K, V>(PhantomData<(K, V)>);
    impl<'de, K, V> de::Visitor<'de> for MapVisitor<K, V> where
        K: Deserialize<'de> + Hash + Eq,
        V: Deserialize<'de>,
    {
        type Value = HashMap<K, V>;

        fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
            fmt.write_str("map or empty sequence")
        }

        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            use serde::de::Error;
            match seq.next_element()? {
                Some(()) => Err(Error::invalid_length(1, &"empty sequence")),
                None => Ok(Default::default()),
            }
        }

        fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut values = HashMap::with_capacity(map.size_hint().unwrap_or(0));
            while let Some((key, value)) = map.next_entry()? {
                values.insert(key, value);
            }
            Ok(values)
        }
    }
    de.deserialize_any(MapVisitor(PhantomData))
}
