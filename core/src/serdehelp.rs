//! Small serde helpers so byte fields are hex/base64 on the wire instead of
//! JSON number arrays.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Deserializer, Serializer};

/// `[u8; 32]` <-> lowercase hex string.
pub mod hex32 {
    use super::*;

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

/// `Vec<u8>` <-> base64 string.
pub mod b64vec {
    use super::*;

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        B64.decode(s.as_bytes()).map_err(serde::de::Error::custom)
    }
}

/// `Vec<Vec<u8>>` <-> JSON array of base64 strings.
pub mod b64vec_nested {
    use super::*;
    use serde::Serialize;

    pub fn serialize<S: Serializer>(v: &Vec<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        let enc: Vec<String> = v.iter().map(|b| B64.encode(b)).collect();
        enc.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
        let enc: Vec<String> = Vec::deserialize(d)?;
        enc.into_iter()
            .map(|s| B64.decode(s.trim()).map_err(serde::de::Error::custom))
            .collect()
    }
}
