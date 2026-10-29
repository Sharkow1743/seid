//! Serde serialization and deserialization implementations for both human-readable and binary formats.

use core::fmt;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::block::{BlockType, InlineStr, RawBlock};
use crate::seid::Seid;

impl Serialize for Seid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.collect_str(self)
        } else {
            let encoded = self.to_encoded();
            serializer.serialize_bytes(encoded.as_bytes())
        }
    }
}

impl<'de> Deserialize<'de> for Seid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SeidVisitor;

        impl<'de> de::Visitor<'de> for SeidVisitor {
            type Value = Seid;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid Base62 Seid identifier string or byte sequence")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Seid::parse(value).map_err(de::Error::custom)
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let s = core::str::from_utf8(v).map_err(de::Error::custom)?;
                Seid::parse(s).map_err(de::Error::custom)
            }

            fn visit_byte_buf<E>(self, v: alloc::vec::Vec<u8>) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_bytes(&v)
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(SeidVisitor)
        } else {
            deserializer.deserialize_bytes(SeidVisitor)
        }
    }
}

impl Serialize for RawBlock {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl Serialize for BlockType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(self.as_u8())
    }
}

impl<'de> Deserialize<'de> for BlockType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let val = u8::deserialize(deserializer)?;
        Ok(BlockType::from_u8(val))
    }
}

impl Serialize for InlineStr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}
