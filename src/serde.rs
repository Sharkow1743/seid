//! Serde serialization and deserialization implementations.

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
                formatter.write_str("a valid Base62 Seid identifier string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Seid::parse(value).map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_str(SeidVisitor)
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
