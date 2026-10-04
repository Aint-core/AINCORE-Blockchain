use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ObjectID(String);

impl ObjectID {
    pub fn new(id: String) -> Self {
        Self(id)
    }
}

impl std::fmt::Display for ObjectID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Owner {
    Address(String), // Owned by a user/address
    Shared,          // Shared object (consensus required)
    Immutable,       // Cannot be changed
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Object {
    pub id: ObjectID,
    pub version: u64,
    pub owner: Owner,
    /// Raw data (an account's is its JSON record), stored by `compact_bytes`.
    #[serde(with = "compact_bytes")]
    pub data: Vec<u8>,
    pub type_struct: String, // e.g., "0x2::coin::Coin<0x2::sui::SUI>"
}

/// B66: `data` is stored as its text when it is UTF-8 (an account record is
/// JSON), else as the array of its bytes, so a value has one encoding and
/// state roots stay canonical. The array alone cost ~3.5 bytes of state a
/// byte (`123,`), which B65's state gas charges. Both forms are read.
mod compact_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(data: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        match std::str::from_utf8(data) {
            Ok(text) => serializer.serialize_str(text),
            Err(_) => serializer.collect_seq(data),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Stored {
            Text(String),
            Bytes(Vec<u8>),
        }
        Ok(match Stored::deserialize(deserializer)? {
            Stored::Text(text) => text.into_bytes(),
            Stored::Bytes(bytes) => bytes,
        })
    }
}

impl Object {
    pub fn new(id: String, owner: Owner, data: Vec<u8>, type_struct: String) -> Self {
        Self {
            id: ObjectID::new(id),
            version: 0,
            owner,
            data,
            type_struct,
        }
    }
}
