use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ObjectID(String);

impl ObjectID {
    pub fn new(id: String) -> Self {
        Self(id)
    }
    
    pub fn to_string(&self) -> String {
        self.0.clone()
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
    pub data: Vec<u8>, // Raw data, can be JSON or BCS/Borsh later
    pub type_struct: String, // e.g., "0x2::coin::Coin<0x2::sui::SUI>"
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
