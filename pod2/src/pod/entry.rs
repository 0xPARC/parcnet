use plonky2::field::goldilocks_field::GoldilocksField;

use super::value::ScalarOrVec;
use crate::pod::{util::hash_string_to_field, value::HashableEntryValue};

/// An Entry, which is just a key-value pair.
#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub key: String,
    pub value: ScalarOrVec,
}

impl Entry {
    pub fn new_from_scalar(key: &str, value: GoldilocksField) -> Self {
        Entry {
            key: key.to_string(),
            value: ScalarOrVec::Scalar(value),
        }
    }

    pub fn new_from_vec(key: &str, value: Vec<GoldilocksField>) -> Self {
        Entry {
            key: key.to_string(),
            value: ScalarOrVec::Vector(value),
        }
    }

    /// Representation as field vector of length 2.
    pub fn to_fields(&self) -> Vec<GoldilocksField> {
        vec![hash_string_to_field(&self.key), self.value.hash_or_value()]
    }
}
