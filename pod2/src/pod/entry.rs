use anyhow::{anyhow, Result};
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

    /// Pads an entry's value if it is a vector. Padding is chosen so
    /// as to define the same set as the original vector.
    pub fn pad_if_vec<const VL: usize>(&self) -> Result<Self> {
        match &self.value {
            ScalarOrVec::Scalar(_) => Ok(self.clone()),
            ScalarOrVec::Vector(v) if v.len() <= VL => v.first()
                .ok_or(anyhow!(
                    "Entry with key {} has empty vector as value!",
                    self.key
                )).map(|padding| Self {
                        key: self.key.clone(),
                        value: ScalarOrVec::Vector(
                            [v.clone(), (v.len()..VL).map(|_| *padding).collect()].concat(),
                        ),
                    }),
            ScalarOrVec::Vector(v) => Err(anyhow!(
                "Entry with key {} has vector of length {}, which exceeds the maximum ({})!",
                self.key,
                v.len(),
                VL
            )),
        }
    }

    /// Representation as field vector of length 2.
    pub fn to_fields(&self) -> Vec<GoldilocksField> {
        vec![hash_string_to_field(&self.key), self.value.hash_or_value()]
    }
}
