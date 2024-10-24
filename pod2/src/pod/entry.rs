use plonky2::field::goldilocks_field::GoldilocksField;

use super::value::ScalarOrVec;

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
}
