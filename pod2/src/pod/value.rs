use parcnet_pod::pod::pod_impl::{string_hash, PodValue};
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::poseidon::PoseidonHash,
    plonk::config::{GenericHashOut, Hasher},
};
use serde::{Deserialize, Serialize};

// EntryValue trait, and ScalarOrVec type which implements it.
// This is a field element or array of field elements.
pub trait HashableEntryValue: Clone + PartialEq {
    fn hash_or_value(&self) -> GoldilocksField;
}

impl HashableEntryValue for GoldilocksField {
    fn hash_or_value(&self) -> GoldilocksField {
        *self
    }
}

impl HashableEntryValue for Vec<GoldilocksField> {
    fn hash_or_value(&self) -> GoldilocksField {
        PoseidonHash::hash_no_pad(self).to_vec()[0]
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum ScalarOrVec {
    Scalar(GoldilocksField),
    Vector(Vec<GoldilocksField>),
}

impl From<&PodValue> for ScalarOrVec {
    fn from(pod_value: &PodValue) -> Self {
        match pod_value {
            PodValue::Int(n) => Self::Scalar(GoldilocksField(*n as u64)),
            PodValue::Cryptographic(n) => Self::Vector(
                n.to_u32_digits()
                    .1
                    .iter()
                    .rev()
                    .map(|n| GoldilocksField(*n as u64))
                    .collect(),
            ),
            PodValue::String(s) => Self::Vector(
                string_hash(s)
                    .to_u32_digits()
                    .1
                    .iter()
                    .rev()
                    .map(|n| GoldilocksField(*n as u64))
                    .collect(),
            ),
        }
    }
}

impl HashableEntryValue for ScalarOrVec {
    fn hash_or_value(&self) -> GoldilocksField {
        match self {
            Self::Scalar(s) => s.hash_or_value(),
            Self::Vector(v) => v.hash_or_value(),
        }
    }
}
