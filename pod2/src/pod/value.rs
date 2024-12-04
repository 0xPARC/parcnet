use ark_ff::BigInteger;
use ark_ff::PrimeField;
use parcnet_pod::pod::{Fq, PodValue};
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

impl From<u64> for ScalarOrVec {
    fn from(x: u64) -> Self {
        Self::Vector(vec![
            GoldilocksField((x as u32) as u64),
            GoldilocksField(x >> 32),
        ])
    }
}

impl From<i64> for ScalarOrVec {
    fn from(x: i64) -> Self {
        Self::from(x as u64)
    }
}

impl From<Fq> for ScalarOrVec {
    fn from(x: Fq) -> Self {
        let x_bytes = &x.into_bigint().to_bytes_le();
        // Group LE bytes into 32-bit chunks.
        let x_fields = x_bytes
            .chunks(4)
            .map(|chunk| {
                GoldilocksField(chunk.iter().rev().fold(0, |acc, b| 8 * acc + *b as u32) as u64)
            })
            .collect::<Vec<_>>();
        ScalarOrVec::Vector(x_fields)
    }
}

impl From<PodValue> for ScalarOrVec {
    fn from(pod_value: PodValue) -> Self {
        match pod_value {
            // TODO: Ponder over these choices. GPC does not pass ints
            // and 'cryptographics' in by value. On the other hand, we
            // have not fixed the representations of other types in
            // this system yet, hence the hashing in other cases.

            // Represent i64 as LE u32 array of corresponding u64.
            PodValue::Int(n) => Self::from(n),
            // Represent BN254 scalar field element as LE u32 array.
            PodValue::Cryptographic(n) => Self::from(n),
            // Represent boolean as 0 or 1.
            PodValue::Boolean(b) => Self::Scalar(GoldilocksField(b as u64)),
            // Treat date as integer (Unix time).
            PodValue::Date(d) => Self::from(PodValue::Int(
                <i128 as TryInto<i64>>::try_into(d.unix_timestamp_nanos())
                    .expect("Could not fit current Unix time in an i64.")
                    / 1_000_000,
            )),
            // Pass the rest in by (BN254 Poseidon) hash.
            _ => Self::from(
                pod_value
                    .hash()
                    .unwrap_or_else(|_| panic!("Error hashing value {:?}.", pod_value)),
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
