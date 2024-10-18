use anyhow::Result;
use plonky2::{field::{goldilocks_field::GoldilocksField, types::Field}, iop::{target::Target, witness::{PartialWitness, WitnessWrite}}, plonk::circuit_builder::CircuitBuilder};

use crate::pod::{statement::{AnchoredKey, Statement}, util::hash_string_to_field, value::HashableEntryValue};

use super::origin::OriginTarget;

#[derive(Clone, Debug, PartialEq)]
pub struct AnchoredKeyTarget(pub OriginTarget, pub Target);

impl AnchoredKeyTarget {
    pub fn new_virtual(builder: &mut CircuitBuilder<GoldilocksField, 2>) -> Self {
        Self(OriginTarget::new_virtual(builder), builder.add_virtual_target())
    }

    pub fn set_witness(
        &self,
        pw: &mut PartialWitness<GoldilocksField>,
        anchkey: &AnchoredKey,
    ) -> Result<()> {
        let Self(origin_target, key_target) = self;
        let AnchoredKey(origin, key) = anchkey;
        origin_target.set_witness(pw, origin)?;
        pw.set_target(*key_target, hash_string_to_field(key))?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct StatementTarget {
    // Statement target as a vector of length 11.
    // Such a vector is of the form
    // [predicate] ++ origin1 ++ [key1] ++ origin2 ++ [key2] ++  origin3 ++ [key3] ++ [value]
    pub predicate: Target,
    pub origin1: OriginTarget,
    pub key1: Target,
    pub origin2: OriginTarget,
    pub key2: Target,
    pub origin3: OriginTarget,
    pub key3: Target,
    pub value: Target
}

impl StatementTarget {
    pub fn new_virtual(builder: &mut CircuitBuilder<GoldilocksField, 2>) -> Self {
        Self {
            predicate: builder.add_virtual_target(),
            origin1: OriginTarget::new_virtual(builder),
            key1: builder.add_virtual_target(),
            origin2: OriginTarget::new_virtual(builder),
            key2: builder.add_virtual_target(),
            origin3: OriginTarget::new_virtual(builder),
            key3: builder.add_virtual_target(),
            value: builder.add_virtual_target()
        }
    }
    pub fn to_targets(&self) -> Vec<Target> {
        [vec![self.predicate],
         self.origin1.to_targets(),
         vec![self.key1],
         self.origin2.to_targets(),
         vec![self.key2],
         self.origin3.to_targets(),
         vec![self.key3],
         vec![self.value]
            ].concat()
    }
    pub fn from_targets(v: &[Target]) -> Self {
        Self {
            predicate: v[0],
            origin1: OriginTarget::from_targets(&[v[1], v[2]]),
            key1: v[3],
            origin2: OriginTarget::from_targets(&[v[4],v[5]]),
            key2: v[6],
            origin3: OriginTarget::from_targets(&[v[7], v[8]]),
            key3: v[9],
            value: v[10]
        }
    }
    pub fn set_witness(
        &self,
        pw: &mut PartialWitness<GoldilocksField>,
        statement: &Statement,
    ) -> Result<()> {
        pw.set_target_arr(&self.to_targets(), &statement.to_fields())
    }
}

