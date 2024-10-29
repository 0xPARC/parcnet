use anyhow::Result;
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};

use crate::pod::{entry::Entry, util::hash_string_to_field, value::HashableEntryValue};
use crate::{D, F};

#[derive(Clone, Copy, Debug)]
pub struct EntryTarget {
    pub key: Target,
    pub value: Target,
}

impl EntryTarget {
    pub fn new_virtual(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            key: builder.add_virtual_target(),
            value: builder.add_virtual_target(),
        }
    }
    pub fn set_witness(
        &self,
        pw: &mut PartialWitness<GoldilocksField>,
        entry: &Entry,
    ) -> Result<()> {
        pw.set_target_arr(
            &[self.key, self.value],
            &[
                hash_string_to_field(&entry.key),
                entry.value.hash_or_value(),
            ],
        )
    }
}
