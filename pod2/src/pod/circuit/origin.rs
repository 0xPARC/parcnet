use anyhow::Result;
use plonky2::{field::{goldilocks_field::GoldilocksField, types::Field}, iop::{target::Target, witness::{PartialWitness, WitnessWrite}}, plonk::circuit_builder::CircuitBuilder};

use crate::pod::origin::Origin;

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct OriginTarget {
    pub origin_id: Target,
    pub gadget_id: Target,
}

impl OriginTarget {
    pub fn new_virtual(builder: &mut CircuitBuilder<GoldilocksField, 2>) -> Self {
        Self {
            origin_id: builder.add_virtual_target(),
            gadget_id: builder.add_virtual_target(),
        }
    }
    pub fn to_targets(&self) -> Vec<Target> {
        vec![self.origin_id, self.gadget_id]
    }
    pub fn from_targets(v: &[Target]) -> Self {
        Self { origin_id: v[0], gadget_id: v[1] }
    }
    pub fn set_witness(
        &self,
        pw: &mut PartialWitness<GoldilocksField>,
        origin: &Origin,
    ) -> Result<()> {
        pw.set_target(self.origin_id, origin.origin_id)?;
        pw.set_target(
            self.gadget_id,
            GoldilocksField::from_canonical_u64(origin.gadget_id as usize as u64),
        )?;
        Ok(())
    }
}

