use anyhow::Result;
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use std::iter::zip;

use super::{operation::OperationTarget, statement::StatementTarget};
use crate::pod::{gadget::GadgetID, GPGInput};
use crate::{D, F};

#[derive(Clone, Debug)]
pub struct GPGTarget {
    pub statements: Vec<Vec<StatementTarget>>,
    pub origin_id_map: Vec<Vec<Target>>,
}

impl GPGTarget {
    pub fn new_virtual(
        builder: &mut CircuitBuilder<F, D>,
        num_pods: usize,
        num_statements: usize,
    ) -> Self {
        Self {
            statements: (0..num_pods)
                .map(|_| {
                    (0..num_statements)
                        .map(|_| StatementTarget::new_virtual(builder))
                        .collect()
                })
                .collect(),
            origin_id_map: (0..num_pods)
                .map(|_| builder.add_virtual_targets(num_statements + 2))
                .collect(),
        }
    }
    pub fn set_witness(
        &self,
        pw: &mut PartialWitness<GoldilocksField>,
        gpg_input: GPGInput,
    ) -> Result<()> {
        zip(&self.statements, &gpg_input.pods_list).try_for_each(|(s_target_vec, (_, pod))| {
            zip(s_target_vec, &pod.payload.statements_list)
                .try_for_each(|(s_target, (_, s))| s_target.set_witness(pw, s))
        })?;
        let origin_id_map_fields = gpg_input.origin_id_map_fields()?;
        zip(&self.origin_id_map.concat(), &origin_id_map_fields.concat()).try_for_each(
            |(map_entry_target, map_entry)| pw.set_target(*map_entry_target, *map_entry),
        )
    }
    pub fn execute(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        ops: Vec<OperationTarget>,
    ) -> Result<Vec<StatementTarget>> {
        ops.iter()
            .map(|op| op.eval_with_gadget_id(builder, GadgetID::PLONKY, &self.statements))
            .collect()
    }
}
