use anyhow::Result;
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use std::collections::HashMap;
use std::iter::zip;

use crate::{
    pod::{
        circuit::util::statement_matrix_ref, gadget::GadgetID, operation::Operation as Op,
        statement::StatementRef, Statement,
        statement::StatementOrRef
    },
    D, F, NUM_BITS,
};

use super::{
    entry::EntryTarget,
    origin::OriginTarget,
    statement::{StatementRefTarget, StatementTarget},
    util::assert_less_if,
};

#[derive(Clone, Copy, Debug)]
pub struct OperationTarget<const VL: usize> {
    pub op: Target,
    pub operand1: StatementRefTarget,
    pub operand2: StatementRefTarget,
    pub operand3: StatementRefTarget,
    pub entry: EntryTarget,
    pub contains_proof: [Target; VL]
}

impl<const VL: usize> OperationTarget<VL> {
    pub fn new_virtual(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            op: builder.add_virtual_target(),
            operand1: StatementRefTarget::new_virtual(builder),
            operand2: StatementRefTarget::new_virtual(builder),
            operand3: StatementRefTarget::new_virtual(builder),
            entry: EntryTarget::new_virtual(builder),
            contains_proof: builder.add_virtual_target_arr()
        }
    }
    // TODO: Perestroika!
    pub fn set_witness(
        &self,
        pw: &mut PartialWitness<GoldilocksField>,
        operation: &Op<StatementRef>,
        ref_index_map: &HashMap<StatementRef, (usize, usize)>,
        statement_table: &<StatementRef as StatementOrRef>::StatementTable
    ) -> Result<()> {
        let operation_as_fields = operation.to_fields::<VL>(ref_index_map, &statement_table)?;
        pw.set_target(self.op, operation_as_fields[0])?;
        pw.set_target_arr(
            &[self.operand1.pod_index, self.operand1.statement_index],
            &[operation_as_fields[1], operation_as_fields[2]],
        )?;
        pw.set_target_arr(
            &[self.operand2.pod_index, self.operand2.statement_index],
            &[operation_as_fields[3], operation_as_fields[4]],
        )?;
        pw.set_target_arr(
            &[self.operand3.pod_index, self.operand3.statement_index],
            &[operation_as_fields[5], operation_as_fields[6]],
        )?;
        pw.set_target_arr(
            &[self.entry.key, self.entry.value],
            &[operation_as_fields[7], operation_as_fields[8]],
        )?;
        pw.set_target_arr(
            &self.contains_proof,
            &operation_as_fields[9..]
        )?;
        Ok(())
    }

    pub fn operands(&self) -> Vec<StatementRefTarget> {
        vec![self.operand1, self.operand2, self.operand3]
    }

    /// Operation evaluation. It is assumed that the provided
    /// statement targets have had their origins remapped.
    pub fn eval_with_gadget_id(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        gadget_id: GadgetID,
        statement_targets: &[Vec<StatementTarget>],
    ) -> Result<StatementTarget> {
        // Select statement targets from matrix.
        let statement1_target = statement_matrix_ref(
            builder,
            statement_targets,
            self.operand1.pod_index,
            self.operand1.statement_index,
        )?;
        let statement2_target = statement_matrix_ref(
            builder,
            statement_targets,
            self.operand2.pod_index,
            self.operand2.statement_index,
        )?;
        let statement3_target = statement_matrix_ref(
            builder,
            statement_targets,
            self.operand3.pod_index,
            self.operand3.statement_index,
        )?;
        let entry_target = self.entry;

        // StatementTarget output of the ith opcode.
        let op_out = [
            StatementTarget::none(builder),                                 // None
            StatementTarget::from_entry(builder, &entry_target, gadget_id), // NewEntry
            statement1_target,                                              // Copy
            StatementTarget::equal(builder, statement1_target, statement2_target), // EqualityFromEntries
            StatementTarget::not_equal(builder, statement1_target, statement2_target), // NonequalityFromEntries
            StatementTarget::gt(builder, statement1_target, statement2_target), // GtFromEntries
            StatementTarget {
                predicate: builder.constant(Statement::EQUAL),
                origin1: statement1_target.origin1,
                key1: statement1_target.key1,
                origin2: statement2_target.origin2,
                key2: statement2_target.key2,
                origin3: OriginTarget::none(builder),
                key3: builder.zero(),
                value: builder.zero(),
            }, // TransitiveEqualityFromStatements
            StatementTarget::not_equal(builder, statement1_target, statement2_target), // GtToNonequality. TODO.
            StatementTarget::contains(builder, statement1_target, statement2_target), // TODO: ContainsFromEntries.
            StatementTarget::rename_contained_by(builder, statement1_target, statement2_target), // TODO: RenameContainedBy
            StatementTarget::sum_of(
                builder,
                statement1_target,
                statement2_target,
                statement3_target,
            ), // TODO: SumOf
            StatementTarget::product_of(
                builder,
                statement1_target,
                statement2_target,
                statement3_target,
            ), // TODO: ProductOf
            StatementTarget::max_of(
                builder,
                statement1_target,
                statement2_target,
                statement3_target,
            ), // TODO: MaxOf
        ];

        // Indicators of whether the conditions on the operands were satisfied.
        let statements_are_value_ofs = {
            let s1_check = statement1_target.has_code(builder, Statement::VALUE_OF);
            let s2_check = statement2_target.has_code(builder, Statement::VALUE_OF);
            builder.and(s1_check, s2_check)
        };

        let statements_1_and_2_equal =
            builder.is_equal(statement1_target.value, statement2_target.value);

        // Gt check. This is a constraint for now (if applicable).
        let gt_opcode_target = builder.constant(Op::<Statement>::GT_FROM_ENTRIES);
        let op_is_gt = builder.is_equal(self.op, gt_opcode_target);
        assert_less_if::<NUM_BITS>(
            builder,
            op_is_gt,
            statement2_target.value,
            statement1_target.value,
        );

        // Check whether statement 1 is (a == b) and statement 2 is (b == c)
        let statements_are_equalities = {
            let s1_check = statement1_target.has_code(builder, Statement::EQUAL);
            let s2_check = statement2_target.has_code(builder, Statement::EQUAL);
            builder.and(s1_check, s2_check)
        };
        // TODO
        let statements_allow_transitivity = {
            let origins_match = builder.is_equal(
                statement1_target.origin2.origin_id,
                statement2_target.origin1.origin_id,
            );
            let keys_match = builder.is_equal(statement1_target.key2, statement2_target.key1);
            builder.and(origins_match, keys_match)
        };

        let op_is_valid = [
            builder._true(),                       // None - no checks needed.
            builder._true(),                       // NewEntry - no checks needed.
            builder._true(),                       // Copy - no checks needed.
            statements_1_and_2_equal,              // EqualityFromEntries - equality check
            builder.not(statements_1_and_2_equal), // NonequalityFromEntries - non-equality check
            statements_are_value_ofs,              // GtFromEntries - Type-check input statements
            builder.and(statements_are_equalities, statements_allow_transitivity), // TransitiveEqualityFromStatements
            statement1_target.has_code(builder, Statement::GT), // GtToNonequality
            builder._true(),                                    // TODO: ContainsFromEntries
            builder._true(),                                    // TODO: RenameContainedBy
            builder._true(),                                    // TODO: SumOf
            builder._true(),                                    // TODO: ProductOf
            builder._true(),                                    // TODO: MaxOf
        ]
        .iter()
        .enumerate()
        .map(|(i, indicator)| {
            let index_target = builder.constant(GoldilocksField(i as u64));
            let is_index = builder.is_equal(self.op, index_target);
            builder.and(is_index, *indicator)
        })
        .collect::<Vec<_>>();

        // Select the right op.
        let (output_statement_is_valid, output_statement_target) = zip(op_is_valid, op_out).fold(
            (builder._false(), StatementTarget::none(builder)),
            |(cur_validity, cur_s), (o_valid, s)| {
                (
                    builder.or(o_valid, cur_validity),
                    // If o_valid, s, else cur_s.
                    StatementTarget::from_targets(
                        std::iter::zip(s.to_targets(), cur_s.to_targets())
                            .map(|(x, y)| builder.select(o_valid, x, y))
                            .collect::<Vec<_>>()
                            .as_ref(),
                    ),
                )
            },
        );
        builder.assert_one(output_statement_is_valid.target);
        Ok(output_statement_target)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use anyhow::Result;
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        iop::witness::PartialWitness,
        plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig},
    };

    use crate::{
        pod::{
            circuit::{pod::SchnorrPODTarget, statement::StatementTarget},
            entry::Entry,
            gadget::GadgetID,
            operation::{OpList, Operation as Op, OperationCmd as OpCmd},
            statement::StatementRef,
            GPGInput, POD,
        },
        signature::schnorr::SchnorrSecretKey,
        C,
    };
}

// pub struct OpListTarget<const NS: usize, const VL: usize>(pub [OperationTarget<VL>; NS]);

// impl<const NS: usize, const VL: usize> OpListTarget<NS, VL> {
//     pub fn new_virtual(builder: &mut CircuitBuilder<F, D>) -> Self {
//         OpListTarget(array::from_fn(|_| OperationTarget::<VL>::new_virtual(builder)))
//     }

//     pub fn set_witness(
//         &self,
//         pw: &mut PartialWitness<GoldilocksField>,
//         op_list: &OpList,
//         gpg_input: &GPGInput
//     ) -> Result<()> {
//         // TODO: Abstract this away.
//         // Determine output POD statements for the purposes of later reference
//         let output_pod = POD::execute_oracle_gadget(gpg_input, &op_list.0)?;
//         // println!("{:?}", output_pod.payload.statements_list);
//         let input_and_output_pod_list = [
//             gpg_input.pods_list.clone(),
//             vec![("_SELF".to_string(), output_pod)],
//         ]
//         .concat();

//         // Set operation targets
//         let ref_index_map = StatementRef::index_map(&input_and_output_pod_list);
//         let statement_table: <StatementRef as StatementOrRef>::StatementTable =
//             input_and_output_pod_list.iter().map(
//                 |(pod_name, pod)|
//                 (pod_name.clone(), pod.payload.statements_map.clone())
//                 ).collect();

//         zip(&self.0, op_list.sort(&input_and_output_pod_list).0).try_for_each(
//             |(op_target, OperationCmd(op, _))| op_target.set_witness(pw, &op, &ref_index_map, &statement_table),
//         )
//     }
// }
