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
pub struct OperationTarget {
    pub op: Target,
    pub operand1: StatementRefTarget,
    pub operand2: StatementRefTarget,
    pub operand3: StatementRefTarget,
    pub entry: EntryTarget,
}

impl OperationTarget {
    pub fn new_virtual(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            op: builder.add_virtual_target(),
            operand1: StatementRefTarget::new_virtual(builder),
            operand2: StatementRefTarget::new_virtual(builder),
            operand3: StatementRefTarget::new_virtual(builder),
            entry: EntryTarget::new_virtual(builder),
        }
    }
    // TODO: Perestroika!
    pub fn set_witness(
        &self,
        pw: &mut PartialWitness<GoldilocksField>,
        operation: &Op<StatementRef>,
        ref_index_map: &HashMap<StatementRef, (usize, usize)>,
    ) -> Result<()> {
        let operation_as_fields = operation.to_fields(ref_index_map)?;
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

    use super::OperationTarget;
    use crate::{D, F};

    #[test]
    fn op_test() -> Result<()> {
        // Input Schnorr PODs. For now, they must all have the same number
        // of statements.
        const NS: usize = 3;
        let schnorr_pod1_name = "Test POD 1".to_string();
        let schnorr_pod1 = POD::execute_schnorr_gadget::<NS>(
            &[
                Entry::new_from_scalar("s1", GoldilocksField(55)),
                Entry::new_from_scalar("s2", GoldilocksField(56)),
            ],
            &SchnorrSecretKey { sk: 27 },
        )?;
        let schnorr_pod2_name = "Test POD 2".to_string();
        let schnorr_pod2 = POD::execute_schnorr_gadget::<NS>(
            &[
                Entry::new_from_scalar("s3", GoldilocksField(57)),
                Entry::new_from_scalar("s4", GoldilocksField(55)),
            ],
            &SchnorrSecretKey { sk: 29 },
        )?;

        let schnorr_pod3_name = "Test POD 3".to_string();
        let schnorr_pod3 = POD::execute_schnorr_gadget::<NS>(
            &[
                Entry::new_from_scalar("s0", GoldilocksField(57)),
                Entry::new_from_scalar("s-1", GoldilocksField(55)),
            ],
            &SchnorrSecretKey { sk: 24 },
        )?;

        let schnorr_pod4_name = "Test POD 4".to_string();
        let schnorr_pod4 = POD::execute_schnorr_gadget::<NS>(
            &[
                Entry::new_from_scalar("who", GoldilocksField(7)),
                Entry::new_from_scalar("what", GoldilocksField(5)),
            ],
            &SchnorrSecretKey { sk: 20 },
        )?;

        let pods_list = [
            (schnorr_pod1_name.clone(), schnorr_pod1),
            (schnorr_pod2_name.clone(), schnorr_pod2),
            (schnorr_pod3_name.clone(), schnorr_pod3),
            (schnorr_pod4_name.clone(), schnorr_pod4),
        ];

        // Ops
        let op_lists = [
            OpList(vec![
                // NONE:pop
                OpCmd::new(Op::None, "pop"),
                // VALUEOF:op3
                OpCmd::new(
                    Op::CopyStatement(StatementRef::new(&schnorr_pod1_name, "VALUEOF:s2")),
                    "op3",
                ),
                // NOTEQUAL:yolo
                OpCmd::new(
                    Op::NonequalityFromEntries(
                        StatementRef::new(&schnorr_pod1_name, "VALUEOF:s1"),
                        StatementRef::new(&schnorr_pod1_name, "VALUEOF:s2"),
                    ),
                    "yolo",
                ),
            ]),
            OpList(vec![
                // VALUEOF:nono
                OpCmd::new(
                    Op::NewEntry(Entry::new_from_scalar("what", GoldilocksField(23))),
                    "nono",
                ),
                // EQUAL:op2
                OpCmd::new(
                    Op::EqualityFromEntries(
                        StatementRef::new(&schnorr_pod1_name, "VALUEOF:s1"),
                        StatementRef::new(&schnorr_pod2_name, "VALUEOF:s4"),
                    ),
                    "op2",
                ),
                OpCmd::new(Op::None, "bop"),
            ]),
        ]
        .into_iter()
        .map(|op_list| op_list.sort(&pods_list))
        .collect::<Vec<_>>();

        let ref_index_map = StatementRef::index_map(&pods_list);

        let gpg_input = GPGInput::new(HashMap::from(pods_list.clone()), HashMap::new());

        op_lists.into_iter().try_for_each(|op_list| {
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);
            let mut pw: PartialWitness<F> = PartialWitness::new();

            let oracle_pod = POD::execute_oracle_gadget(&gpg_input, &op_list.0)?;
            let out_statements = oracle_pod
                .payload
                .statements_list
                .iter()
                .map(|(_, s)| s.clone())
                .collect::<Vec<_>>();

            // Apply ops in ZK, making sure to remap statement origins.
            let origin_id_map = gpg_input.origin_id_map_fields()?;
            let origin_id_map_target = origin_id_map
                .iter()
                .map(|row| row.iter().map(|i| builder.constant(*i)).collect::<Vec<_>>())
                .collect::<Vec<_>>();
            let statement_targets = pods_list
                .iter()
                .enumerate()
                .map(|(pod_index, (_, pod))| {
                    // QUESTION: this is creating a new target, but does not call
                    // `compute_targets_and_verify`
                    let pod_target = SchnorrPODTarget::new_virtual(&mut builder, NS);
                    let pod_index_target = builder.constant(GoldilocksField(pod_index as u64));
                    pod_target.set_witness(&mut pw, pod)?;
                    pod_target
                        .payload
                        .iter()
                        .map(|s| {
                            s.remap_origins(&mut builder, &origin_id_map_target, pod_index_target)
                        })
                        .collect()
                })
                .collect::<Result<Vec<Vec<_>>>>()?;

            op_list
                .0
                .iter()
                .enumerate()
                .try_for_each(|(i, OpCmd(op, _))| {
                    let op_target = OperationTarget::new_virtual(&mut builder);
                    op_target.set_witness(&mut pw, op, &ref_index_map)?;
                    let out_statement_target = op_target.eval_with_gadget_id(
                        &mut builder,
                        GadgetID::ORACLE,
                        &statement_targets,
                    )?;
                    let expected_out_statement =
                        StatementTarget::constant(&mut builder, &out_statements[i]);
                    // Check that we get the expected output.
                    out_statement_target.connect(&mut builder, &expected_out_statement);
                    anyhow::Ok(())
                })?;
            let data = builder.build::<C>();
            let proof = data.prove(pw)?;
            data.verify(proof.clone())
        })
    }
}
