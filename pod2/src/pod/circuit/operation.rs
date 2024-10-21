use std::collections::HashMap;

use anyhow::{anyhow, Result};
use plonky2::{
    field::{
        goldilocks_field::GoldilocksField,
        types::{Field, PrimeField64},
    },
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig},
};

use super::{pod::SchnorrPODTarget, C, D, F};

use crate::{
    pod::{
        circuit::util::vector_ref,
        entry::Entry,
        gadget::GadgetID,
        operation::{Operation as Op, OperationCmd as OpCmd},
        statement::{Statement, StatementRef},
        GPGInput, POD,
    },
    signature::schnorr::SchnorrSecretKey,
};

use super::{
    entry::EntryTarget,
    statement::{StatementRefTarget, StatementTarget},
    util::vector_slice,
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

    /// Operation evaluation. It is assumed that the provided
    /// statement targets have had their origins remapped.
    pub fn eval_with_gadget_id(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        gadget_id: GadgetID,
        statement_targets: &[Vec<StatementTarget>],
    ) -> Result<StatementTarget> {
        let one_target = builder.constant(GoldilocksField(1));
        let statement_len_target = builder.constant(StatementTarget::len());
        // Get operands by flattening out `statement_targets`.
        // TODO: Factor out.
        let num_statements = GoldilocksField(
            statement_targets
                .first()
                .ok_or(anyhow!("No statement targets provided!"))?
                .len() as u64,
        );
        let flattened_statement_targets = statement_targets
            .iter()
            .flat_map(|s_vec| s_vec.iter().flat_map(|s| s.to_targets()))
            .collect::<Vec<_>>();
        // Statement N is the slice of length 11 starting at
        // pod_index*num_statements*11 + statement_index*11.
        let statement1_target = {
            let i = builder.arithmetic(
                num_statements,
                StatementTarget::len(),
                self.operand1.pod_index,
                statement_len_target,
                self.operand1.statement_index,
            );
            vector_slice(
                builder,
                &flattened_statement_targets[..64],
                i,
                StatementTarget::len().to_canonical_u64() as usize,
            )
            .map(|v| StatementTarget::from_targets(&v))
        }?;
        let statement2_target = {
            let i = builder.arithmetic(
                num_statements,
                StatementTarget::len(),
                self.operand2.pod_index,
                statement_len_target,
                self.operand2.statement_index,
            );
            vector_slice(
                builder,
                &flattened_statement_targets,
                i,
                StatementTarget::len().to_canonical_u64() as usize,
            )
            .map(|v| StatementTarget::from_targets(&v))
        }?;
        let _statement3_target = {
            let i = builder.arithmetic(
                num_statements,
                StatementTarget::len(),
                self.operand3.pod_index,
                statement_len_target,
                self.operand3.statement_index,
            );
            vector_slice(
                builder,
                &flattened_statement_targets,
                i,
                StatementTarget::len().to_canonical_u64() as usize,
            )
            .map(|v| StatementTarget::from_targets(&v))
        }?;
        let entry_target = self.entry;

        // StatementTarget outputs of each of these ops.
        let op_out = [
            StatementTarget::none(builder),
            StatementTarget::from_entry(builder, &entry_target, gadget_id),
            statement1_target, // Copy
            StatementTarget::equal(builder, statement1_target, statement2_target),
            StatementTarget::not_equal(builder, statement1_target, statement2_target),
            // TODO: Rest!
        ];

        // Indicators of whether the conditions on the operands were satisfied.
        let statements_1_and_2_equal =
            builder.is_equal(statement1_target.value, statement2_target.value);
        let op_is_valid = [
            builder._true(),
            builder._true(),
            builder._true(),
            statements_1_and_2_equal, // equality check
            builder.not(statements_1_and_2_equal), // non-equality check
                                      // TODO: Rest!
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
        let (output_statement_is_valid, output_statement_target) =
            std::iter::zip(op_is_valid, op_out).fold(
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

#[test]
fn op_test() -> Result<()> {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let mut pw: PartialWitness<F> = PartialWitness::new();

    // Input Schnorr PODs. For now, they must all have the same number
    // of statements.
    let num_statements = 3;
    let schnorr_pod1_name = "Test POD 1".to_string();
    let schnorr_pod1 = POD::execute_schnorr_gadget(
        &[
            Entry::new_from_scalar("s1", GoldilocksField(55)),
            Entry::new_from_scalar("s2", GoldilocksField(56)),
        ],
        &SchnorrSecretKey { sk: 27 },
    );
    let schnorr_pod2_name = "Test POD 2".to_string();
    let schnorr_pod2 = POD::execute_schnorr_gadget(
        &[
            Entry::new_from_scalar("s3", GoldilocksField(57)),
            Entry::new_from_scalar("s4", GoldilocksField(55)),
        ],
        &SchnorrSecretKey { sk: 29 },
    );

    // Ops
    let op_cmds = [
        // EQUAL:op2
        OpCmd(
            Op::EqualityFromEntries(
                StatementRef(&schnorr_pod1_name, "VALUEOF:s1"),
                StatementRef(&schnorr_pod2_name, "VALUEOF:s4"),
            ),
            "op2",
        ),
        // NONE:pop
        OpCmd(Op::None, "pop"),
        // NOTEQUAL:yolo
        OpCmd(
            Op::NonequalityFromEntries(
                StatementRef(&schnorr_pod1_name, "VALUEOF:s1"),
                StatementRef(&schnorr_pod1_name, "VALUEOF:s2"),
            ),
            "yolo",
        ),
        // VALUEOF:nono
        OpCmd(
            Op::NewEntry(Entry::new_from_scalar("what", GoldilocksField(23))),
            "nono",
        ),
        // VALUEOF:op3
        OpCmd(
            Op::CopyStatement(StatementRef(&schnorr_pod1_name, "VALUEOF:s2")),
            "op3",
        ),
    ];

    let pods_list = [
        (schnorr_pod1_name.clone(), schnorr_pod1),
        (schnorr_pod2_name.clone(), schnorr_pod2),
    ];
    let ref_index_map = StatementRef::index_map(&pods_list);

    let gpg_input = GPGInput::new(HashMap::from(pods_list.clone()), HashMap::new());

    let oracle_pod = POD::execute_oracle_gadget(&gpg_input, &op_cmds)?;
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
            let pod_target = SchnorrPODTarget::new_virtual(&mut builder, num_statements);
            let pod_index_target = builder.constant(GoldilocksField(pod_index as u64));
            pod_target.set_witness(&mut pw, pod)?;
            pod_target
                .payload
                .iter()
                .map(|s| s.remap_origins(&mut builder, &origin_id_map_target, pod_index_target))
                .collect()
        })
        .collect::<Result<Vec<Vec<_>>>>()?;

    op_cmds
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
    let _proof = data.prove(pw)?;

    Ok(())
}
