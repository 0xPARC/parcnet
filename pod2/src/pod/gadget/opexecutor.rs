use anyhow::Result;
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use std::array;
use std::iter::zip;

use crate::{
    pod::{
        gadget::GadgetID,
        operation::{OpList, OperationCmd},
        payload::StatementList,
        statement::StatementRef,
        GPGInput, POD,
    },
    recursion::OpsExecutorTrait,
    D, F,
};

use crate::pod::circuit::{operation::OperationTarget, statement::StatementTarget};

/// OpExecutorGadget implements the OpsExecutorTrait
/// - NP: NumPODs (NP = M+N)
/// - NS: Num Statements
/// - VL: Vector Length
/// Notice that `output_statement_list_target` is registered as public input.
pub struct OpExecutorGadget<const NP: usize, const NS: usize, const VL: usize>;

impl<const NP: usize, const NS: usize, const VL: usize> OpsExecutorTrait
    for OpExecutorGadget<NP, NS, VL>
{
    /// Input consists of:
    /// - GPG input (pod list + origin renaming map), and
    /// - a list of operations.
    type Input = (GPGInput, OpList);

    /// Output consists of the output statement list of the list of operations.
    /// Note that this should contain `NS` elements!
    ///
    /// TODO: Switch from vecs to arrays? Yes! In general for all the vectors that depend on the
    /// M, N, and M+N values, I would put them as fixed-length arrays instead of Vec, because in
    /// this way we enforce the dev to pass the correct.
    type Output = StatementList;

    /// Targets consist of input targets corresponding to all of the
    /// above, viz.
    /// (statement_list_vec_target, origin_id_map_target, op_list_target, output_statement_list_target).
    ///
    /// TODO: `statement_list_vec_target` should be `connected`
    /// (i.e. `builder.connect`ed) to the statements passed in to the
    /// inner and recursion circuits.
    type Targets = (
        [[StatementTarget; NS]; NP],
        [Vec<Target>; NP],
        [OperationTarget; NS],
        [StatementTarget; NS], // registered as public input
    );

    fn add_targets(builder: &mut CircuitBuilder<F, D>) -> Result<Self::Targets> {
        let statement_list_vec_target: [[StatementTarget; NS]; NP] = array::from_fn(|_| {
            array::from_fn::<StatementTarget, NS, _>(|_| StatementTarget::new_virtual(builder))
        });
        let origin_id_map_target: [Vec<Target>; NP] =
            array::from_fn(|_| builder.add_virtual_targets(NS + 2));

        let op_list_target: [OperationTarget; NS] =
            array::from_fn(|_| OperationTarget::new_virtual(builder));

        // TODO: Check that origin ID map has appropriate properties.

        // To apply ops, remap statements' origin IDs.
        let remapped_statement_list_vec_target = statement_list_vec_target
            .iter()
            .enumerate()
            .map(|(pod_index, s_vec)| {
                s_vec
                    .iter()
                    .map(|s| {
                        let pod_index_target = builder.constant(GoldilocksField(pod_index as u64));
                        s.remap_origins(builder, &origin_id_map_target, pod_index_target)
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .collect::<Result<Vec<_>>>()?;

        // Apply ops.
        // Create output statement list target.
        let output_statement_list_target: [StatementTarget; NS] =
            array::from_fn(|_| StatementTarget::new_virtual(builder));

        // register `output_statement_list_target` as public inputs
        for statement_target in output_statement_list_target {
            statement_target.register_as_public_input(builder);
        }

        // Combine inputs and outputs.
        let input_and_output_statement_list_vec_target = [
            remapped_statement_list_vec_target,
            vec![output_statement_list_target.to_vec()],
        ]
        .concat();
        // Compute output statement list
        let computed_output_statement_list_target: [StatementTarget; NS] =
            array::try_from_fn(|i| {
                // TODO: Make sure current op does not reference itself or an
                // as-yet unevaluated op.
                op_list_target[i].eval_with_gadget_id(
                    builder,
                    GadgetID::ORACLE,
                    &input_and_output_statement_list_vec_target,
                )
            })?;

        // Connect targets
        zip(
            output_statement_list_target,
            computed_output_statement_list_target,
        )
        .for_each(|(a, b)| a.connect(builder, &b));

        Ok((
            statement_list_vec_target,
            origin_id_map_target,
            op_list_target,
            output_statement_list_target,
        ))
    }

    fn set_targets(
        pw: &mut PartialWitness<F>,
        targets: &Self::Targets,
        input: &Self::Input,
        output: &Self::Output,
    ) -> Result<Vec<F>> {
        // Set POD targets.
        // TODO: Connect these to the POD targets that go into the inner and recursion circuits instead!
        zip(&targets.0, &input.0.pods_list).try_for_each(|(s_targets, (_, pod))| {
            let pod_statements = &pod.payload.statements_list;
            zip(s_targets, pod_statements)
                .try_for_each(|(s_target, (_, s))| s_target.set_witness(pw, &s))
        })?;

        // Set origin remapping targets.
        zip(&targets.1, input.0.origin_id_map_fields()?).try_for_each(|(target_row, row)| {
            zip(target_row, row).try_for_each(|(target, value)| pw.set_target(*target, value))
        })?;

        // TODO: Abstract this away.
        // Determine output POD statements for the purposes of later reference
        let output_pod = POD::execute_oracle_gadget(&input.0, &input.1 .0)?;
        // println!("{:?}", output_pod.payload.statements_list);
        let input_and_output_pod_list = [
            input.0.pods_list.clone(),
            vec![("_SELF".to_string(), output_pod)],
        ]
        .concat();

        // Set operation targets
        let ref_index_map = StatementRef::index_map(&input_and_output_pod_list);
        zip(&targets.2, input.1.sort(&input_and_output_pod_list).0).try_for_each(
            |(op_target, OperationCmd(op, _))| op_target.set_witness(pw, &op, &ref_index_map),
        )?;

        // Check output statement list target
        zip(&targets.3, output).try_for_each(|(s_target, (_, s))| s_target.set_witness(pw, s))?;

        // return a Vec<F> containing the public inputs. This must match the order of the
        // registered public inputs at the `add_targets` method.
        Ok(output.into_iter().flat_map(|v| v.1.to_fields()).collect())
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
            entry::Entry,
            operation::{OpList, Operation as Op, OperationCmd as OpCmd},
            statement::StatementRef,
            GPGInput, POD,
        },
        recursion::OpsExecutorTrait,
        signature::schnorr::SchnorrSecretKey,
        C,
    };

    use super::{OpExecutorGadget, D, F};
    #[test]
    fn test_op_executor_gadget() -> Result<()> {
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
                // TODO: Fails with s4 in place of s3
                OpCmd::new(
                    Op::GtFromEntries(
                        StatementRef::new(&schnorr_pod2_name, "VALUEOF:s3"),
                        StatementRef::new(&schnorr_pod1_name, "VALUEOF:s1"),
                    ),
                    "bop",
                ),
            ]),
            OpList(vec![
                OpCmd::new(Op::None, "cons"),
                OpCmd::new(Op::None, "car"),
                OpCmd::new(Op::None, "cdr"),
            ]),
        ]
        .into_iter()
        .map(|op_list| op_list.sort(&pods_list))
        .collect::<Vec<_>>();

        let gpg_input = GPGInput::new(HashMap::from(pods_list.clone()), HashMap::new());

        op_lists.into_iter().try_for_each(|op_list| {
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);
            let mut pw: PartialWitness<F> = PartialWitness::new();
            let oracle_pod = POD::execute_oracle_gadget(&gpg_input, &op_list.0)?;

            // circuit test
            let targets = OpExecutorGadget::<4, 3, 0>::add_targets(&mut builder)?;
            OpExecutorGadget::<4, 3, 0>::set_targets(
                &mut pw,
                &targets,
                &(gpg_input.clone(), op_list),
                &oracle_pod.payload.statements_list,
            )?;

            let data = builder.build::<C>();
            let proof = data.prove(pw)?;
            data.verify(proof.clone())
        })
    }
}
