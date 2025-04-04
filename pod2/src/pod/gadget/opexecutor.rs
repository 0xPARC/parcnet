use anyhow::Result;
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::hash_types::{HashOut, HashOutTarget},
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
        circuit::operation::OpListTarget, gadget::GadgetID, operation::OpList,
        payload::StatementList, ContentID, GPGInput,
    },
    recursion::OpsExecutorTrait,
    D, F,
};

use crate::pod::circuit::statement::StatementTarget;

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
        // Content IDs. TODO.
        [HashOutTarget; NP],
        [[StatementTarget; NS]; NP],
        OpListTarget<NS, VL>,
        [StatementTarget; NS], // registered as public input
    );

    fn add_targets(builder: &mut CircuitBuilder<F, D>) -> Result<Self::Targets> {
        let content_id_list_target: [HashOutTarget; NP] =
            array::from_fn(|_| builder.add_virtual_hash());
        let statement_list_vec_target: [[StatementTarget; NS]; NP] = array::from_fn(|_| {
            array::from_fn::<StatementTarget, NS, _>(|_| StatementTarget::new_virtual(builder))
        });
        let origin_id_map_target: [Vec<Target>; NP] =
            array::from_fn(|_| builder.add_virtual_targets(NS + 2));

        let op_list_target = OpListTarget::new_virtual(builder);

        // To apply ops, remap statements' origin IDs.
        let remapped_statement_list_vec_target = statement_list_vec_target
            .iter()
            .enumerate()
            .map(|(pod_index, s_vec)| {
                s_vec
                    .iter()
                    .map(|s| {
                        let content_id_target = content_id_list_target[pod_index];
                        s.remap_origins(builder, content_id_target)
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
                op_list_target.0[i].eval_with_gadget_id(
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
            content_id_list_target,
            statement_list_vec_target,
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
        targets
            .0
            .iter()
            .enumerate()
            .try_for_each(|(i, hash_targ)| {
                pw.set_hash_target(*hash_targ, input.0.pods_list[i].1.content_id().into())
            })?;
        // TODO: Connect these to the POD targets that go into the inner and recursion circuits instead!
        zip(&targets.1, &input.0.pods_list).try_for_each(|(s_targets, (_, pod))| {
            let pod_statements = &pod.payload.statements_list;
            zip(s_targets, pod_statements)
                .try_for_each(|(s_target, (_, s))| s_target.set_witness(pw, s))
        })?;

        // Set op list target.
        let op_list_target = &targets.2;
        op_list_target.set_witness(pw, &input.1, &input.0)?;

        // Check output statement list target
        zip(&targets.3, output).try_for_each(|(s_target, (_, s))| s_target.set_witness(pw, s))?;

        // return a Vec<F> containing the public inputs. This must match the order of the
        // registered public inputs at the `add_targets` method.
        Ok(output.iter().flat_map(|v| v.1.to_fields()).collect())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use anyhow::{anyhow, Result};
    use itertools::Itertools;
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
        const VL: usize = 3;

        let schnorr_pod1_name = "Test POD 1".to_string();
        let schnorr_pod1 = POD::execute_schnorr_gadget::<NS, VL>(
            &[
                Entry::new_from_scalar("s1", GoldilocksField(55)),
                Entry::new_from_scalar("s2", GoldilocksField(56)),
            ],
            &SchnorrSecretKey { sk: 27 },
        )?;
        let schnorr_pod2_name = "Test POD 2".to_string();
        let schnorr_pod2 = POD::execute_schnorr_gadget::<NS, VL>(
            &[
                Entry::new_from_scalar("s3", GoldilocksField(57)),
                Entry::new_from_scalar("s4", GoldilocksField(55)),
            ],
            &SchnorrSecretKey { sk: 29 },
        )?;

        let schnorr_pod3_name = "Test POD 3".to_string();
        let schnorr_pod3 = POD::execute_schnorr_gadget::<NS, VL>(
            &[
                Entry::new_from_scalar("s0", GoldilocksField(57)),
                Entry::new_from_scalar("s-1", GoldilocksField(55)),
            ],
            &SchnorrSecretKey { sk: 24 },
        )?;

        let schnorr_pod4_name = "Test POD 4".to_string();
        let schnorr_pod4 = POD::execute_schnorr_gadget::<NS, VL>(
            &[
                Entry::new_from_vec(
                    "who",
                    vec![GoldilocksField(5), GoldilocksField(6), GoldilocksField(7)],
                ),
                Entry::new_from_scalar("what", GoldilocksField(5)),
            ],
            &SchnorrSecretKey { sk: 20 },
        )?;

        let schnorr_pod5_name = "Test POD 5".to_string();
        let schnorr_pod5 = POD::execute_schnorr_gadget::<NS, VL>(
            &[
                Entry::new_from_scalar("who", GoldilocksField(111)),
                Entry::new_from_scalar("what", GoldilocksField(55 * 57)),
            ],
            &SchnorrSecretKey { sk: 20 },
        )?;

        let schnorr_pod6_name = "Test POD 6".to_string();
        let schnorr_pod6 = POD::execute_schnorr_gadget::<NS, VL>(
            &[
                Entry::new_from_vec(
                    "whence",
                    vec![GoldilocksField(5), GoldilocksField(6), GoldilocksField(7)],
                ),
                Entry::new_from_scalar("why", GoldilocksField(0)),
            ],
            &SchnorrSecretKey { sk: 20 },
        )?;

        let oracle_pod_name = "Oracle POD".to_string();
        let oracle_pod = POD::execute_oracle_gadget(
            &GPGInput::new(
                [
                    (schnorr_pod4_name.clone(), schnorr_pod4.clone()),
                    (schnorr_pod6_name.clone(), schnorr_pod6.clone()),
                ]
                .into_iter()
                .collect(),
                HashMap::new(),
            ),
            &OpList(vec![
                OpCmd::new(
                    Op::ContainsFromEntries(
                        StatementRef::new(&schnorr_pod4_name, "VALUEOF:who"),
                        StatementRef::new(&schnorr_pod4_name, "VALUEOF:what"),
                    ),
                    "car",
                ),
                OpCmd::new(
                    Op::EqualityFromEntries(
                        StatementRef::new(&schnorr_pod4_name, "VALUEOF:who"),
                        StatementRef::new(&schnorr_pod6_name, "VALUEOF:whence"),
                    ),
                    "yes",
                ),
            ])
            .pad::<NS>()?
            .0,
        )?;

        let pods_list = [
            (schnorr_pod1_name.clone(), schnorr_pod1),
            (schnorr_pod2_name.clone(), schnorr_pod2),
            (schnorr_pod3_name.clone(), schnorr_pod3),
            (schnorr_pod4_name.clone(), schnorr_pod4),
            (schnorr_pod5_name.clone(), schnorr_pod5),
            (schnorr_pod6_name.clone(), schnorr_pod6),
            (oracle_pod_name.clone(), oracle_pod),
        ];

        const NP: usize = 7;
        if pods_list.len() != NP {
            return Err(anyhow!(
                "Number of PODs in list must be equal to NP ({})!",
                NP
            ));
        };

        // Ops
        let ops = [
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
            OpCmd::new(Op::None, "cons"),
            OpCmd::new(
                Op::ContainsFromEntries(
                    StatementRef::new(&schnorr_pod4_name, "VALUEOF:who"),
                    StatementRef::new(&schnorr_pod4_name, "VALUEOF:what"),
                ),
                "car",
            ),
            OpCmd::new(Op::None, "cdr"),
            OpCmd::new(
                Op::SumOf(
                    StatementRef::new(&schnorr_pod5_name, "VALUEOF:who"),
                    StatementRef::new(&schnorr_pod1_name, "VALUEOF:s2"),
                    StatementRef::new(&schnorr_pod2_name, "VALUEOF:s4"),
                ),
                "cadr",
            ),
            OpCmd::new(
                Op::ProductOf(
                    StatementRef::new(&schnorr_pod5_name, "VALUEOF:what"),
                    StatementRef::new(&schnorr_pod1_name, "VALUEOF:s1"),
                    StatementRef::new(&schnorr_pod2_name, "VALUEOF:s3"),
                ),
                "caar",
            ),
            OpCmd::new(
                Op::MaxOf(
                    StatementRef::new(&schnorr_pod2_name, "VALUEOF:s3"),
                    StatementRef::new(&schnorr_pod1_name, "VALUEOF:s1"),
                    StatementRef::new(&schnorr_pod2_name, "VALUEOF:s3"),
                ),
                "cdar",
            ),
            OpCmd::new(
                Op::RenameContainedBy(
                    StatementRef::new(&oracle_pod_name, "CONTAINS:car"),
                    StatementRef::new(&oracle_pod_name, "EQUAL:yes"),
                ),
                "cadadr",
            ),
        ];
        let op_lists = ops
            .iter()
            .chunks(3)
            .into_iter()
            .map(|chunk| {
                OpList(chunk.cloned().collect::<Vec<_>>())
                    .pad::<NS>()
                    .map(|o| o.sort(&pods_list))
            })
            .collect::<Result<Vec<_>>>()?;

        let gpg_input = GPGInput::new(
            HashMap::from(pods_list.clone()),
            [
                (
                    (oracle_pod_name.clone(), schnorr_pod4_name.clone()),
                    "parent".to_string(),
                ),
                (
                    (oracle_pod_name.clone(), schnorr_pod6_name.clone()),
                    "parent2".to_string(),
                ),
            ]
            .into_iter()
            .collect(),
        );

        op_lists.into_iter().try_for_each(|op_list| {
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);
            let mut pw: PartialWitness<F> = PartialWitness::new();
            let oracle_pod = POD::execute_oracle_gadget(&gpg_input, &op_list.0)?;

            // circuit test
            let targets = OpExecutorGadget::<NP, NS, VL>::add_targets(&mut builder)?;
            OpExecutorGadget::<NP, NS, VL>::set_targets(
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
