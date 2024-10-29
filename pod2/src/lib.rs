#![feature(array_try_from_fn)]
#![feature(generic_const_exprs)]
#![allow(clippy::new_without_default)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]

use anyhow::{anyhow, Result};
use hashbrown::HashMap;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CircuitData, VerifierCircuitData, VerifierCircuitTarget,
};
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::plonk::proof::Proof;
use plonky2::recursion::dummy_circuit::cyclic_base_proof;
use std::array;
use std::marker::PhantomData;

use pod::circuit::pod::SchnorrPODGadget;
use pod::entry::Entry;
use pod::gadget::GadgetID;
use pod::operation::OpList;
use pod::payload::{PODPayload, StatementList};
use pod::statement::Statement;
use pod::PODProof;
use pod::{GPGInput, POD};
use signature::schnorr::SchnorrSecretKey;

pub type F = GoldilocksField;
pub type C = PoseidonGoldilocksConfig;
pub const D: usize = 2;
pub type PlonkyProof = Proof<F, PoseidonGoldilocksConfig, D>;

pub mod pod;
pub mod recursion;
pub mod signature;

// expose the main structs & traits at the high level
pub use pod::circuit::operation::{OpExecutorGadget, OperationTarget};
pub use recursion::{RecursionCircuit, RecursionTree};

// const num_statements: usize = 10;
// const num_schnorr_pods: usize = 2;
// const num_plonky_pods: usize = 2;

// TODO
/// PlonkyPOD constructor taking a list of named input PODs (which
/// could be either Schnorr or Plonky PODs) as well as operations to
/// be carried out on them as inputs.
pub struct PlonkyButNotPlonkyGadget<'a, const M: usize, const N: usize, const NS: usize>(
    PhantomData<&'a ()>,
)
where
    [(); M + N]:;

impl<'a, const M: usize, const N: usize, const NS: usize> PlonkyButNotPlonkyGadget<'a, M, N, NS>
where
    [(); M + N]:,
{
    pub fn execute(input_pods: &[(String, POD)], op_list: OpList) -> Result<POD> {
        // Check that the input data is valid, i.e. that we have at most M
        // SchnorrPODs and N PlonkyPODs in our list, *and each POD
        // contains exactly `NS` statements*.
        let mut schnorr_pods: Vec<(String, POD)> = input_pods
            .to_vec()
            .into_iter()
            .filter(|(_, pod)| pod.proof_type == GadgetID::SCHNORR16)
            .collect::<Vec<_>>();
        let schnorr_count = schnorr_pods.len();

        let mut plonky_pods: Vec<(String, POD)> = input_pods
            .to_vec()
            .into_iter()
            .filter(|(_, pod)| pod.proof_type == GadgetID::PLONKY)
            .collect::<Vec<_>>();
        let plonky_count = plonky_pods.len();

        if schnorr_count > M {
            return Err(anyhow!(
                "Number of SchnorrPODs ({}) exceeds allowed maximum ({}).",
                schnorr_count,
                M
            ));
        }
        if plonky_count > N {
            return Err(anyhow!(
                "Number of PlonkyPODs ({}) exceeds allowed maximum ({}).",
                plonky_count,
                N
            ));
        }

        let statement_check = input_pods
            .iter()
            .all(|(_, pod)| pod.payload.statements_list.len() == NS);
        if !statement_check {
            return Err(anyhow!(
                "All input PODs must contain exactly {} statements.",
                NS
            ));
        }

        // Sort POD lists.
        schnorr_pods.sort_by(|a, b| a.0.cmp(&b.0));
        plonky_pods.sort_by(|a, b| a.0.cmp(&b.0));

        // generate circuit data
        // TODO the circuit_data & verifier_data will be moved outside so it can be reused instead of
        // recomputed each time
        let circuit_data = RecursionCircuit::<
            SchnorrPODGadget<NS>,
            // TODO: ideally the user does not have to set the
            // `NP={M+N}` param, and it can get 'deducted' from
            // the M,N params of the RecursionCircuit
            OpExecutorGadget<'a, { M + N }, NS>, // NP=M+N
            M,
            N,
        >::circuit_data()?;
        let verifier_data = circuit_data.verifier_data();
        let dummy_proof = RecursionCircuit::<
            SchnorrPODGadget<NS>,
            OpExecutorGadget<'a, { M + N }, NS>,
            M,
            N,
        >::dummy_proof(circuit_data);

        // TODO: Constructor
        let dummy_plonky_pod = POD {
            payload: PODPayload {
                statements_list: (0..NS)
                    .map(|i| (format!("Dummy statement {}", i), Statement::None))
                    .collect(),
                statements_map: std::collections::HashMap::new(),
            },
            proof: pod::PODProof::Plonky(dummy_proof.clone()),
            proof_type: GadgetID::PLONKY,
        };

        let dummy_schnorr_pod = POD::execute_schnorr_gadget(
            &(0..NS)
                .map(|i| Entry::new_from_scalar(&format!("Dummy entry {}", i), GoldilocksField(0)))
                .collect::<Vec<_>>(),
            &SchnorrSecretKey { sk: 0 },
        );

        // Arrange input PODs as a list of M SchnorrPODs followed by N
        // PlonkyPODs. Pad with appropriate dummy data.
        let schnorr_pods_padded: [(String, POD); M] = array::from_fn(|i| {
            if i < schnorr_count {
                schnorr_pods[i].clone()
            } else {
                (format!("_DUMMYSCHNORR{}", i), dummy_schnorr_pod.clone())
            }
        });
        let plonky_pods_padded: [(String, POD); N] = array::from_fn(|i| {
            if i < plonky_count {
                plonky_pods[i].clone()
            } else {
                (format!("_DUMMYPLONKY{}", i), dummy_plonky_pod.clone())
            }
        });
        let mut padded_pod_list: [(String, POD); M + N] = array::from_fn(|i| {
            if i < M {
                schnorr_pods_padded[i].clone()
            } else {
                plonky_pods_padded[i - M].clone()
            }
        });

        // Prepare selectors. Set them enabled for the given schnorr & plonky pods, and disabled for
        // the padding ones
        let selectors: [F; M + N] = array::from_fn(|i| {
            if i < M {
                GoldilocksField(if i < schnorr_count { 1 } else { 0 })
            } else {
                GoldilocksField(if i < M + plonky_count { 1 } else { 0 })
            }
        });

        // Compute result of operations.
        let gpg_input = {
            let sorted_gpg_input = GPGInput::new(
                padded_pod_list.clone().into_iter().collect(),
                std::collections::HashMap::new(),
            );
            GPGInput {
                // TODO NOTE: this feels redundant usage of `GPGInput`, first we call
                // GPGInput::new and then we manually construct it
                pods_list: padded_pod_list.to_vec(),
                origin_renaming_map: sorted_gpg_input.origin_renaming_map,
            }
        };

        // Output Plonky POD should have this as its statement_list in its payload.
        let output_statements: StatementList = POD::execute_oracle_gadget(&gpg_input, &op_list.0)?
            .payload
            .statements_list;

        // Verify SchnorrPODs in circuit by routing the first `M` elements of `padded_pod_list`
        // (ignoring the string part of the tuple) and the first `M` elements of `selectors` into the
        // InnerCircuit.

        // Verify PlonkyPODs in circuit by routing the last `N` elements of `padded_pod_list` (ignoring
        // the string part of the tuple) and the last `N` elements of `selectors` into the Plonky2
        // proof verification circuit.

        // prepare inputs for the circuit
        let inner_circuit_input: [POD; M] = array::from_fn(|i| schnorr_pods_padded[i].1.clone());
        let recursive_proofs: [PlonkyProof; N] = array::from_fn(|i| {
            // convert the PODProof.proof into an actual PlonkyProof:
            let proof = match plonky_pods_padded[i].1.proof.clone() {
                PODProof::Plonky(p) => p,
                _ => panic!("Expected PODProof's Plonky variant"),
            };
            proof
        });

        /*
        // TODO WIP: plonky2 proof generation:
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::new(config);
        let mut pw: PartialWitness<F> = PartialWitness::new();

        // create the circuit
        let mut circuit = RecursionCircuit::<
            SchnorrPODGadget<NS>,
            OpExecutorGadget<'static, { M + N }, NS>,
            M,
            N,
        >::add_targets(&mut builder, verifier_data.clone())?;
        // set the circuit witness
        circuit.set_targets(
            &mut pw,
            selectors,
            inner_circuit_input,  // =[InnerCircuit::Input; M]
            (gpg_input, op_list), // =OpsExecutor::Input
            output_statements,    // =OpsExecutor::Output
            &recursive_proofs,
        )?;

        let data = builder.build::<C>();
        let plonky2_proof = data.prove(pw)?; // TODO plonky2_proof.proof will be returned inside
                                             // the output POD

        #[cfg(test)] // if running a test, verify the proof
        data.verify(plonky2_proof.clone())?;
        */

        // Check operations in circuit by routing `gpg_input` and
        // `output_statements` into the op executor.

        // Note that one of the targets of `OpExecutorGadget`, `target.0`,
        // should be connected to the corresponding statement targets of
        // the SchnorrPOD and PlonkyPOD gadgets (in that order). These
        // can be connected using StatementTarget's `connect` method.

        Ok(POD {
            payload: PODPayload {
                statements_list: output_statements.clone(),
                statements_map: output_statements.into_iter().collect(),
            },
            proof: PODProof::Plonky(dummy_proof),
            proof_type: GadgetID::PLONKY,
        })
        /*
        // Actually want to return
            Ok(output_plonky_pod)
        // Where output_plonky_pod.payload.statements_map =
        // output_statements (_._.statements_map can be deduced from this)
        // and output_plonky_pod.proof = PODProof::Plonky(proof), where
        // `proof` is the Plonky2 proof obtained above.
         */
    }
}

/*

// Example usage:

// Enumerate PODs you want to prove about:
let input_pods = [("some POD", schnorr_pod1), ("some other POD", schnorr_pod2)];

// Enumerate operations
let op_list = OpList(
        OpCmd(Op::None, "some out statement name"),
        OpCmd(
                Op::CopyStatement(StatementRef(&schnorr_pod1_name, "VALUEOF:s2")),
        "some other out statement name",
            ), ...
              );

// Call the procedure
let plonky_pod = PlonkyButNotPlonkyGadget::<2,2,3>::execute(&input_pods, &op_list)?;
*/

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        iop::witness::PartialWitness,
        plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig},
    };
    use std::array;
    use std::collections::HashMap;

    use super::PlonkyButNotPlonkyGadget;
    use super::{OpExecutorGadget, OperationTarget, D, F};
    use crate::{
        pod::{
            circuit::{pod::SchnorrPODTarget, statement::StatementTarget},
            entry::Entry,
            gadget::GadgetID,
            operation::{OpList, Operation as Op, OperationCmd as OpCmd},
            statement::StatementRef,
            GPGInput, POD,
        },
        recursion::OpsExecutorTrait,
        signature::schnorr::SchnorrSecretKey,
        C,
    };

    /// returns M Schnorr PODs
    fn prepare_pods() -> Vec<(String, POD)> {
        // TODO generate the list dependent on M, instead of hardcoded
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

        let pods_list = vec![
            (schnorr_pod1_name.clone(), schnorr_pod1),
            (schnorr_pod2_name.clone(), schnorr_pod2),
        ];
        pods_list
    }

    #[test]
    fn test_make_plonky_pod() -> Result<()> {
        const M: usize = 2; // max num SchnorrPOD
        const N: usize = 1; // max num Plonky2 recursive proof // TODO allow having >1 plonky2proofs
        const NS: usize = 3; // num statements

        let pods_list = prepare_pods();
        assert_eq!(pods_list.len(), M);

        let schnorr_pod1_name = pods_list[0].0.clone();
        let schnorr_pod2_name = pods_list[1].0.clone();

        let op_list = OpList(vec![
            // NONE:pop
            OpCmd(Op::None, "pop"),
            // VALUEOF:op3
            OpCmd(
                Op::CopyStatement(StatementRef(&schnorr_pod1_name, "VALUEOF:s2")),
                "op3",
            ),
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
            // EQUAL:op2
            OpCmd(
                Op::EqualityFromEntries(
                    StatementRef(&schnorr_pod1_name, "VALUEOF:s1"),
                    StatementRef(&schnorr_pod2_name, "VALUEOF:s4"),
                ),
                "op2",
            ),
        ])
        .sort(&pods_list);

        PlonkyButNotPlonkyGadget::<M, N, NS>::execute(&pods_list, op_list)?;

        Ok(())
    }
}
