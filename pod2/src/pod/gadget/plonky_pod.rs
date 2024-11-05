use anyhow::{anyhow, Result};
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CircuitData, ProverCircuitData, VerifierCircuitData,
};
use std::array;
use std::collections::HashMap;
use std::time::Instant;

use crate::pod::entry::Entry;
use crate::pod::gadget::GadgetID;
use crate::pod::gadget::{opexecutor::OpExecutorGadget, schnorr_pod::SchnorrPODGadget};
use crate::pod::operation::OpList;
use crate::pod::payload::{PODPayload, StatementList};
use crate::pod::statement::Statement;
use crate::pod::{GPGInput, PODProof, POD};
use crate::recursion::RecursionCircuit;
use crate::signature::schnorr::SchnorrSecretKey;

use crate::{PlonkyProof, C, D, F};

pub struct ProverParams<const M: usize, const N: usize, const NS: usize, const VL: usize>
where
    [(); M + N]:,
{
    circuit:
        RecursionCircuit<SchnorrPODGadget<NS>, OpExecutorGadget<{ M + N }, NS, VL>, M, N, NS, VL>,
    prover: ProverCircuitData<F, C, D>,
    dummy_proof: PlonkyProof,
}

/// PlonkyPOD constructor taking a list of named input PODs (which could be either Schnorr or
/// Plonky PODs) as well as operations to be carried out on them as inputs.
/// Example usage:
///
/// Enumerate PODs you want to prove about:
/// ```no_run,ignore
/// let input_pods = [("some POD", schnorr_pod1), ("some other POD", schnorr_pod2)];
/// ```
///
/// Enumerate operations:
/// ```no_run,ignore
/// let op_list = OpList(
///         OpCmd::new(Op::None, "some out statement name"),
///         OpCmd::new(
///                 Op::CopyStatement(StatementRef::new(&schnorr_pod1_name, "VALUEOF:s2")),
///         "some other out statement name",
///             ), ...
///               );
/// ```
///
/// Call the procedure
/// ```no_run,ignore
/// let plonky_pod = PlonkyButNotPlonkyGadget::<2,2,3>::execute(&input_pods, &op_list)?;
/// ```
// TODO: `PlonkyButNotPlonkyGadget` is a placeholder name, set better struct name.
pub struct PlonkyButNotPlonkyGadget<
    const M: usize,
    const N: usize,
    const NS: usize,
    const VL: usize,
> where
    [(); M + N]:;

impl<const M: usize, const N: usize, const NS: usize, const VL: usize>
    PlonkyButNotPlonkyGadget<M, N, NS, VL>
where
    [(); M + N]:,
{
    /// Returns the RecursiveCircuit's CircuitData, which is reused for all calls of the `execute`
    /// method
    pub fn circuit_data() -> Result<CircuitData<F, C, D>> {
        // generate circuit data
        RecursionCircuit::<
            SchnorrPODGadget<NS>,
            OpExecutorGadget<{ M + N }, NS, VL>, // NP=M+N
            M,
            N,
            NS,
            VL,
        >::circuit_data()
    }

    /// returns ProverCircuitData
    pub fn build_prover_params(
        circuit_data: CircuitData<F, C, D>,
    ) -> Result<ProverParams<M, N, NS, VL>> {
        let verifier_data = circuit_data.verifier_data();

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::new(config);

        let circuit = RecursionCircuit::<
            SchnorrPODGadget<NS>,
            OpExecutorGadget<{ M + N }, NS, VL>,
            M,
            N,
            NS,
            VL,
        >::add_targets(&mut builder, verifier_data.clone())?;

        let prover = RecursionCircuit::<
            SchnorrPODGadget<NS>,
            OpExecutorGadget<{ M + N }, NS, VL>, // NP=M+N
            M,
            N,
            NS,
            VL,
        >::build_prover(verifier_data)?;

        let dummy_proof = RecursionCircuit::<
            SchnorrPODGadget<NS>,
            OpExecutorGadget<{ M + N }, NS, VL>,
            M,
            N,
            NS,
            VL,
        >::dummy_proof(circuit_data);

        Ok(ProverParams {
            circuit,
            prover,
            dummy_proof,
        })
    }

    /// Generates a new POD from the given input PODs and the OpList (operations list)
    pub fn execute(
        mut prover_params: ProverParams<M, N, NS, VL>,
        input_pods: &[(String, POD)],
        op_list: OpList,
        origin_renaming_map: HashMap<(String, String), String>,
    ) -> Result<POD> {
        let start_execute = Instant::now();
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

        // Pad op list
        let op_list = op_list.pad::<NS>()?;

        // Sort POD lists.
        schnorr_pods.sort_by(|a, b| a.0.cmp(&b.0));
        plonky_pods.sort_by(|a, b| a.0.cmp(&b.0));

        // TODO: Constructor
        let dummy_plonky_pod = POD {
            payload: PODPayload {
                statements_list: (0..NS)
                    .map(|i| (format!("Dummy statement {}", i), Statement::None))
                    .collect(),
                statements_map: std::collections::HashMap::new(),
            },
            proof: crate::pod::PODProof::Plonky(prover_params.dummy_proof.clone()),
            proof_type: GadgetID::PLONKY,
        };

        // Note: One statement is reserved for the signer's public key.
        let dummy_schnorr_pod = POD::execute_schnorr_gadget::<NS>(
            &(0..(NS - 1))
                .map(|i| Entry::new_from_scalar(&format!("Dummy entry {}", i), GoldilocksField(0)))
                .collect::<Vec<_>>(),
            &SchnorrSecretKey { sk: 0 },
        )?;

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
        let padded_pod_list: [(String, POD); M + N] = array::from_fn(|i| {
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
                origin_renaming_map,
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

        // plonky2 proof generation:
        // let config = CircuitConfig::standard_recursion_config();
        // let mut builder = CircuitBuilder::new(config);
        let mut pw: PartialWitness<F> = PartialWitness::new();

        // create the circuit
        // let start_add_targets = Instant::now();
        // let mut circuit = RecursionCircuit::<
        //     SchnorrPODGadget<NS>,
        //     OpExecutorGadget<{ M + N }, NS, VL>,
        //     M,
        //     N,
        //     NS,
        //     VL
        // >::add_targets(&mut builder, verifier_data.clone())?;
        // let time_add_targets = start_add_targets.elapsed();

        // set the circuit witness
        prover_params.circuit.set_targets(
            &mut pw,
            selectors,
            inner_circuit_input,       // =[InnerCircuit::Input; M]
            (gpg_input, op_list),      // =OpsExecutor::Input
            output_statements.clone(), // =OpsExecutor::Output
            &recursive_proofs,
        )?;

        let start_prove = Instant::now();
        let plonky_proof = prover_params.prover.prove(pw)?;
        let time_prove = start_prove.elapsed();

        // Check operations in circuit by routing `gpg_input` and
        // `output_statements` into the op executor.

        // Note that one of the targets of `OpExecutorGadget`, `target.0`,
        // should be connected to the corresponding statement targets of
        // the SchnorrPOD and PlonkyPOD gadgets (in that order). These
        // can be connected using StatementTarget's `connect` method.

        let time_execute = start_execute.elapsed();
        println!(
            "| {} | {} | {} | {} | {:#.2?} | {:#.2?} |",
            M, N, NS, VL, time_prove, time_execute,
        );

        Ok(POD {
            payload: PODPayload {
                statements_list: output_statements.clone(),
                statements_map: output_statements.into_iter().collect(),
            },
            proof: PODProof::Plonky(plonky_proof.proof),
            proof_type: GadgetID::PLONKY,
        })
    }

    /// This is a helper method that just verifies the PlonkyProof contained inside the POD
    pub fn verify_plonky_pod(verifier_data: VerifierCircuitData<F, C, D>, pod: POD) -> Result<()> {
        // get the PlonkyProof from the pod.proof
        let proof = match pod.proof.clone() {
            PODProof::Plonky(p) => Ok(p),
            _ => Err(anyhow!("Expected PODProof's Plonky variant")),
        }?;

        // get the statement fields from each statement in the
        // `pod.payload.statements_list:Vec<(String,Statement)>`
        let public_inputs: Vec<F> = pod
            .payload
            .statements_list
            .into_iter()
            .flat_map(|v| v.1.to_fields())
            .collect();

        Self::verify_plonky_proof(verifier_data, proof, public_inputs)
    }

    /// This is a helper method that just verifies the given PlonkyProof
    pub fn verify_plonky_proof(
        verifier_data: VerifierCircuitData<F, C, D>,
        proof: PlonkyProof,
        public_inputs: Vec<F>,
    ) -> Result<()> {
        let public_inputs: Vec<F> = [
            public_inputs,
            // add verifier_data as public inputs
            verifier_data.verifier_only.circuit_digest.elements.to_vec(),
            verifier_data
                .verifier_only
                .constants_sigmas_cap
                .0
                .iter()
                .flat_map(|e| e.elements)
                .collect(),
        ]
        .concat();

        // verify the PlonkyProof
        verifier_data.verify(plonky2::plonk::proof::ProofWithPublicInputs {
            proof,
            public_inputs,
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use std::collections::HashMap;
    use std::time::Instant;

    use super::PlonkyButNotPlonkyGadget;
    use crate::{
        pod::{
            entry::Entry,
            operation::{OpList, Operation as Op, OperationCmd as OpCmd},
            statement::StatementRef,
            POD,
        },
        signature::schnorr::SchnorrSecretKey,
    };

    /// returns M Schnorr PODs
    fn prepare_pods<const NS: usize>() -> Result<Vec<(String, POD)>> {
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

        let pods_list = vec![
            (schnorr_pod1_name.clone(), schnorr_pod1),
            (schnorr_pod2_name.clone(), schnorr_pod2),
        ];
        Ok(pods_list)
    }

    // TODO: `PlonkyButNotPlonkyGadget` is tmp, put better name.
    #[test]
    fn test_PlonkyButNotPlonkyGadget() -> Result<()> {
        const M: usize = 3; // max num SchnorrPOD
        const N: usize = 2; // max num Plonky2 recursive proof
        const NS: usize = 3; // num statements
        const VL: usize = 0; // vec length in contains op

        let pods_list = prepare_pods::<NS>()?;

        let schnorr_pod1_name = pods_list[0].0.clone();
        // let schnorr_pod2_name = pods_list[1].0.clone();

        let op_list = OpList(vec![
            // NONE:pop
            OpCmd::new(Op::None, "pop"),
            // VALUEOF:op3
            OpCmd::new(
                Op::CopyStatement(StatementRef::new(schnorr_pod1_name, "VALUEOF:s2")),
                "op3",
            ),
            // COPY preceding op's output
            OpCmd::new(
                Op::CopyStatement(StatementRef::new("_SELF", "VALUEOF:op3")),
                "op4",
            ),
            // NOTEQUAL:yolo
            // OpCmd::new(
            //     Op::NonequalityFromEntries(
            //         StatementRef::new(schnorr_pod1_name, "VALUEOF:s1"),
            //         StatementRef::new(schnorr_pod1_name, "VALUEOF:s2"),
            //     ),
            //     "yolo",
            // ),
            // // VALUEOF:nono
            // OpCmd::new(
            //     Op::NewEntry(Entry::new_from_scalar("what", GoldilocksField(23))),
            //     "nono",
            // ),
            // // EQUAL:op2
            // OpCmd::new(
            //     Op::EqualityFromEntries(
            //         StatementRef::new(schnorr_pod1_name, "VALUEOF:s1"),
            //         StatementRef::new(schnorr_pod2_name, "VALUEOF:s4"),
            //     ),
            //     "op2",
            // ),
        ]);

        // build the circuit_data, this struct is reused for all the calls of
        // PlonkyButNotPlonkyGadget::execute
        let circuit_data = PlonkyButNotPlonkyGadget::<M, N, NS, VL>::circuit_data()?;
        let verifier_data = circuit_data.verifier_data();
        let prover_params =
            PlonkyButNotPlonkyGadget::<M, N, NS, VL>::build_prover_params(circuit_data)?;

        let start = Instant::now();
        let new_pod = PlonkyButNotPlonkyGadget::<M, N, NS, VL>::execute(
            prover_params,
            &pods_list,
            op_list,
            HashMap::new(),
        )?;
        println!("PlonkyButNotPlonkyGadget::execute(): {:?}", start.elapsed());

        // verify the new_pod's plonky2 proof
        PlonkyButNotPlonkyGadget::<M, N, NS, VL>::verify_plonky_pod(verifier_data, new_pod)?;

        // TODO do a 2nd iteration where the generated plonky2-pod is (recursively) verified
        Ok(())
    }

    #[test]
    fn get_numbers_PlonkyButNotPlonkyGadget() -> Result<()> {
        println!("| M | N | NS | VL | prove | total |");
        println!("|--- | --- | --- | --- | ------ | ------ |");

        test_empty_inputs_PlonkyButNotPlonkyGadget_opt::<3, 1, 1, 0>()?;
        test_empty_inputs_PlonkyButNotPlonkyGadget_opt::<3, 1, 3, 0>()?;
        // the next tests are commented out by default because they take longer time to compute
        // test_empty_inputs_PlonkyButNotPlonkyGadget_opt::<3, 1, 5, 0>()?;
        // test_empty_inputs_PlonkyButNotPlonkyGadget_opt::<3, 1, 10, 0>()?;
        // test_empty_inputs_PlonkyButNotPlonkyGadget_opt::<3, 1, 25, 0>()?;
        // test_empty_inputs_PlonkyButNotPlonkyGadget_opt::<3, 2, 1, 0>()?;
        // test_empty_inputs_PlonkyButNotPlonkyGadget_opt::<3, 2, 3, 0>()?;
        // test_empty_inputs_PlonkyButNotPlonkyGadget_opt::<3, 2, 5>()?;
        // test_empty_inputs_PlonkyButNotPlonkyGadget_opt::<3, 2, 10>()?;
        // test_empty_inputs_PlonkyButNotPlonkyGadget_opt::<3, 2, 25>()?;
        // test_empty_inputs_PlonkyButNotPlonkyGadget_opt::<3, 3, 1>()?;
        // test_empty_inputs_PlonkyButNotPlonkyGadget_opt::<3, 3, 3>()?;
        // test_empty_inputs_PlonkyButNotPlonkyGadget_opt::<3, 3, 5>()?;
        // test_empty_inputs_PlonkyButNotPlonkyGadget_opt::<3, 3, 10>()?;
        // test_empty_inputs_PlonkyButNotPlonkyGadget_opt::<3, 3, 25>()?;
        Ok(())
    }

    fn test_empty_inputs_PlonkyButNotPlonkyGadget_opt<
        const M: usize,  // max num SchnorrPOD
        const N: usize,  // max num Plonky2 recursive proof
        const NS: usize, // num statements
        const VL: usize, // vec length in contains op
    >() -> Result<()>
    where
        [(); M + N]:,
    {
        let pods_list = vec![];
        let out_statement_names = (0..NS)
            .map(|i| format!("_DUMMYOUT{}", i))
            .collect::<Vec<_>>();
        let op_list = OpList(
            out_statement_names
                .iter()
                .map(|name| OpCmd::new(Op::None, name))
                .collect(),
        );

        let circuit_data = PlonkyButNotPlonkyGadget::<M, N, NS, VL>::circuit_data()?;
        let prover_params =
            PlonkyButNotPlonkyGadget::<M, N, NS, VL>::build_prover_params(circuit_data)?;

        let _new_pod = PlonkyButNotPlonkyGadget::<M, N, NS, VL>::execute(
            prover_params,
            &pods_list,
            op_list,
            HashMap::new(),
        )?;

        Ok(())
    }
}
