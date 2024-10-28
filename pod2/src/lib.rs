#![feature(array_try_from_fn)]
#![feature(generic_const_exprs)]
#![allow(clippy::new_without_default)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]

use anyhow::{anyhow, Result};
use hashbrown::HashMap;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::plonk::proof::Proof;
use plonky2::recursion::dummy_circuit::cyclic_base_proof;
use pod::circuit::operation::OpExecutorGadget;
use pod::circuit::pod::SchnorrPODGadget;
use pod::entry::Entry;
use pod::gadget::GadgetID;
use pod::operation::OpList;
use pod::payload::PODPayload;
use pod::statement::Statement;
use pod::{GPGInput, POD};
use recursion::RecursionTree;
use signature::schnorr::SchnorrSecretKey;

pub type F = GoldilocksField;
pub type C = PoseidonGoldilocksConfig;
pub const D: usize = 2;
pub type PlonkyProof = Proof<F, PoseidonGoldilocksConfig, D>;

pub mod pod;
pub mod recursion;
pub mod signature;

const num_statements: usize = 10;
const num_schnorr_pods: usize = 2;
const num_plonky_pods: usize = 2;

// TODO
/// PlonkyPOD constructor taking a list of named input PODs (which
/// could be either Schnorr or Plonky PODs) as well as operations to
/// be carried out on them as inputs.
pub fn make_plonky_pod(
    /*    num_schnorr_pods: usize, // i.e. `M`
    num_plonky_pods: usize, // i.e. `N`
    num_statements: usize, // i.e. `NS` */
    input_pods: &[(String, POD)],
    op_list: &OpList,
) -> Result<()> /* -> POD */ {
    // Check that the input data is valid, i.e. that we have at most M
    // SchnorrPODs and N PlonkyPODs in our list, *and each POD
    // contains exactly `NS` statements*.
    let mut schnorr_pods = input_pods
        .to_vec()
        .into_iter()
        .filter(|(_, pod)| pod.proof_type == GadgetID::SCHNORR16)
        .collect::<Vec<_>>();
    let schnorr_count = schnorr_pods.len();
    let mut plonky_pods = input_pods
        .to_vec()
        .into_iter()
        .filter(|(_, pod)| pod.proof_type == GadgetID::PLONKY)
        .collect::<Vec<_>>();
    let plonky_count = plonky_pods.len();
    if schnorr_count > num_schnorr_pods {
        return Err(anyhow!(
            "Number of SchnorrPODs ({}) exceeds allowed maximum ({}).",
            schnorr_count,
            num_schnorr_pods
        ));
    }
    if plonky_count > num_plonky_pods {
        return Err(anyhow!(
            "Number of PlonkyPODs ({}) exceeds allowed maximum ({}).",
            plonky_count,
            num_plonky_pods
        ));
    }

    // Sort POD lists.
    schnorr_pods.sort_by(|a, b| a.0.cmp(&b.0));
    plonky_pods.sort_by(|a, b| a.0.cmp(&b.0));

    let statement_check = input_pods
        .iter()
        .all(|(_, pod)| pod.payload.statements_list.len() == num_statements);
    if !statement_check {
        return Err(anyhow!(
            "All input PODs must contain exactly {} statements.",
            num_statements
        ));
    }

    // TODO
    // Initialise circuit data for padding.
    type RT<'a> = RecursionTree<
        SchnorrPODGadget<num_statements>,
        OpExecutorGadget<'a, { num_plonky_pods + num_schnorr_pods }, num_statements>,
        num_schnorr_pods,
        num_plonky_pods,
    >;
    let circuit_data = RT::circuit_data()?;
    let verifier_data = circuit_data.verifier_data();
    let dummy_proof_pis = cyclic_base_proof(
        &circuit_data.common,
        &verifier_data.verifier_only,
        HashMap::new(),
    );
    let dummy_proof = dummy_proof_pis.proof;
    // TODO: Constructor
    let dummy_plonky_pod = POD {
        payload: PODPayload {
            statements_list: (0..num_statements)
                .map(|i| (format!("Dummy statement {}", i), Statement::None))
                .collect(),
            statements_map: std::collections::HashMap::new(),
        },
        proof: pod::PODProof::Plonky(dummy_proof),
        proof_type: GadgetID::PLONKY,
    };

    let dummy_schnorr_pod = POD::execute_schnorr_gadget(
        &(0..num_statements)
            .map(|i| Entry::new_from_scalar(&format!("Dummy entry {}", i), GoldilocksField(0)))
            .collect::<Vec<_>>(),
        &SchnorrSecretKey { sk: 0 },
    );

    // Arrange input PODs as a list of M SchnorrPODs followed by N
    // PlonkyPODs. Pad with appropriate dummy data.
    let padded_pod_list = [
        schnorr_pods,
        (0..(num_schnorr_pods - schnorr_count))
            .map(|i| (format!("_DUMMYSCHNORR{}", i), dummy_schnorr_pod.clone()))
            .collect(),
        plonky_pods,
        (0..(num_plonky_pods - plonky_count))
            .map(|i| (format!("_DUMMYPLONKY{}", i), dummy_plonky_pod.clone()))
            .collect(),
    ]
    .concat();

    // Prepare selectors
    let selectors = (0..num_schnorr_pods)
        .map(|i| GoldilocksField(if i < schnorr_count { 1 } else { 0 }))
        .chain((0..num_plonky_pods).map(|i| GoldilocksField(if i < plonky_count { 1 } else { 0 })))
        .collect::<Vec<_>>();

    // TODO: Clean up.
    // Compute result of operations.
    let gpg_input = {
        let sorted_gpg_input = GPGInput::new(
            padded_pod_list.clone().into_iter().collect(),
            std::collections::HashMap::new(),
        );
        GPGInput {
            pods_list: padded_pod_list,
            origin_renaming_map: sorted_gpg_input.origin_renaming_map,
        }
    };

    // Output Plonky POD should have this as its statement_list in its payload.
    let output_statements = POD::execute_oracle_gadget(&gpg_input, &op_list.0)?
        .payload
        .statements_list;

    // Verify SchnorrPODs in circuit.
    // Verify PlonkyPODs in circuit.
    // Check operations.

    Ok(())
    /*
    // Actually want to return
        Ok(output_plonky_pod)
    // Where output_plonky_pod.payload.statements_map =
    // output_statements (_._.statements_map can be deduced from this)
    // and output_plonky_pod.proof = PODProof::Plonky(proof), where
    // `proof` is the Plonky2 proof obtained above.
     */
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
let plonky_pod = make_plonky_pod(&input_pods, &op_list)?;
*/
