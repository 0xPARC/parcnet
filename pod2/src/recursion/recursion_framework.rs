/*
 N-arity tree of recursion, which at each recursive node it also verifies M InnerCircuits.

                 p_root
                  ▲
        ┌─────────┴──────────┐
        │         F          │
        └────────────────────┘
         ▲ ▲    ▲       ▲   ▲
  ┌──────┘┌┘    │       │   │
  │       │     │       │   └──┐
c'_1...c'_m     │p''_1  │      │p''_n
            ┌───┴────┐  │  ┌───┴────┐
            │   F    │(...)│   F    │
            └────────┘     └────────┘
            ▲ ▲ ▲  ▲          ▲ ▲ ▲  ▲
        ┌───┘┌┘ └┐ └──┐    ┌──┘┌┘ └─┐└───┐
        │    │   │    │    │   │    └┐   │
       c_1..c_m p_1..p_n c'_1..c'_m p'_1..p'_n

 where
 - each c_i is an InnerCircuit
 - each p_i is a plonky2 proof
 and each of them is enabled/disabled by a selector s_i.

 Current version has m+n selectors, but we could make them shared between c's and p's.

 To run the tests that checks this logic:
 cargo test --release test_recursion -- --nocapture
*/
use anyhow::{anyhow, Result};
use plonky2::field::types::Field;
use plonky2::gates::noop::NoopGate;
use plonky2::hash::hash_types::{HashOut, HashOutTarget, NUM_HASH_OUT_ELTS};
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CircuitData, VerifierCircuitData, VerifierCircuitTarget,
};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use std::array;
use std::marker::PhantomData;
use std::time::Instant;

use super::utils::*;
use super::InnerCircuit;
use crate::{PlonkyProof, C, D, F};

/// RecursiveCircuit defines the circuit used on each node of the recursion tree, which is doing
/// `(InnerCircuit OR recursive-proof-verification)` N times, and generating a new proof that can
/// be verified by the same circuit itself.
///
/// It contains the methods to `add_targets` (ie. create the targets, the logic of the circuit),
/// and `set_targets` (ie. set the specific values to be used for the previously created targets).
///
/// I: InnerCircuit
/// M: number of InnerCircuits per recursive step
/// N: number of plonky2 proofs per recursive step
pub struct RecursiveCircuit<I: InnerCircuit, const M: usize, const N: usize>
where
    [(); M + N]:,
{
    hashes_targ: [HashOutTarget; M + N],
    selectors_targ: [Target; M + N],
    inner_circuit_targ: [I::Targets; M],
    proofs_targ: [ProofWithPublicInputsTarget<D>; N],
    // the next two are common for all the given proofs. It is the data for this circuit itself
    // (cyclic circuit).
    verifier_data_targ: VerifierCircuitTarget,
    verifier_data: VerifierCircuitData<F, C, D>,
}

impl<I: InnerCircuit, const M: usize, const N: usize> RecursiveCircuit<I, M, N>
where
    [(); M + N]:,
{
    pub fn prepare_public_inputs(
        verifier_data: VerifierCircuitData<F, C, D>,
        // hashese contains (in this order) M hashes corresponding to the M InnerCircuits, and N
        // hashes corresponding to the plonky2 proofs
        hashes: [HashOut<F>; M + N],
    ) -> Vec<F> {
        [
            hashes.into_iter().flat_map(|h| h.elements).collect(),
            // add verifier_data as public inputs:
            verifier_data.verifier_only.circuit_digest.elements.to_vec(),
            verifier_data
                .verifier_only
                .constants_sigmas_cap
                .0
                .iter()
                .flat_map(|e| e.elements)
                .collect(),
        ]
        .concat()
    }

    // notice that this method does not fill the targets, which is done in the method
    // `fill_recursive_circuit_targets`
    pub fn add_targets(
        builder: &mut CircuitBuilder<F, D>,
        verifier_data: VerifierCircuitData<F, C, D>,
    ) -> Result<Self> {
        let hashes_targ: [HashOutTarget; M + N] =
            array::from_fn(|_| builder.add_virtual_hash_public_input());

        // build the InnerCircuit logic. Also set the selectors, used both by the InnerCircuit and
        // by the recursive proofs verifications.
        let selectors_targ: [Target; M + N] = array::from_fn(|_| {
            let selector_F_targ = builder.add_virtual_target();
            // ensure that selector_booltarg is \in {0,1}
            binary_check(builder, selector_F_targ);
            selector_F_targ
        });
        let selectors_bool_targ: [BoolTarget; M + N] =
            array::from_fn(|i| BoolTarget::new_unsafe(selectors_targ[i]));

        let inner_circuit_targ: [I::Targets; M] = array::try_from_fn(|i| {
            I::add_targets(builder, &selectors_bool_targ[i], &hashes_targ[i])
        })?;

        // proof verification:

        let common_data = verifier_data.common.clone();
        let verifier_data_targ = builder.add_verifier_data_public_inputs();

        let proofs_targ: Result<[ProofWithPublicInputsTarget<D>; N]> = array::try_from_fn(|i| {
            let proof_targ = builder.add_virtual_proof_with_pis(&common_data);
            builder.conditionally_verify_cyclic_proof_or_dummy::<C>(
                selectors_bool_targ[i],
                &proof_targ,
                &common_data,
            )?;
            Ok(proof_targ)
        });
        let proofs_targ = proofs_targ?;

        Ok(Self {
            hashes_targ,
            selectors_targ,
            inner_circuit_targ,
            proofs_targ,
            verifier_data_targ,
            verifier_data,
        })
    }

    pub fn set_targets(
        &mut self,
        pw: &mut PartialWitness<F>,
        // hashese contains (in this order) M hashes corresponding to the M InnerCircuits, and N
        // hashes corresponding to the plonky2 proofs
        hashes: &[HashOut<F>; M + N],
        // if selectors[i]==0: verify InnerCircuit. if selectors[i]==1: verify recursive_proof[i]
        selectors: [F; M + N],
        inner_circuit_input: [I::Input; M],
        recursive_proofs: &[PlonkyProof; N],
    ) -> Result<()> {
        // set the msgs values
        for i in 0..(M + N) {
            pw.set_hash_target(self.hashes_targ[i], hashes[i])?;
        }

        // set the InnerCircuit related values
        for i in 0..(M + N) {
            pw.set_target(self.selectors_targ[i], selectors[i])?;
        }

        for i in 0..M {
            I::set_targets(pw, &self.inner_circuit_targ[i], &inner_circuit_input[i])?;
        }

        // set proof related values:

        // recursive proofs verification
        pw.set_verifier_data_target(&self.verifier_data_targ, &self.verifier_data.verifier_only)?;

        let public_inputs = RecursiveCircuit::<I, M, N>::prepare_public_inputs(
            self.verifier_data.clone(),
            hashes.clone(),
        );
        for i in 0..N {
            pw.set_proof_with_pis_target(
                &self.proofs_targ[i],
                &ProofWithPublicInputs {
                    proof: recursive_proofs[i].clone(),
                    public_inputs: public_inputs.clone(),
                },
            )?;
        }

        Ok(())
    }
}

pub fn common_data_for_recursion<I: InnerCircuit, const M: usize, const N: usize>(
) -> Result<CircuitData<F, C, D>> {
    // 1st
    let config = CircuitConfig::standard_recursion_config();
    let builder = CircuitBuilder::<F, D>::new(config);
    let data = builder.build::<C>();

    // 2nd
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config.clone());
    let verifier_data = builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    // proofs
    for _ in 0..N {
        let proof = builder.add_virtual_proof_with_pis(&data.common);
        builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    }
    // let n_gates = builder.num_gates();
    let data = builder.build::<C>();

    // 3rd
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config.clone());
    let mut hashes_targ: Vec<HashOutTarget> = vec![];
    for _ in 0..(M + N) {
        let hash_targ = builder.add_virtual_hash_public_input();
        hashes_targ.push(hash_targ);
    }

    builder.add_gate(
        // add a ConstantGate, because without this, when later generating the `dummy_circuit`
        // (inside the `conditionally_verify_cyclic_proof_or_dummy`), it fails due the
        // `CommonCircuitData` of the generated circuit not matching the given `CommonCircuitData`
        // to create it. Without this it fails because it misses a ConstantGate.
        plonky2::gates::constant::ConstantGate::new(config.num_constants),
        vec![],
    );

    // InnerCircuits targets
    for i in 0..(M + N) {
        let selector_F_targ = builder.add_virtual_target();
        binary_check(&mut builder, selector_F_targ);
        let b = BoolTarget::new_unsafe(selector_F_targ);
        // add targets of M InnerCircuits
        if i < M {
            let _ = I::add_targets(&mut builder, &b, &hashes_targ[i]).unwrap();
        }
    }

    // proofs verify
    let verifier_data = builder.add_verifier_data_public_inputs();
    // proofs
    for _ in 0..N {
        let proof = builder.add_virtual_proof_with_pis(&data.common);
        builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    }

    // pad min gates
    let n_gates = compute_num_gates::<N>()?;
    while builder.num_gates() < n_gates {
        builder.add_gate(NoopGate, vec![]);
    }
    dbg!(builder.num_gates());
    Ok(builder.build::<C>())
}

fn compute_num_gates<const N: usize>() -> Result<usize> {
    // Note: the following numbers are WIP, obtained by trial-error by running different
    // configurations in the tests.
    let n_gates = match N {
        1 => 1 << 12,
        2 => 1 << 13,
        3..=5 => 1 << 14,
        6 => 1 << 15,
        _ => 0,
    };
    if n_gates == 0 {
        return Err(anyhow!(
            "arity of N={} not supported yet. Currently supported N from 1 to 6 (both included)",
            N
        ));
    }
    Ok(n_gates)
}

#[derive(Debug, Clone)]
pub struct RecursionTree<I: InnerCircuit, const M: usize, const N: usize> {
    _i: PhantomData<I>,
}

impl<I: InnerCircuit, const M: usize, const N: usize> RecursionTree<I, M, N>
where
    [(); M + N]:,
{
    /// returns the full-recursive CircuitData
    pub fn circuit_data() -> Result<CircuitData<F, C, D>> {
        let mut data = common_data_for_recursion::<I, M, N>()?;

        // build the actual RecursiveCircuit circuit data
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::new(config);
        let _ = RecursiveCircuit::<I, M, N>::add_targets(&mut builder, data.verifier_data())?;
        dbg!(builder.num_gates());
        data = builder.build::<C>();

        Ok(data)
    }

    pub fn prove_node(
        verifier_data: VerifierCircuitData<F, C, D>,
        hashes: &[HashOut<F>; M + N],
        // if selectors[i]==0: verify InnerCircuit. if selectors[i]==1: verify recursive_proof[i]
        selectors: [F; M + N],
        inner_circuits_input: [I::Input; M],
        recursive_proofs: &[PlonkyProof; N],
    ) -> Result<PlonkyProof> {
        println!("prove_node:");
        for i in 0..M + N {
            let what = if i < M { "inner circuit" } else { "proof" };
            if selectors[i].is_nonzero() {
                println!("  (selectors[{}]==1), verify {}-th {}", i, i, what);
            } else {
                println!("  (selectors[{}]==0), verify {}-th {}", i, i, what);
            }
        }

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::new(config);

        // assign the targets
        let start = Instant::now();
        let mut circuit =
            RecursiveCircuit::<I, M, N>::add_targets(&mut builder, verifier_data.clone())?;
        println!("RecursiveCircuit::add_targets(): {:?}", start.elapsed());

        // fill the targets
        let mut pw = PartialWitness::new();
        let start = Instant::now();
        circuit.set_targets(
            &mut pw,
            hashes,
            selectors,
            inner_circuits_input,
            recursive_proofs,
        )?;
        println!("circuit.set_targets(): {:?}", start.elapsed());

        let start = Instant::now();
        let data = builder.build::<C>();
        println!("builder.build(): {:?}", start.elapsed());

        let start = Instant::now();
        let new_proof = data.prove(pw)?;
        println!("generate new_proof: {:?}", start.elapsed());

        let start = Instant::now();
        data.verify(new_proof.clone())?;
        println!("verify new_proof: {:?}", start.elapsed());

        #[cfg(test)]
        data.verifier_data().verify(ProofWithPublicInputs {
            proof: new_proof.proof.clone(),
            public_inputs: new_proof.public_inputs.clone(),
        })?;

        #[cfg(test)]
        verifier_data.verify(ProofWithPublicInputs {
            proof: new_proof.proof.clone(),
            public_inputs: new_proof.public_inputs.clone(),
        })?;

        Ok(new_proof.proof)
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use hashbrown::HashMap;
    use plonky2::field::types::{Field, Sample};
    use plonky2::plonk::proof::ProofWithPublicInputs;
    use plonky2::recursion::dummy_circuit::cyclic_base_proof;
    use rand;
    use std::array;
    use std::time::Instant;

    use super::*;

    use crate::recursion::example_innercircuit::{ExampleGadget, ExampleGadgetInput};
    use crate::signature::schnorr::*;

    // this sets the plonky2 internal logs level
    fn set_log() {
        let _ = env_logger::builder()
            .filter_level(log::LevelFilter::Warn)
            .is_test(true)
            .try_init();
    }

    /// to run:
    /// cargo test --release test_recursion -- --nocapture
    #[test]
    fn test_recursion() -> Result<()> {
        test_recursion_opt::<2, 2>()?; // M=2, N=2

        Ok(())
    }

    fn test_recursion_opt<const M: usize, const N: usize>() -> Result<()>
    where
        [(); M + N]:,
    {
        set_log();
        println!("\n--------------------------------------------------");
        println!("\n--------------------------------------------------");
        println!(
            "\nrunning test:\n===test_tree_recursion_opt with N={} (arity)",
            N
        );

        let l: u32 = 2; // levels of the recursion (binary) tree
        println!(
            "Testing {} recursive iterations, where each iteration checks M={} InnerCircuits and N={} plonky2 proofs",
            l, M, N
        );

        let mut rng: rand::rngs::ThreadRng = rand::thread_rng();
        let schnorr = SchnorrSigner::new();
        // generate M+N random hashes
        let hashes: [HashOut<F>; M + N] = array::from_fn(|_| HashOut::<F>::sample(&mut rng));

        // generate M*N key pairs (M for each of the N recursive nodes at the base level)
        let sk_vec: Vec<SchnorrSecretKey> = (0..(M))
            .map(|i| SchnorrSecretKey { sk: i as u64 })
            .collect();
        let pk_vec: Vec<SchnorrPublicKey> = sk_vec.iter().map(|&sk| schnorr.keygen(&sk)).collect();

        // sign the hashes
        let sig_vec: Vec<SchnorrSignature> = sk_vec
            .iter()
            .zip(hashes.iter().take(M).map(|h| h.elements).cycle())
            .map(|(&sk, msg)| schnorr.sign(&msg.to_vec(), &sk, &mut rng))
            .collect();
        assert_eq!(sig_vec.len(), M);

        // build the circuit_data & verifier_data for the recursive circuit
        let circuit_data = RecursionTree::<ExampleGadget, M, N>::circuit_data()?;
        let verifier_data = circuit_data.verifier_data();

        let dummy_proof_pis = cyclic_base_proof(
            &circuit_data.common,
            &verifier_data.verifier_only,
            HashMap::new(),
        );
        let dummy_proof = dummy_proof_pis.proof;

        // we start with k dummy proofs, since at the leafs level we don't have proofs yet and we
        // just verify the signatures. At each level we divide the amount of proofs by N. At the
        // root level there is a single proof.
        let mut proofs_at_level_i: Vec<PlonkyProof> = (0..(N * N))
            .into_iter()
            .map(|_| dummy_proof.clone())
            .collect();

        // loop over the recursion levels
        for i in 0..l {
            println!("\n--- recursion level i={}", i);
            let mut next_level_proofs: Vec<PlonkyProof> = vec![];

            // loop over the nodes of each recursion tree level
            for j in (0..proofs_at_level_i.len()).into_iter().step_by(N) {
                println!(
                    "\n------ recursion node: (level) i={}, (node in level) j={}",
                    i, j
                );

                // let proof_enabled = if i == 0 { F::ZERO } else { F::ONE };
                // prepare the inputs for the `RecursionTree::prove_node` call
                let mut selectors: [F; M + N] = [F::ZERO; M + N];
                if i > 0 {
                    // if we're not at the base-level, enable the N selectors of the proofs
                    // verifications
                    selectors[M..N].fill(F::ONE);
                }
                let innercircuits_input: [ExampleGadgetInput; M] =
                    array::from_fn(|k| ExampleGadgetInput {
                        pk: pk_vec[k],
                        sig: sig_vec[k],
                    });
                let proofs: [PlonkyProof; N] = array::from_fn(|k| proofs_at_level_i[k].clone());

                // do the recursive step
                let start = Instant::now();
                let new_proof = RecursionTree::<ExampleGadget, M, N>::prove_node(
                    verifier_data.clone(),
                    &hashes,
                    selectors,
                    innercircuits_input,
                    &proofs,
                )?;
                println!(
                    "RecursionTree::prove_node (level: i={}, node: j={}) took: {:?}",
                    i,
                    j,
                    start.elapsed()
                );

                // verify the recursive proof
                let public_inputs = RecursiveCircuit::<ExampleGadget, M, N>::prepare_public_inputs(
                    verifier_data.clone(),
                    hashes.clone(),
                );
                verifier_data.clone().verify(ProofWithPublicInputs {
                    proof: new_proof.clone(),
                    public_inputs: public_inputs.clone(),
                })?;

                // set new_proof for next iteration
                next_level_proofs.push(new_proof);
            }
            proofs_at_level_i = next_level_proofs.clone();
        }
        assert_eq!(proofs_at_level_i.len(), 1);
        let last_proof = proofs_at_level_i[0].clone();

        // verify the last proof
        let public_inputs = RecursiveCircuit::<ExampleGadget, M, N>::prepare_public_inputs(
            verifier_data.clone(),
            hashes.clone(),
        );
        verifier_data.clone().verify(ProofWithPublicInputs {
            proof: last_proof.clone(),
            public_inputs: public_inputs.clone(),
        })?;

        Ok(())
    }
}
