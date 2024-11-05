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
c''_1...c''_M   │p''_1  │      │p''_N
            ┌───┴────┐  │  ┌───┴────┐
            │   F    │(...)│   F    │
            └────────┘     └────────┘
            ▲ ▲ ▲  ▲          ▲ ▲ ▲  ▲
        ┌───┘┌┘ └┐ └──┐    ┌──┘┌┘ └─┐└───┐
        │    │   │    │    │   │    └┐   │
       c_1..c_M p_1..p_N c'_1..c'_M p'_1..p'_N

 where
 - each c_i is an InnerCircuit
 - each p_i is a plonky2 proof
 and each of them is enabled/disabled by a selector s_i.

 Current version has M+N selectors, but we could make them shared between c's and p's.

 To run the tests that checks this logic:
 cargo test --release test_recursion -- --nocapture
*/
use anyhow::{anyhow, Result};
use hashbrown::HashMap;
use plonky2::field::types::Field;
use plonky2::gates::noop::NoopGate;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CircuitData, ProverCircuitData, VerifierCircuitData, VerifierCircuitTarget,
};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2::recursion::dummy_circuit::cyclic_base_proof;
use std::array;
use std::marker::PhantomData;
use std::time::Instant;

use super::utils::*;
use super::{InnerCircuitTrait, OpsExecutorTrait};
use crate::{PlonkyProof, C, D, F};

/// RecursionTree defines the tree, where each recursive node executes
/// - M InnerCircuitTrait
/// - N plonky2 recursive proof verifiers
/// - the given OpsExecutorTrait
#[derive(Debug, Clone)]
pub struct RecursionTree<
    I: InnerCircuitTrait,
    O: OpsExecutorTrait,
    const M: usize,
    const N: usize,
    const NS: usize,
    const VL: usize,
> where
    [(); M + N]:,
{
    _i: PhantomData<I>,
    _o: PhantomData<O>,
}

impl<I, O, const M: usize, const N: usize, const NS: usize, const VL: usize>
    RecursionTree<I, O, M, N, NS, VL>
where
    I: InnerCircuitTrait,
    O: OpsExecutorTrait,
    [(); M + N]:,
{
    /// returns the full-recursive CircuitData
    pub fn circuit_data() -> Result<CircuitData<F, C, D>> {
        RecursionCircuit::<I, O, M, N, NS, VL>::circuit_data()
    }

    pub fn prepare_public_inputs(
        verifier_data: VerifierCircuitData<F, C, D>,
        public_inputs: Vec<F>,
    ) -> Vec<F> {
        RecursionCircuit::<I, O, M, N, NS, VL>::prepare_public_inputs(verifier_data, public_inputs)
    }

    pub fn prove_node(
        prover: &ProverCircuitData<F, C, D>,
        circuit: &mut RecursionCircuit<I, O, M, N, NS, VL>,
        selectors: [F; M + N],
        inner_circuits_input: [I::Input; M],
        ops_executor_input: O::Input,
        ops_executor_output: O::Output,
        recursive_proofs: &[PlonkyProof; N],
    ) -> Result<PlonkyProof> {
        println!("prove_node:");
        for i in 0..M + N {
            let what = if i < M { "inner circuit" } else { "proof" };
            if selectors[i].is_nonzero() {
                println!("  (selectors[{}] enabled), verify {}", i, what);
            } else {
                println!("  (selectors[{}] disabled), skip {}", i, what);
            }
        }

        // fill the targets
        let mut pw = PartialWitness::new();
        let start = Instant::now();
        circuit.set_targets(
            &mut pw,
            selectors,
            inner_circuits_input,
            ops_executor_input,
            ops_executor_output,
            recursive_proofs,
        )?;
        println!("circuit.set_targets(): {:?}", start.elapsed());

        let start = Instant::now();
        let new_proof = prover.prove(pw)?;
        println!("generate new_proof: {:?}", start.elapsed());

        Ok(new_proof.proof)
    }
}

/// RecursionCircuit defines the circuit used on each node of the recursion tree, which is doing
/// `(InnerCircuit OR recursive-proof-verification)` N times, and generating a new proof that can
/// be verified by the same circuit itself.
///
/// It contains the methods to `add_targets` (ie. create the targets, the logic of the circuit),
/// and `set_targets` (ie. set the specific values to be used for the previously created targets).
///
/// I: InnerCircuitTrait
/// O: OpsExecutorTrait
/// M: number of InnerCircuits per recursive step
/// N: number of plonky2 proofs per recursive step
pub struct RecursionCircuit<
    I: InnerCircuitTrait,
    O: OpsExecutorTrait,
    const M: usize,
    const N: usize,
    const NS: usize,
    const VL: usize,
> where
    [(); M + N]:,
{
    selectors_targ: [Target; M + N],
    inner_circuit_targ: [I::Targets; M],
    ops_executor_targ: O::Targets,
    proofs_targ: [ProofWithPublicInputsTarget<D>; N],
    // the next two are common for all the given proofs. It is the data for this circuit itself
    // (cyclic circuit).
    verifier_data_targ: VerifierCircuitTarget,
    verifier_data: VerifierCircuitData<F, C, D>,
}

impl<I, O, const M: usize, const N: usize, const NS: usize, const VL: usize>
    RecursionCircuit<I, O, M, N, NS, VL>
where
    I: InnerCircuitTrait,
    O: OpsExecutorTrait,
    [(); M + N]:,
{
    /// returns the full-recursive CircuitData
    pub fn circuit_data() -> Result<CircuitData<F, C, D>> {
        let mut data = common_data_for_recursion::<I, O, M, N, NS, VL>()?;

        // build the actual RecursionCircuit circuit data
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::new(config);
        let _ = Self::add_targets(&mut builder, data.verifier_data())?;
        data = builder.build::<C>();

        Ok(data)
    }

    /// returns ProverCircuitData
    pub fn build_prover(
        verifier_data: VerifierCircuitData<F, C, D>,
    ) -> Result<ProverCircuitData<F, C, D>> {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::new(config);

        let _ = Self::add_targets(&mut builder, verifier_data.clone())?;

        Ok(builder.build_prover::<C>())
    }

    pub fn dummy_proof(circuit_data: CircuitData<F, C, D>) -> PlonkyProof {
        let verifier_data = circuit_data.verifier_data();
        let dummy_proof_pis = cyclic_base_proof(
            &circuit_data.common,
            &verifier_data.verifier_only,
            HashMap::new(),
        );
        dummy_proof_pis.proof
    }

    pub fn prepare_public_inputs(
        verifier_data: VerifierCircuitData<F, C, D>,
        public_inputs: Vec<F>,
    ) -> Vec<F> {
        [
            public_inputs,
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

        let inner_circuit_targ: [I::Targets; M] =
            array::try_from_fn(|i| I::add_targets(builder, &selectors_bool_targ[i]))?;

        let ops_executor_targ: O::Targets = O::add_targets(builder)?;

        // proof verification:

        let common_data = verifier_data.common.clone();

        let verifier_data_targ = builder.add_verifier_data_public_inputs();

        let proofs_targ: Result<[ProofWithPublicInputsTarget<D>; N]> = array::try_from_fn(|i| {
            let proof_targ = builder.add_virtual_proof_with_pis(&common_data);
            builder.conditionally_verify_cyclic_proof_or_dummy::<C>(
                selectors_bool_targ[M + i],
                &proof_targ,
                &common_data,
            )?;
            Ok(proof_targ)
        });
        let proofs_targ = proofs_targ?;

        Ok(Self {
            selectors_targ,
            inner_circuit_targ,
            ops_executor_targ,
            proofs_targ,
            verifier_data_targ,
            verifier_data,
        })
    }

    pub fn set_targets(
        &mut self,
        pw: &mut PartialWitness<F>,
        // the first M selectors correspond to the M InnerCircuits, and the following N selectors
        // correspond to the N PlonkyProofs verifications. If the selector is set to 1, it enables
        // the verification (either of the InnerCircuit or the Plonky2Proof verification).
        selectors: [F; M + N],
        inner_circuit_input: [I::Input; M],
        ops_executor_input: O::Input,
        ops_executor_output: O::Output, // public inputs
        recursive_proofs: &[PlonkyProof; N],
    ) -> Result<()> {
        for i in 0..(M + N) {
            pw.set_target(self.selectors_targ[i], selectors[i])?;
        }

        // set the InnerCircuit related values
        let mut ic_pubinp: Vec<Vec<F>> = vec![];
        for i in 0..M {
            ic_pubinp.push(I::set_targets(
                pw,
                &self.inner_circuit_targ[i],
                &inner_circuit_input[i],
            )?);
        }

        let oe_pubinp = O::set_targets(
            pw,
            &self.ops_executor_targ,
            &ops_executor_input,
            &ops_executor_output,
        )?;

        // set proof related values:

        // recursive proofs verification
        pw.set_verifier_data_target(&self.verifier_data_targ, &self.verifier_data.verifier_only)?;

        // join the public inputs from the InnerCircuits and the OpsExecutor
        let pubinp: Vec<F> = [ic_pubinp.into_iter().flatten().collect(), oe_pubinp].concat();
        // put together the public inputs with the verifier_data
        let public_inputs = Self::prepare_public_inputs(self.verifier_data.clone(), pubinp);
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

pub fn common_data_for_recursion<
    I: InnerCircuitTrait,
    O: OpsExecutorTrait,
    const M: usize,
    const N: usize,
    const NS: usize,
    const VL: usize,
>() -> Result<CircuitData<F, C, D>>
where
    [(); M + N]:,
{
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
    let data = builder.build::<C>();

    // 3rd
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config.clone());

    builder.add_gate(
        // add a ConstantGate, because without this, when later generating the `dummy_circuit`
        // (inside the `conditionally_verify_cyclic_proof_or_dummy`), it fails due the
        // `CommonCircuitData` of the generated circuit not matching the given `CommonCircuitData`
        // to create it. Without this it fails because it misses a ConstantGate.
        plonky2::gates::constant::ConstantGate::new(config.num_constants),
        vec![],
    );

    // add selectors and InnerCircuits targets
    for i in 0..(M + N) {
        let selector_F_targ = builder.add_virtual_target();
        binary_check(&mut builder, selector_F_targ);
        let b = BoolTarget::new_unsafe(selector_F_targ);
        // add targets of M InnerCircuits
        if i < M {
            let _ = I::add_targets(&mut builder, &b)?;
        }
    }
    // add the OpsExecutor targets
    let _: O::Targets = O::add_targets(&mut builder)?;

    // proofs verify
    let verifier_data = builder.add_verifier_data_public_inputs();
    // proofs
    for _ in 0..N {
        let proof = builder.add_virtual_proof_with_pis(&data.common);
        builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    }

    // pad min gates
    let n_gates = compute_num_gates::<N, NS, VL>()?;
    while builder.num_gates() < n_gates {
        builder.add_gate(NoopGate, vec![]);
    }
    Ok(builder.build::<C>())
}

// TODO: Take `VL` into account.
fn compute_num_gates<const N: usize, const NS: usize, const VL: usize>() -> Result<usize> {
    // Note: the following numbers are WIP, obtained by trial-error by running different
    // configurations in the tests.
    let n_gates = match N {
        0..=1 => 1 << 12,
        2 => {
            if NS < 9 {
                1 << 13
            } else {
                1 << 14
            }
        }
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

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2::field::types::{Field, Sample};
    use plonky2::plonk::proof::ProofWithPublicInputs;
    use rand;
    use std::array;
    use std::time::Instant;

    use super::*;

    use crate::recursion::traits_examples::{
        ExampleGadget, ExampleGadgetInput, ExampleOpsExecutor,
    };
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
        test_recursion_opt::<3, 2, 2, 0>()?; // <M, N, NS, VL>

        Ok(())
    }

    fn test_recursion_opt<const M: usize, const N: usize, const NS: usize, const VL: usize>(
    ) -> Result<()>
    where
        [(); M + N]:,
    {
        set_log();
        println!("\n--------------------------------------------------");
        println!("\n--------------------------------------------------");
        println!(
            "\nrunning test:\n===test_tree_recursion_opt with M={} (num InnerCircuits) N={} (arity of the recursion tree)",
            M, N
        );

        let l: u32 = 2; // levels of the recursion (binary) tree
        println!(
            "Testing {} recursive iterations, where each iteration checks M={} InnerCircuits and N={} plonky2 proofs",
            l, M, N
        );

        let mut rng: rand::rngs::ThreadRng = rand::thread_rng();
        let schnorr = SchnorrSigner::new();
        // generate M random messages, each of length 4
        let msg_vec: Vec<Vec<F>> = (0..M)
            .map(|_| {
                std::iter::repeat_with(|| F::sample(&mut rng))
                    .take(4)
                    .collect()
            })
            .collect();

        // generate M*N key pairs (M for each of the N recursive nodes at the base level)
        let sk_vec: Vec<SchnorrSecretKey> =
            (0..M).map(|i| SchnorrSecretKey { sk: i as u64 }).collect();
        let pk_vec: Vec<SchnorrPublicKey> = sk_vec.iter().map(|&sk| schnorr.keygen(&sk)).collect();

        // sign the messages
        let sig_vec: Vec<SchnorrSignature> = sk_vec
            .iter()
            .zip(msg_vec.clone())
            .map(|(&sk, msg)| schnorr.sign(&msg.to_vec(), &sk, &mut rng))
            .collect();
        assert_eq!(sig_vec.len(), M);

        type RC<const M: usize, const N: usize, const NS: usize, const VL: usize> =
            RecursionCircuit<ExampleGadget, ExampleOpsExecutor<1, VL>, M, N, NS, VL>;
        type RT<const M: usize, const N: usize, const NS: usize, const VL: usize> =
            RecursionTree<ExampleGadget, ExampleOpsExecutor<1, VL>, M, N, NS, VL>;

        // build the circuit_data & verifier_data for the recursive circuit
        let circuit_data = RC::<M, N, NS, VL>::circuit_data()?;
        let verifier_data = circuit_data.verifier_data();
        let prover = RC::<M, N, NS, VL>::build_prover(verifier_data.clone())?;

        let dummy_proof = RC::<M, N, NS, VL>::dummy_proof(circuit_data);

        // we start with k dummy proofs, since at the leafs level we don't have proofs yet and we
        // just verify the signatures. At each level we divide the amount of proofs by N. At the
        // root level there is a single proof.
        let mut proofs_at_level_i: Vec<PlonkyProof> = (0..(N * N))
            .map(|_| dummy_proof.clone())
            .collect();

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::new(config);
        let start = Instant::now();
        let mut circuit = RC::<M, N, NS, VL>::add_targets(&mut builder, verifier_data.clone())?;
        println!("RecursionCircuit::add_targets(): {:?}", start.elapsed());

        // loop over the recursion levels
        for i in 0..l {
            println!("\n--- recursion level i={}", i);
            let mut next_level_proofs: Vec<PlonkyProof> = vec![];

            // loop over the nodes of each recursion tree level
            for j in (0..proofs_at_level_i.len()).step_by(N) {
                println!(
                    "\n------ recursion node: (level) i={}, (node in level) j={}",
                    i, j
                );

                // prepare the inputs for the `RecursionTree::prove_node` call
                let mut selectors: [F; M + N] = [F::ONE; M + N];
                if i == 0 {
                    // if we're at the base level, set to 0 (=disable) the N selectors of the
                    // proofs verifications
                    selectors[M..M + N].fill(F::ZERO);
                }
                let innercircuits_input: [ExampleGadgetInput; M] =
                    array::from_fn(|k| ExampleGadgetInput {
                        pk: pk_vec[k],
                        sig: sig_vec[k],
                        msg: msg_vec[k].clone(),
                    });
                // let ops_executor_input = array::from_fn(|_| ());
                let ops_executor_input = ();
                let ops_executor_output = ();
                let proofs: [PlonkyProof; N] = array::from_fn(|k| proofs_at_level_i[j + k].clone());

                // do the recursive step
                let start = Instant::now();
                let new_proof = RT::<M, N, NS, VL>::prove_node(
                    &prover,
                    &mut circuit,
                    selectors,
                    innercircuits_input,
                    ops_executor_input,
                    ops_executor_output,
                    &proofs,
                )?;
                println!(
                    "RecursionTree::prove_node (level: i={}, node: j={}) took: {:?}",
                    i,
                    j,
                    start.elapsed()
                );

                // verify the recursive proof
                let public_inputs =
                    RT::<M, N, NS, VL>::prepare_public_inputs(verifier_data.clone(), vec![]);
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
        let public_inputs =
            RT::<M, N, NS, VL>::prepare_public_inputs(verifier_data.clone(), vec![]);
        verifier_data.clone().verify(ProofWithPublicInputs {
            proof: last_proof.clone(),
            public_inputs: public_inputs.clone(),
        })?;

        Ok(())
    }
}
