/*
 N-arity tree of recursion, which at each recursive node it also verifies L POD1-Introducer proofs
 and M InnerCircuits.

                      π_root
                       ▲
        ┌──────────────┴───────────────────┐
        │              F                   │
        └──────────────────────────────────┘
         ▲ ▲           ▲             ▲  ▲
  ┌──────┘┌┘           │             │  │
  │       │            │             │  └──┐
c''_1...c''_M          │π''_1        │     │π''_N
             ┌─────────┴─────────┐   │    ┌┴───────────────────┐
             │         F         │ (...)  │         F          │
             └───────────────────┘        └────────────────────┘
              ▲ ▲    ▲  ▲    ▲  ▲           ▲ ▲    ▲  ▲    ▲  ▲
          ┌───┘┌┘   ┌┘  └┐   └┐ └──┐    ┌───┘┌┘   ┌┘  └┐   └┐ └──┐
          │    │    │    │    │    │    │    │    │    │    │    │
         p_1..p_L  c_1..c_M  π_1..π_N  p_1..p_L  c_1..c_M  π_1..π_N

 where
 - each p_i is a POD1-Introducer plonky2 proof
 - each c_i is an InnerCircuit
 - each π_i is a plonky2 proof
 and each of them is enabled/disabled by a selector s_i.


 There are L POD1-Introducer plonky2 proofs verifications, M InnerCircuit verifications, and N
 plonky2 full-recursive proofs verifications. Enalbed/disabled by the L+M+N selectors.

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

pub trait RecursionConfig {
    const L: usize;
    const M: usize;
    const N: usize;
    const NS: usize;
    const VL: usize;
}
pub struct DefaultRC {}
impl RecursionConfig for DefaultRC {
    const L: usize = 0;
    const M: usize = 2;
    const N: usize = 2;
    const NS: usize = 10;
    const VL: usize = 10;
}

/// RecursionTree defines the tree, where each recursive node executes
/// - L POD1-Introducer proof verifiers
/// - M InnerCircuitTrait
/// - N plonky2 recursive proof verifiers
/// - the given OpsExecutorTrait
#[derive(Debug, Clone)]
pub struct RecursionTree<I: InnerCircuitTrait, O: OpsExecutorTrait, RC: RecursionConfig>
where
    [(); RC::L + RC::M + RC::N]:,
{
    _i: PhantomData<I>,
    _o: PhantomData<O>,
    _rc: PhantomData<RC>,
}

impl<I, O, RC> RecursionTree<I, O, RC>
where
    I: InnerCircuitTrait,
    O: OpsExecutorTrait,
    RC: RecursionConfig,
    [(); RC::L + RC::M + RC::N]:,
    [(); RC::L + RC::N]:,
{
    /// returns the full-recursive CircuitData
    pub fn circuit_data(
        pod1_verifier_data: VerifierCircuitData<F, C, D>,
    ) -> Result<CircuitData<F, C, D>> {
        RecursionCircuit::<I, O, RC>::circuit_data(pod1_verifier_data)
    }

    pub fn prepare_public_inputs(
        public_inputs: Vec<F>,
        verifier_data: VerifierCircuitData<F, C, D>,
    ) -> Vec<F> {
        RecursionCircuit::<I, O, RC>::prepare_public_inputs(public_inputs, verifier_data)
    }

    pub fn prove_node(
        prover: &ProverCircuitData<F, C, D>,
        circuit: &mut RecursionCircuit<I, O, RC>,
        selectors: [F; RC::L + RC::M + RC::N],
        ops_executor_input: O::Input,
        ops_executor_output: O::Output,
        // pod1's public inputs needed to verify pod1's proof, not public inputs in the current
        // RecursiveCircuit
        pod1_public_inputs: &[Vec<F>; RC::L],
        pod1_proofs: &[PlonkyProof; RC::L],
        inner_circuits_input: [I::Input; RC::M],
        recursive_proofs: &[PlonkyProof; RC::N],
    ) -> Result<PlonkyProof> {
        println!("prove_node with L={}, M={}, N={}:", RC::L, RC::M, RC::N);
        for i in 0..RC::L + RC::M + RC::N {
            let what = if i < RC::L {
                "pod1 proof"
            } else if i >= RC::L && i < RC::L + RC::M {
                "inner circuit"
            } else if i >= RC::L + RC::M && i < RC::L + RC::M + RC::N {
                "recursive proof"
            } else {
                "unknown"
            };
            // let what = match i {
            //     0..L => "pod1 proof",
            //     L..(L+M) => "inner circuit",
            //     (L+M)..(L+M+N) => "recursive proof",
            //     _ => "unknown",
            // };
            let action = if selectors[i].is_nonzero() {
                "verify"
            } else {
                "skip"
            };
            println!("  (selectors[{}]={}), {} {}", i, selectors[i], action, what);
        }

        // fill the targets
        let mut pw = PartialWitness::new();
        let start = Instant::now();
        circuit.set_targets(
            &mut pw,
            selectors,
            ops_executor_input,
            ops_executor_output,
            pod1_public_inputs,
            pod1_proofs,
            inner_circuits_input,
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
/// O: OpsExecutorTrait
/// L: number of pod1-proofs per recursive step
/// M: number of InnerCircuits per recursive step
/// N: number of plonky2 proofs per recursive step
pub struct RecursionCircuit<I: InnerCircuitTrait, O: OpsExecutorTrait, RC: RecursionConfig>
where
    [(); RC::L + RC::M + RC::N]:,
{
    selectors_targ: [Target; RC::L + RC::M + RC::N],
    ops_executor_targ: O::Targets,
    pod1_proofs_targ: [ProofWithPublicInputsTarget<D>; RC::L],
    inner_circuit_targ: [I::Targets; RC::M],
    proofs_targ: [ProofWithPublicInputsTarget<D>; RC::N],
    // the next parameters are common for all the given proofs.
    // 1-level-recursion params (pod1 translator verifier):
    pod1_verifier_data_targ: VerifierCircuitTarget, // TODO naming: introducer proof
    pod1_verifier_data: VerifierCircuitData<F, C, D>,
    // cyclic-recursion params:
    // It is the data for this circuit
    // itself (cyclic circuit).
    verifier_data_targ: VerifierCircuitTarget,
    verifier_data: VerifierCircuitData<F, C, D>,
}

impl<I, O, RC: RecursionConfig> RecursionCircuit<I, O, RC>
where
    I: InnerCircuitTrait,
    O: OpsExecutorTrait,
    [(); RC::L + RC::M + RC::N]:,
    [(); RC::L + RC::N]:,
{
    /// returns the full-recursive CircuitData
    pub fn circuit_data(
        pod1_verifier_data: VerifierCircuitData<F, C, D>,
    ) -> Result<CircuitData<F, C, D>> {
        let mut data = common_data_for_recursion::<I, O, RC>()?;

        // build the actual RecursionCircuit circuit data
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::new(config);

        let _ = Self::add_targets(&mut builder, pod1_verifier_data, data.verifier_data())?;
        data = builder.build::<C>();

        Ok(data)
    }

    /// returns ProverCircuitData
    pub fn build_prover(
        pod1_verifier_data: VerifierCircuitData<F, C, D>,
        verifier_data: VerifierCircuitData<F, C, D>,
    ) -> Result<ProverCircuitData<F, C, D>> {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::new(config);

        let _ = Self::add_targets(&mut builder, pod1_verifier_data, verifier_data.clone())?;

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

    // notice that this method is used to prepare the public inputs for both the
    // 1-level-recursion-verification (used for the POD1-Introducer verification) and the
    // cyclic-recursion-verification
    pub fn prepare_public_inputs(
        public_inputs: Vec<F>,
        verifier_data: VerifierCircuitData<F, C, D>,
    ) -> Vec<F> {
        [
            public_inputs,
            // add verifier_data
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
        // pod1 circuit verifier_data
        pod1_verifier_data: VerifierCircuitData<F, C, D>,
        // self's verifier_data
        verifier_data: VerifierCircuitData<F, C, D>,
    ) -> Result<Self> {
        // build the InnerCircuit logic. Also set the selectors, used both by the InnerCircuit and
        // by the recursive proofs verifications.
        let selectors_targ: [Target; RC::L + RC::M + RC::N] = array::from_fn(|_| {
            let selector_F_targ = builder.add_virtual_target();
            // ensure that selector_booltarg is \in {0,1}
            binary_check(builder, selector_F_targ);
            selector_F_targ
        });
        let selectors_bool_targ: [BoolTarget; RC::L + RC::M + RC::N] =
            array::from_fn(|i| BoolTarget::new_unsafe(selectors_targ[i]));

        let ops_executor_targ: O::Targets = O::add_targets(builder)?;

        // Notice: pod1 recursive verification is only 1-level-depth recursion, whereas the other
        // proof verification is infinity-levels-depth recursion (cyclic recursion).

        // pod1 proof verification
        let pod1_common_data = pod1_verifier_data.common.clone();

        // notice that pod1_verifier_data is not registered as public input, while the
        // cyclic-recursive verifier_data is registered as public input.
        let pod1_verifier_data_targ = builder
            .add_virtual_verifier_data(pod1_verifier_data.common.config.fri_config.cap_height);

        let pod1_proofs_targ: Result<[ProofWithPublicInputsTarget<D>; RC::L]> =
            array::try_from_fn(|i| {
                let pod1_proof_targ = builder.add_virtual_proof_with_pis(&pod1_common_data);
                // let pod1_proof_targ = builder.add_virtual_proof(&pod1_common_data);
                builder.conditionally_verify_proof_or_dummy::<C>(
                    selectors_bool_targ[i],
                    &pod1_proof_targ,
                    &pod1_verifier_data_targ,
                    &pod1_common_data,
                )?;
                Ok(pod1_proof_targ)
            });
        let pod1_proofs_targ = pod1_proofs_targ?;

        // InnerCircuits logic
        let inner_circuit_targ: [I::Targets; RC::M] =
            array::try_from_fn(|i| I::add_targets(builder, &selectors_bool_targ[RC::L + i]))?;

        // proof verification:

        let common_data = verifier_data.common.clone();
        let verifier_data_targ = builder.add_verifier_data_public_inputs();

        let proofs_targ: Result<[ProofWithPublicInputsTarget<D>; RC::N]> =
            array::try_from_fn(|i| {
                let proof_targ = builder.add_virtual_proof_with_pis(&common_data);
                builder.conditionally_verify_cyclic_proof_or_dummy::<C>(
                    selectors_bool_targ[RC::L + RC::M + i],
                    &proof_targ,
                    &common_data,
                )?;
                Ok(proof_targ)
            });
        let proofs_targ = proofs_targ?;

        Ok(Self {
            selectors_targ,
            ops_executor_targ,
            pod1_proofs_targ,
            inner_circuit_targ,
            proofs_targ,
            pod1_verifier_data_targ,
            pod1_verifier_data,
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
        selectors: [F; RC::L + RC::M + RC::N],
        ops_executor_input: O::Input,
        ops_executor_output: O::Output, // public inputs

        // notice that the pod1_public_inputs are not the public
        // inputs for the current RecursiveCircuit, but the public
        // inputs used to verify (inside the RecursiveCircuit) the
        // POD1-Introducer plonky2 proof.
        pod1_public_inputs: &[Vec<F>; RC::L],
        pod1_recursive_proofs: &[PlonkyProof; RC::L],
        inner_circuit_input: [I::Input; RC::M],
        recursive_proofs: &[PlonkyProof; RC::N],
    ) -> Result<()> {
        for i in 0..(RC::L + RC::M + RC::N) {
            pw.set_target(self.selectors_targ[i], selectors[i])?;
        }

        // set the OpExecutor related values, and get it's public inputs
        let oe_pubinp: Vec<F> = O::set_targets(
            pw,
            &self.ops_executor_targ,
            &ops_executor_input,
            &ops_executor_output,
        )?;

        // set proof related values:

        // pod1 proof verification
        pw.set_verifier_data_target(
            &self.pod1_verifier_data_targ,
            &self.pod1_verifier_data.verifier_only,
        )?;
        for i in 0..RC::L {
            // put together the public inputs with the verifier_data
            // let pub_inp = Self::prepare_public_inputs(vec![], self.pod1_verifier_data.clone());
            // Self::prepare_public_inputs(pod1_public_inputs[i], self.pod1_verifier_data.clone());
            pw.set_proof_with_pis_target(
                &self.pod1_proofs_targ[i],
                &ProofWithPublicInputs {
                    proof: pod1_recursive_proofs[i].clone(),
                    // public_inputs: pod1_public_inputs[i].clone(),
                    public_inputs: vec![],
                },
            )?;
            // pw.set_proof_target(&self.pod1_proofs_targ[i], pod1_recursive_proofs[i].clone())?;
        }

        // set the InnerCircuit related values
        let mut ic_pubinp: Vec<Vec<F>> = vec![];
        for i in 0..RC::M {
            ic_pubinp.push(I::set_targets(
                pw,
                &self.inner_circuit_targ[i],
                &inner_circuit_input[i],
            )?);
        }

        // recursive proofs verification
        pw.set_verifier_data_target(&self.verifier_data_targ, &self.verifier_data.verifier_only)?;

        // join the public inputs from the InnerCircuits and the OpsExecutor
        let pubinp: Vec<F> = [ic_pubinp.into_iter().flatten().collect(), oe_pubinp].concat();
        // put together the public inputs with the verifier_data
        let public_inputs = Self::prepare_public_inputs(pubinp, self.verifier_data.clone());
        for i in 0..RC::N {
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

pub fn common_data_for_recursion<I: InnerCircuitTrait, O: OpsExecutorTrait, RC: RecursionConfig>(
) -> Result<CircuitData<F, C, D>>
where
    [(); RC::L + RC::M + RC::N]:,
    [(); RC::L + RC::N]:,
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
    for _ in 0..RC::N {
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
    for i in 0..(RC::M + RC::N) {
        let selector_F_targ = builder.add_virtual_target();
        binary_check(&mut builder, selector_F_targ);
        let b = BoolTarget::new_unsafe(selector_F_targ);
        // add targets of M InnerCircuits
        if i < RC::M {
            let _ = I::add_targets(&mut builder, &b)?;
        }
    }
    // add the OpsExecutor targets
    let _: O::Targets = O::add_targets(&mut builder)?;

    // pod1 proofs // TODO group with N in a single loop
    let pod1_verifier_data =
        builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    for _ in 0..RC::L {
        let proof = builder.add_virtual_proof_with_pis(&data.common);
        builder.verify_proof::<C>(&proof, &pod1_verifier_data, &data.common);
    }
    // proofs
    let verifier_data = builder.add_verifier_data_public_inputs();
    for _ in 0..RC::N {
        let proof = builder.add_virtual_proof_with_pis(&data.common);
        builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    }

    // pad min gates
    let n_gates = compute_num_gates::<RC>()?;
    while builder.num_gates() < n_gates {
        builder.add_gate(NoopGate, vec![]);
    }
    Ok(builder.build::<C>())
}

// TODO: Take `VL` into account.
fn compute_num_gates<RC: RecursionConfig>() -> Result<usize>
where
    [(); RC::L + RC::N]:,
{
    // Note: the following numbers are WIP, obtained by trial-error by running different
    // configurations in the tests.
    let n_gates = match RC::L + RC::N {
        0..=1 => 1 << 12,
        2 => {
            if RC::NS < 9 {
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
            "arity of L+N={} not supported yet. Currently supported L+N from 1 to 6 (both included)",
            RC::L+RC::N
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

    use crate::recursion::traits::IntroducerCircuitTrait;
    use crate::recursion::traits_examples::{
        ExampleGadget, ExampleGadgetInput, ExampleIntroducer, ExampleOpsExecutor,
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
        struct TestRC {}
        impl RecursionConfig for TestRC {
            const L: usize = 1;
            const M: usize = 3;
            const N: usize = 1;
            const NS: usize = 2;
            const VL: usize = 0;
        }

        test_recursion_opt::<TestRC>()?;

        Ok(())
    }

    fn test_recursion_opt<RC: RecursionConfig>() -> Result<()>
    where
        [(); RC::L + RC::M + RC::N]:,
        [(); RC::L + RC::N]:,
        [(); RC::VL]:,
    {
        set_log();
        println!("\n--------------------------------------------------");
        println!("\n--------------------------------------------------");
        println!(
            "\nrunning test:\n===test_tree_recursion_opt with L={} (num POD1-Introducer proofs) M={} (num InnerCircuits) N={} (arity of the recursion tree)",
            RC::L, RC::M, RC::N
        );

        let l: u32 = 2; // levels of the recursion (binary) tree
        println!(
            "Testing {} recursive iterations, where each iteration checks:\n    L={} POD1-Introducer plonky2 proofs\n    M={} InnerCircuits\n    N={} cyclic plonky2 proofs",
            l, RC::L, RC::M, RC::N
        );

        let mut rng: rand::rngs::ThreadRng = rand::thread_rng();
        let schnorr = SchnorrSigner::new();
        // generate M random messages, each of length 4
        let msg_vec: Vec<Vec<F>> = (0..RC::M)
            .map(|_| {
                std::iter::repeat_with(|| F::sample(&mut rng))
                    .take(4)
                    .collect()
            })
            .collect();

        // generate M*N key pairs (M for each of the N recursive nodes at the base level)
        let sk_vec: Vec<SchnorrSecretKey> = (0..RC::M)
            .map(|i| SchnorrSecretKey { sk: i as u64 })
            .collect();
        let pk_vec: Vec<SchnorrPublicKey> = sk_vec.iter().map(|&sk| schnorr.keygen(&sk)).collect();

        // sign the messages
        let sig_vec: Vec<SchnorrSignature> = sk_vec
            .iter()
            .zip(msg_vec.clone())
            .map(|(&sk, msg)| schnorr.sign(&msg.to_vec(), &sk, &mut rng))
            .collect();
        assert_eq!(sig_vec.len(), RC::M);

        // POD1 introducer logic:
        let pod1_circuit_data = ExampleIntroducer::circuit_data()?;
        let pod1_verifier_data = pod1_circuit_data.verifier_data();
        let pod1_dummy_proof: PlonkyProof = ExampleIntroducer::dummy_proof(pod1_circuit_data)?;
        let pod1_proofs: [PlonkyProof; RC::L] = array::from_fn(|_| pod1_dummy_proof.clone());
        let pod1_public_inputs: [Vec<F>; RC::L] = array::from_fn(|_| vec![]);

        type RCircuit<RC: RecursionConfig> =
            RecursionCircuit<ExampleGadget, ExampleOpsExecutor<1, { RC::VL }>, RC>;
        type RT<RC: RecursionConfig> =
            RecursionTree<ExampleGadget, ExampleOpsExecutor<1, { RC::VL }>, RC>;

        // build the circuit_data & verifier_data for the recursive circuit
        let circuit_data = RCircuit::<RC>::circuit_data(pod1_verifier_data.clone())?;
        let verifier_data = circuit_data.verifier_data();
        let prover =
            RCircuit::<RC>::build_prover(pod1_verifier_data.clone(), verifier_data.clone())?;

        let dummy_proof = RCircuit::<RC>::dummy_proof(circuit_data);

        // we start with k dummy proofs, since at the leafs level we don't have proofs yet and we
        // just verify the signatures. At each level we divide the amount of proofs by N. At the
        // root level there is a single proof.
        let mut proofs_at_level_i: Vec<PlonkyProof> =
            (0..(RC::N * RC::N)).map(|_| dummy_proof.clone()).collect();

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::new(config);
        let start = Instant::now();
        let mut circuit = RCircuit::<RC>::add_targets(
            &mut builder,
            pod1_verifier_data.clone(),
            verifier_data.clone(),
        )?;
        println!("RecursionCircuit::add_targets(): {:?}", start.elapsed());

        // loop over the recursion levels
        for i in 0..l {
            println!("\n--- recursion level i={}", i);
            let mut next_level_proofs: Vec<PlonkyProof> = vec![];

            // loop over the nodes of each recursion tree level
            for j in (0..proofs_at_level_i.len()).step_by(RC::N) {
                println!(
                    "\n------ recursion node: (level) i={}, (node in level) j={}",
                    i, j
                );

                // prepare the inputs for the `RecursionTree::prove_node` call
                let mut selectors: [F; RC::L + RC::M + RC::N] = [F::ONE; RC::L + RC::M + RC::N];
                if i == 0 {
                    // if we're at the base level, set to 0 (=disable) the L & N selectors of the
                    // proofs verifications
                    selectors[0..RC::L].fill(F::ZERO); // pod1 proof verifications
                    selectors[RC::L + RC::M..RC::L + RC::M + RC::N].fill(F::ZERO);
                    // recursive proof verifications
                }
                let innercircuits_input: [ExampleGadgetInput; RC::M] =
                    array::from_fn(|k| ExampleGadgetInput {
                        pk: pk_vec[k],
                        sig: sig_vec[k],
                        msg: msg_vec[k].clone(),
                    });
                // let ops_executor_input = array::from_fn(|_| ());
                let ops_executor_input = ();
                let ops_executor_output = ();

                // let pod1_proofs: [PlonkyProof; M] = array::from_fn(|k| pod1_proofs[j + k].clone());
                let proofs: [PlonkyProof; RC::N] =
                    array::from_fn(|k| proofs_at_level_i[j + k].clone());

                // do the recursive step
                let start = Instant::now();
                let new_proof = RT::<RC>::prove_node(
                    &prover,
                    &mut circuit,
                    selectors,
                    ops_executor_input,
                    ops_executor_output,
                    &pod1_public_inputs,
                    &pod1_proofs,
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
                let public_inputs = RT::<RC>::prepare_public_inputs(vec![], verifier_data.clone());
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
        let public_inputs = RT::<RC>::prepare_public_inputs(vec![], verifier_data.clone());
        verifier_data.clone().verify(ProofWithPublicInputs {
            proof: last_proof.clone(),
            public_inputs: public_inputs.clone(),
        })?;

        Ok(())
    }
}
