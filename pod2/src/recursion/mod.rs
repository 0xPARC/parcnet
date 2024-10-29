/*
 N-arity tree of recursion with conditionals.

                   p_root
                   ▲
                   │
               ┌────────┐
               │   F    │
               └────────┘
                ▲ ▲  ▲ ▲
              ┌─┘ │  │ └─┐
         ┌────┘ ┌─┘  └┐  └───┐
         │      │ ... │      │
     ┌────────┐┌┴┐┌─┐┌┴┐ ┌────────┐
     │   F    ││.││.││.│ │   F    │
     └────────┘└─┘└─┘└─┘ └────────┘
     ▲ ▲  ▲  ▲            ▲ ▲  ▲  ▲
   ┌─┘ │  └┐ └─┐        ┌─┘┌┘  └┐ └┐
   │   │   │   │        │  │    │  │
  p_1 p_2 ... p_n     p'_1 p'_2... p'_n


 where each p_i is either
    - InnerCircuit verification
    - recursive plonky2 proof (proof that verifies previous proof)
            (generated by `RecursiveCircuit::prove_step` method)
 in other words, each p_i is checking:
   `(InnerCircuit OR recursive proof verify)`

 Each node of the recursion tree, ie. each F, verifies the N incoming p_i's, that is
   `(InnerCircuit OR recursive proof verify) AND ... AND (InnerCircuit OR recursive proof verify)`
 and produces a new proof.

 For example, if N is set to N=2, then we work with a binary recursion tree:
           p_root
            ▲
            │
          ┌─┴─┐
          │ F │
          └───┘
           ▲ ▲
         ┌─┘ └─┐
     ┌───┘     └───┐
     │p_5          │p_6
   ┌─┴─┐         ┌─┴─┐
   │ F │         │ F │
   └───┘         └───┘
    ▲ ▲           ▲ ▲
  ┌─┘ └─┐       ┌─┘ └─┐
  │     │       │     │
 p_1   p_2     p_3   p_4

 p_i: `(InnerCircuit OR recursive-proof-verification)`


 So that each node (F box) is verifying 2 p_i's, ie:
   `(InnerCircuit OR recursive-proof-verification) AND (InnerCircuit OR recursive-proof-verification)`


 With N=3, each node will be verifying 3 p_i's.
   `(InnerCircuit OR recursive-proof-verification) AND (InnerCircuit OR recursive-proof-verification) AND (InnerCircuit OR recursive-proof-verification)`



 Also, notice that if we set N=1, it is directly a linear chain of recursive proofs ('tree' of
 arity 1):
        ┌─┐     ┌─┐     ┌─┐     ┌─┐
  ─────►│F├────►│F├────►│F├────►│F├────►
   p_1  └─┘ p_2 └─┘ p_3 └─┘ p_4 └─┘ p_5

 where each p_i is proving: `(InnerCircuit OR recursive-proof-verification)`.






  Where each F is the following circuit:

                           ┌─────────────────────────────────────┐
                           │    ┌───────────────────────────┐    │
                           │    │                           │    │
  inner-circuit inputs─────┼───►│     InnerCircuit logic    │    │
                           │    │                           │    │
                           │    └───────────────────────────┘    │
                           │                  OR                 │──────► new recursive
                           │ ┌────────────────────────────────┐  │           proof
                           │ │                                │  │
   previous recursive──────┼►│  Recursive proof verification  │  │
         proof             │ │                                │  │
                           │ └────────────────────────────────┘  │
                           └─────────────────────────────────────┘


 To run the tests that checks this logic:
 cargo test --release test_tree_recursion -- --nocapture
*/
use anyhow::{anyhow, Result};
use plonky2::field::types::Field;
use plonky2::gates::noop::NoopGate;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CircuitData, VerifierCircuitData, VerifierCircuitTarget,
};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use std::marker::PhantomData;
use std::time::Instant;

use crate::signature::schnorr_prover::MessageTarget;
use crate::{PlonkyProof, C, D, F};

mod example_innercircuit;

/// if s==0: returns x
/// if s==1: returns y
/// Warning: this method assumes all input values are ensured to be \in {0,1}
pub fn selector_gate(
    builder: &mut CircuitBuilder<F, D>,
    x: Target,
    y: Target,
    s: Target,
) -> Target {
    // z = x + s(y-x)
    let y_x = builder.sub(y, x);
    // z = x+s(y-x) <==> mul_add(s, yx, x)=s*(y-x)+x
    builder.mul_add(s, y_x, x)
}

/// ensures b \in {0,1}
pub fn binary_check(builder: &mut CircuitBuilder<F, D>, b: Target) {
    let zero = builder.zero();
    let one = builder.one();
    // b * (b-1) == 0
    let b_1 = builder.sub(b, one);
    let r = builder.mul(b, b_1);
    builder.connect(r, zero);
}

/// InnerCircuit is the trait that is used to define the logic of the circuit that is used at each
/// node of the recursive tree.
pub trait InnerCircuit {
    type Input;
    type Targets;

    // set up the circuit logic
    fn add_targets(
        builder: &mut CircuitBuilder<F, D>,
        selector_booltarg: &BoolTarget,
        msg_targ: &MessageTarget,
    ) -> Result<Self::Targets>;

    // set the actual witness values for the current instance of the circuit
    fn set_targets(
        pw: &mut PartialWitness<F>,
        targets: &Self::Targets,
        input: &Self::Input,
    ) -> Result<()>;
}

/// RecursiveCircuit defines the circuit used on each node of the recursion tree, which is doing
/// `(InnerCircuit OR recursive-proof-verification)` N times, and generating a new proof that can
/// be verified by the same circuit itself.
///
/// It contains the methods to `add_targets` (ie. create the targets, the logic of the circuit),
/// and `set_targets` (ie. set the specific values to be used for the previously created targets).
///
/// I: InnerCircuit
/// M: msg length. The upper-bound of the msg length.
/// N: arity of the recursion tree, ie. how many `(InnerCircuit OR recursive-proof-verify)` each
/// node of the recursion tree is checking.
pub struct RecursiveCircuit<I: InnerCircuit, const M: usize, const N: usize> {
    msgs_targ: Vec<MessageTarget>,
    selectors_targ: Vec<Target>,
    inner_circuit_targ: Vec<I::Targets>,
    proofs_targ: Vec<ProofWithPublicInputsTarget<D>>,
    // the next two are common for all the given proofs. It is the data for this circuit itself
    // (cyclic circuit).
    verifier_data_targ: VerifierCircuitTarget,
    verifier_data: VerifierCircuitData<F, C, D>,
}

impl<I: InnerCircuit, const M: usize, const N: usize> RecursiveCircuit<I, M, N> {
    pub fn prepare_public_inputs(
        verifier_data: VerifierCircuitData<F, C, D>,
        msgs: Vec<Vec<F>>,
    ) -> Vec<F> {
        [
            msgs.into_iter().flatten().collect(),
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
        let mut msgs_targ: Vec<MessageTarget> = vec![];
        for _ in 0..N {
            let msg_targ = MessageTarget::new_with_size(builder, M);
            // set msg as public input
            builder.register_public_inputs(&msg_targ.msg);
            msgs_targ.push(msg_targ);
        }

        // build the InnerCircuit logic. Also set the selectors, used both by the InnerCircuit and
        // by the recursive proofs verifications.
        let mut selectors_targ: Vec<Target> = vec![];
        let mut selectors_bool_targ: Vec<BoolTarget> = vec![];
        let mut inner_circuit_targ: Vec<I::Targets> = vec![];
        for i in 0..N {
            // selectors:
            let selector_F_targ = builder.add_virtual_target();
            // ensure that selector_booltarg is \in {0,1}
            binary_check(builder, selector_F_targ);
            let selector_bool_targ = BoolTarget::new_unsafe(selector_F_targ);
            selectors_targ.push(selector_F_targ);
            selectors_bool_targ.push(selector_bool_targ);

            // inner circuits:
            let inner_circuit_targets =
                I::add_targets(builder, &selector_bool_targ, &msgs_targ[i])?;
            inner_circuit_targ.push(inner_circuit_targets);
        }

        // proof verification:

        let common_data = verifier_data.common.clone();
        let verifier_data_targ = builder.add_verifier_data_public_inputs();

        let mut proofs_targ: Vec<ProofWithPublicInputsTarget<D>> = vec![];
        for i in 0..N {
            let proof_targ = builder.add_virtual_proof_with_pis(&common_data);
            builder.conditionally_verify_cyclic_proof_or_dummy::<C>(
                selectors_bool_targ[i],
                &proof_targ,
                &common_data,
            )?;
            proofs_targ.push(proof_targ);
        }

        Ok(Self {
            msgs_targ,
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
        msgs: &Vec<Vec<F>>,
        // if selectors[i]==0: verify InnerCircuit. if selectors[i]==1: verify recursive_proof[i]
        selectors: Vec<F>,
        inner_circuit_input: Vec<I::Input>,
        recursive_proofs: &Vec<PlonkyProof>,
    ) -> Result<()> {
        // set the msgs values
        for i in 0..N {
            self.msgs_targ[i].set_witness(pw, &msgs[i]).unwrap();
        }

        // set the InnerCircuit related values
        for i in 0..N {
            pw.set_target(self.selectors_targ[i], selectors[i])?;

            I::set_targets(pw, &self.inner_circuit_targ[i], &inner_circuit_input[i])?;
        }

        // set proof related values:

        // recursive proofs verification
        pw.set_verifier_data_target(&self.verifier_data_targ, &self.verifier_data.verifier_only)?;

        let public_inputs = RecursiveCircuit::<I, M, N>::prepare_public_inputs(
            self.verifier_data.clone(),
            msgs.clone(),
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
    let mut msgs_targ: Vec<MessageTarget> = vec![];
    for _ in 0..N {
        let msg_targ = MessageTarget::new_with_size(&mut builder, M);
        builder.register_public_inputs(&msg_targ.msg);
        msgs_targ.push(msg_targ);
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
    for i in 0..N {
        let selector_F_targ = builder.add_virtual_target();
        binary_check(&mut builder, selector_F_targ);
        let b = BoolTarget::new_unsafe(selector_F_targ);
        let _ = I::add_targets(&mut builder, &b, &msgs_targ[i]).unwrap();
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
pub struct Recursion<I: InnerCircuit, const M: usize, const N: usize> {
    _i: PhantomData<I>,
}

impl<I: InnerCircuit, const M: usize, const N: usize> Recursion<I, M, N> {
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

    pub fn prove_step(
        verifier_data: VerifierCircuitData<F, C, D>,
        msgs: &Vec<Vec<F>>,
        // if selectors[i]==0: verify InnerCircuit. if selectors[i]==1: verify recursive_proof[i]
        selectors: Vec<F>,
        inner_circuits_input: Vec<I::Input>,
        recursive_proofs: &Vec<PlonkyProof>,
    ) -> Result<PlonkyProof> {
        println!("prove_step:");
        for i in 0..N {
            if selectors[i].is_nonzero() {
                println!("  (selectors[{}]==1), verify {}-th proof", i, i);
            } else {
                println!("  (selectors[{}]==0), verify {}-th inner circuit", i, i);
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
            msgs,
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
    use std::time::Instant;

    use super::*;

    // mod super::example_innercircuit;
    use super::example_innercircuit::{ExampleGadget, ExampleGadgetInput};
    use crate::signature::schnorr::*;
    // use sch::schnorr_prover::*;

    // this sets the plonky2 internal logs level
    fn set_log() {
        let _ = env_logger::builder()
            .filter_level(log::LevelFilter::Warn)
            .is_test(true)
            .try_init();
    }

    /// to run:
    /// cargo test --release test_tree_recursion -- --nocapture
    #[test]
    fn test_tree_recursion() -> Result<()> {
        // For testing: change the following `N` value to try different arities of the recursion tree:
        test_tree_recursion_opt::<2>()?; // N=2

        test_tree_recursion_opt::<3>()?; // N=3

        Ok(())
    }

    fn test_tree_recursion_opt<const N: usize>() -> Result<()> {
        set_log();
        println!("\n--------------------------------------------------");
        println!("\n--------------------------------------------------");
        println!(
            "\nrunning test:\n===test_tree_recursion_opt with N={} (arity)",
            N
        );

        let l: u32 = 2; // levels of the recursion (binary) tree
        let k = (N as u32).pow(l) as usize; // number of leafs in the recursion tree, N^l
        println!(
            "Testing a {}-arity recursion tree, of {} levels, with {} leaves",
            N, l, k
        );

        let mut rng: rand::rngs::ThreadRng = rand::thread_rng();
        let schnorr = SchnorrSigner::new();
        const MSG_LEN: usize = 5;
        // generate N random msgs
        let msgs: Vec<Vec<F>> = (0..N)
            .into_iter()
            .map(|_| {
                std::iter::repeat_with(|| F::sample(&mut rng))
                    .take(MSG_LEN)
                    .collect()
            })
            .collect();

        // generate k key pairs
        let sk_vec: Vec<SchnorrSecretKey> =
            (0..k).map(|i| SchnorrSecretKey { sk: i as u64 }).collect();
        let pk_vec: Vec<SchnorrPublicKey> = sk_vec.iter().map(|&sk| schnorr.keygen(&sk)).collect();

        // sign
        let sig_vec: Vec<SchnorrSignature> = sk_vec
            .iter()
            .zip(msgs.iter().cycle())
            .map(|(&sk, msg)| schnorr.sign(&msg, &sk, &mut rng))
            .collect();
        assert_eq!(sig_vec.len(), k);

        // build the circuit_data & verifier_data for the recursive circuit
        let circuit_data = Recursion::<ExampleGadget, MSG_LEN, N>::circuit_data()?;
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
        let mut proofs_at_level_i: Vec<PlonkyProof> =
            (0..k).into_iter().map(|_| dummy_proof.clone()).collect();

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

                // - if we're at the first level of the recursion tree:
                //      proof_enabled=false=0, so that the circuit verifies the signature and not the proof.
                // - else:
                //      proof_enabled=true=1, so that the circuit verifies the proof and not the signature.
                //
                //  In future tests we will try other cases (eg. some sigs and some proofs in a
                //  node), but for the moment we just do base_case: sig verify, other cases: proof
                //  verify.
                let proof_enabled = if i == 0 { F::ZERO } else { F::ONE };

                // prepare the inputs for the `Recursion::prove_step` call
                let selectors = (0..N).into_iter().map(|_| proof_enabled.clone()).collect();
                let innercircuits_input: Vec<ExampleGadgetInput> = (0..N)
                    .into_iter()
                    .map(|k| ExampleGadgetInput {
                        pk: pk_vec[j + k],
                        sig: sig_vec[j + k],
                    })
                    .collect();
                let proofs = (0..N)
                    .into_iter()
                    .enumerate()
                    .map(|(k, _)| proofs_at_level_i[j + k].clone())
                    .collect();

                // do the recursive step
                let start = Instant::now();
                let new_proof = Recursion::<ExampleGadget, MSG_LEN, N>::prove_step(
                    verifier_data.clone(),
                    &msgs,
                    selectors,
                    innercircuits_input,
                    &proofs,
                )?;
                println!(
                    "Recursion::prove_step (level: i={}, node: j={}) took: {:?}",
                    i,
                    j,
                    start.elapsed()
                );

                // verify the recursive proof
                let public_inputs =
                    RecursiveCircuit::<ExampleGadget, MSG_LEN, N>::prepare_public_inputs(
                        verifier_data.clone(),
                        msgs.clone(),
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
        let public_inputs = RecursiveCircuit::<ExampleGadget, MSG_LEN, N>::prepare_public_inputs(
            verifier_data.clone(),
            msgs.clone(),
        );
        verifier_data.clone().verify(ProofWithPublicInputs {
            proof: last_proof.clone(),
            public_inputs: public_inputs.clone(),
        })?;

        Ok(())
    }
}
