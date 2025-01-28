/// This file contains a simple example implementing the InnerCircuit trait, by a circuit that
/// checks a signature over the given msg.
use anyhow::Result;
use plonky2::field::types::Field;
use plonky2::iop::target::BoolTarget;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use std::array;

// use crate::pod::circuit::operation::OperationTarget;
use crate::signature::schnorr::*;
use crate::signature::schnorr_prover::*;

use super::{
    utils::assert_one_if_enabled, InnerCircuitTrait, IntroducerCircuitTrait, OpsExecutorTrait,
};
use crate::{C, D, F};

pub struct ExampleIntroducer {}

impl IntroducerCircuitTrait for ExampleIntroducer {
    type Targets = ExampleGadgetTargets;
    type Input = ExampleGadgetInput;

    /// Notice that the methods `circuit_data`, `dummy_proof`, `build_prover` are already
    /// implemented at the trait level, in a generic way agnostic to the specific logic of the
    /// circuit.

    fn dummy_inputs() -> Result<Self::Input> {
        let mut rng: rand::rngs::ThreadRng = rand::thread_rng();
        let schnorr = SchnorrSigner::new();
        let msg: Vec<F> = vec![F::ZERO, F::ZERO, F::ZERO, F::ZERO];
        let sk: SchnorrSecretKey = SchnorrSecretKey { sk: 0u64 };
        let pk: SchnorrPublicKey = schnorr.keygen(&sk);
        let sig: SchnorrSignature = schnorr.sign(&msg.to_vec(), &sk, &mut rng);
        Ok(Self::Input { pk, sig, msg })
    }

    fn add_targets(builder: &mut CircuitBuilder<F, D>) -> Result<Self::Targets> {
        // signature verification:
        let sb: SchnorrBuilder = SchnorrBuilder {};
        let pk_targ = SchnorrPublicKeyTarget::new_virtual(builder);
        let sig_targ = SchnorrSignatureTarget::new_virtual(builder);
        let msg_targ = MessageTarget::new_with_size(builder, 4);
        let sig_verif_targ = sb.verify_sig::<C>(builder, &sig_targ, &msg_targ, &pk_targ);

        let true_target = builder._true();
        builder.connect(sig_verif_targ.target, true_target.target);

        // TODO TMP rm
        // use plonky2::gates::noop::NoopGate;
        // pad min gates
        // while builder.num_gates() < 1 << 12 {
        //     builder.add_gate(NoopGate, vec![]);
        // }

        Ok(Self::Targets {
            pk_targ,
            sig_targ,
            msg_targ,
        })
    }

    fn set_targets(
        pw: &mut PartialWitness<F>,
        targets: &Self::Targets,
        pod: &Self::Input,
    ) -> Result<()> {
        assert_eq!(pod.msg.len(), 4);
        // set signature related values:
        targets.pk_targ.set_witness(pw, &pod.pk).unwrap();
        targets.sig_targ.set_witness(pw, &pod.sig).unwrap();
        targets.msg_targ.set_witness(pw, &pod.msg).unwrap();

        Ok(())
    }
}

pub struct ExampleGadgetInput {
    pub pk: SchnorrPublicKey,
    pub sig: SchnorrSignature,
    pub msg: Vec<F>,
}

pub struct ExampleGadgetTargets {
    pub pk_targ: SchnorrPublicKeyTarget,
    pub sig_targ: SchnorrSignatureTarget,
    pub msg_targ: MessageTarget,
}

/// The logic of this gadget verifies the given signature if `selector==0`.
///
/// It implements the InnerCircuit trait, so it contains the methods to `add_targets` (ie. create
/// the targets, the logic of the circuit), and `set_targets` (ie. set the specific values to be
/// used for the previously created targets).
pub struct ExampleGadget {}

impl InnerCircuitTrait for ExampleGadget {
    type Targets = ExampleGadgetTargets;
    type Input = ExampleGadgetInput;

    fn add_targets(
        builder: &mut CircuitBuilder<F, D>,
        selector_booltarg: &BoolTarget, // 1==inner circuit check enabled
    ) -> Result<Self::Targets> {
        // signature verification:
        let sb: SchnorrBuilder = SchnorrBuilder {};
        let pk_targ = SchnorrPublicKeyTarget::new_virtual(builder);
        let sig_targ = SchnorrSignatureTarget::new_virtual(builder);
        let msg_targ = MessageTarget::new_with_size(builder, 4);
        let sig_verif_targ = sb.verify_sig::<C>(builder, &sig_targ, &msg_targ, &pk_targ);

        // if selector==1: verify the signature; else: don't check it. ie:
        //   if selector=1: check that sig_verif==1
        //   if selector=0: check that one==1
        assert_one_if_enabled(builder, sig_verif_targ.target, selector_booltarg);

        Ok(Self::Targets {
            pk_targ,
            sig_targ,
            msg_targ,
        })
    }

    fn set_targets(
        pw: &mut PartialWitness<F>,
        targets: &Self::Targets,
        pod: &Self::Input,
    ) -> Result<Vec<F>> {
        // set signature related values:
        targets.pk_targ.set_witness(pw, &pod.pk).unwrap();
        targets.sig_targ.set_witness(pw, &pod.sig).unwrap();
        targets.msg_targ.set_witness(pw, &pod.msg).unwrap();

        Ok(vec![])
    }
}

pub struct ExampleOpsExecutor<const NS: usize, const VL: usize>;

impl<const NS: usize, const VL: usize> OpsExecutorTrait for ExampleOpsExecutor<NS, VL> {
    type Targets = plonky2::iop::target::Target;
    type Input = ();
    type Output = ();

    fn add_targets(builder: &mut CircuitBuilder<F, D>) -> Result<Self::Targets> {
        let targ = builder.add_virtual_target();
        Ok(targ)
    }

    fn set_targets(
        _pw: &mut PartialWitness<F>,
        _targets: &Self::Targets,
        _input: &Self::Input,
        _output: &Self::Output,
    ) -> Result<Vec<F>> {
        Ok(vec![])
    }
}
