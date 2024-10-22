/// This file contains a simple example implementing the InnerCircuit trait, by a circuit that
/// checks a signature over the given msg.
use anyhow::Result;
use plonky2::hash::hash_types::{HashOut, HashOutTarget};
use plonky2::iop::target::BoolTarget;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::signature::schnorr::*;
use crate::signature::schnorr_prover::*;

use super::{utils::assert_one_if_enabled, InnerCircuit};
use super::{C, D, F};

pub struct ExampleGadgetInput {
    pub pk: SchnorrPublicKey,
    pub sig: SchnorrSignature,
}

pub struct ExampleGadgetTargets {
    pub pk_targ: SchnorrPublicKeyTarget,
    pub sig_targ: SchnorrSignatureTarget,
}

/// The logic of this gadget verifies the given signature if `selector==0`.
///
/// It implements the InnerCircuit trait, so it contains the methods to `add_targets` (ie. create
/// the targets, the logic of the circuit), and `set_targets` (ie. set the specific values to be
/// used for the previously created targets).
pub struct ExampleGadget {}

impl InnerCircuit for ExampleGadget {
    type Input = ExampleGadgetInput;
    type Targets = ExampleGadgetTargets;

    fn add_targets(
        mut builder: &mut CircuitBuilder<F, D>,
        selector_booltarg: &BoolTarget, // 0==inner circuit check enabled
        hash_targ: &HashOutTarget,
    ) -> Result<Self::Targets> {
        // signature verification:
        let sb: SchnorrBuilder = SchnorrBuilder {};
        let pk_targ = SchnorrPublicKeyTarget::new_virtual(&mut builder);
        let sig_targ = SchnorrSignatureTarget::new_virtual(&mut builder);
        let msg_targ = MessageTarget {
            msg: hash_targ.elements.to_vec(),
        };
        let sig_verif_targ = sb.verify_sig::<C>(&mut builder, &sig_targ, &msg_targ, &pk_targ);

        // if selector==0: verify the signature; else: don't check it. ie:
        //   if selector=0: check that sig_verif==1
        //   if selector=1: check that one==1
        assert_one_if_enabled(builder, sig_verif_targ.target, &selector_booltarg);

        Ok(Self::Targets { pk_targ, sig_targ })
    }

    fn set_targets(
        pw: &mut PartialWitness<F>,
        targets: &Self::Targets,
        pod: &Self::Input,
    ) -> Result<()> {
        // set signature related values:
        targets.pk_targ.set_witness(pw, &pod.pk).unwrap();
        targets.sig_targ.set_witness(pw, &pod.sig).unwrap();

        Ok(())
    }
}
