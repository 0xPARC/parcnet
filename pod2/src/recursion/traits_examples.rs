/// This file contains a simple example implementing the InnerCircuit trait, by a circuit that
/// checks a signature over the given msg.
use anyhow::Result;
use hashbrown::HashMap;
use plonky2::hash::hash_types::{HashOut, HashOutTarget, NUM_HASH_OUT_ELTS};
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::pod::{
    circuit::operation::OperationTarget, circuit::statement::StatementTarget, gadget::GadgetID,
    operation::Operation as Op, statement::StatementRef,
};
use crate::signature::schnorr::*;
use crate::signature::schnorr_prover::*;

use super::{utils::assert_one_if_enabled, InnerCircuitTrait, OpsExecutorTrait};
use crate::{C, D, F};

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

impl InnerCircuitTrait for ExampleGadget {
    type Targets = ExampleGadgetTargets;
    type Input = ExampleGadgetInput;

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

pub struct ExampleOpsExecutor<const M: usize, const N: usize> {}

impl<const M: usize, const N: usize> OpsExecutorTrait<M, N> for ExampleOpsExecutor<M, N>
where
    [(); M + N]:,
{
    // in this case, Targets only contains the computed new hash
    type Targets = HashOutTarget;
    type Input = HashOut<F>;

    fn add_targets(
        builder: &mut CircuitBuilder<F, D>,
        hashes: [HashOutTarget; M + N],
    ) -> Result<Self::Targets> {
        // here we would do some logic combining the `hashes` to obtain the new hash (using
        // `hashes[0]` for the moment
        Ok(hashes[0])
    }

    fn set_targets(
        pw: &mut PartialWitness<F>,
        targets: &Self::Targets,
        input: &Self::Input,
    ) -> Result<()> {
        pw.set_hash_target(*targets, *input)?;
        Ok(())
    }
}
