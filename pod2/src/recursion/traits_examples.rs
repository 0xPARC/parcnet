/// This file contains a simple example implementing the InnerCircuit trait, by a circuit that
/// checks a signature over the given msg.
use anyhow::Result;
use plonky2::hash::hash_types::{HashOut, HashOutTarget, NUM_HASH_OUT_ELTS};
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use std::array;
use std::collections::HashMap;

use crate::pod::{
    circuit::operation::OperationTarget,
    circuit::statement::StatementTarget,
    gadget::GadgetID,
    operation::Operation as Op,
    statement::{Statement, StatementRef},
};
use crate::signature::schnorr::*;
use crate::signature::schnorr_prover::*;

use super::{utils::assert_one_if_enabled, InnerCircuitTrait, OpsExecutorTrait};
use crate::{C, D, F};

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
        mut builder: &mut CircuitBuilder<F, D>,
        selector_booltarg: &BoolTarget, // 1==inner circuit check enabled
    ) -> Result<Self::Targets> {
        // signature verification:
        let sb: SchnorrBuilder = SchnorrBuilder {};
        let pk_targ = SchnorrPublicKeyTarget::new_virtual(&mut builder);
        let sig_targ = SchnorrSignatureTarget::new_virtual(&mut builder);
        let msg_targ = MessageTarget::new_with_size(&mut builder, 4);
        let sig_verif_targ = sb.verify_sig::<C>(&mut builder, &sig_targ, &msg_targ, &pk_targ);

        // if selector==1: verify the signature; else: don't check it. ie:
        //   if selector=1: check that sig_verif==1
        //   if selector=0: check that one==1
        assert_one_if_enabled(builder, sig_verif_targ.target, &selector_booltarg);

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
        // set signature related values:
        targets.pk_targ.set_witness(pw, &pod.pk).unwrap();
        targets.sig_targ.set_witness(pw, &pod.sig).unwrap();
        targets.msg_targ.set_witness(pw, &pod.msg).unwrap();

        Ok(())
    }
}

pub struct ExampleOpsExecutor;

impl OpsExecutorTrait for ExampleOpsExecutor {
    const NP: usize = 2;
    const NS: usize = 3;
    type Targets = [OperationTarget; Self::NS];
    type Input = (); // WIP
                     // type Input = (
                     //     [Op<StatementRef<'static>>; Self::NS],
                     //     HashMap<StatementRef<'static>, (usize, usize)>, // StatementRef::index_map()
                     // );
    type Output = ();

    fn add_targets(builder: &mut CircuitBuilder<F, D>) -> Result<Self::Targets> {
        // naive ops logic (create the targets without logic)
        let ops = array::from_fn(|_| OperationTarget::new_virtual(builder));
        Ok(ops)
    }

    fn set_targets(
        pw: &mut PartialWitness<F>,
        targets: &Self::Targets,
        input: &Self::Input,
        output: &Self::Output,
    ) -> Result<()>
    where
        [(); Self::NS]:,
    {
        // let (ops, ref_index_map) = input;
        // // targets[i].set_witness(pw, &input[i])
        // for i in (0..Self::NS).into_iter() {
        //     targets[i].set_witness(pw, &ops[i], ref_index_map)?
        // }
        Ok(())
    }
}
