use anyhow::{anyhow, Result};
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::hash_types::{HashOut, HashOutTarget, NUM_HASH_OUT_ELTS},
    hash::poseidon::PoseidonHash,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, config::PoseidonGoldilocksConfig},
};
use std::iter::zip;

use super::{statement::StatementTarget, util::vector_ref};
use crate::{
    pod::{util::hash_string_to_field, PODProof, POD, SIGNER_PK_KEY},
    recursion::{utils::assert_one_if_enabled, InnerCircuit},
    signature::schnorr_prover::{
        MessageTarget, SchnorrBuilder, SchnorrPublicKeyTarget, SchnorrSignatureTarget,
        SignatureVerifierBuilder,
    },
    C, D, F,
};

pub struct SchnorrPODTarget {
    /// Sorted payload.
    pub payload: Vec<StatementTarget>,
    /// Index of statement containing value of signer's public
    /// key. Checked in circuit.
    pub pk_index: Target,
    pub proof: SchnorrSignatureTarget,
}

impl SchnorrPODTarget {
    pub fn new_virtual(builder: &mut CircuitBuilder<F, D>, num_statements: usize) -> Self {
        let pk_index = builder.add_virtual_target();
        Self {
            payload: (0..num_statements)
                .map(|_| StatementTarget::new_virtual(builder))
                .collect(),
            pk_index,
            proof: SchnorrSignatureTarget::new_virtual(builder),
        }
    }
    /// Singles out signer's public key target by index, adding
    /// constraints ensuring that the proper entry has been chosen.
    pub fn signer_pk_target(&self, builder: &mut CircuitBuilder<F, D>) -> Result<Target> {
        let key_target = vector_ref(
            builder,
            self.payload
                .iter()
                .map(|s| s.key1)
                .collect::<Vec<_>>()
                .as_ref(),
            self.pk_index,
        )?;
        let origin_id_target = vector_ref(
            builder,
            self.payload
                .iter()
                .map(|s| s.origin1.origin_id)
                .collect::<Vec<_>>()
                .as_ref(),
            self.pk_index,
        )?;
        let value_target = vector_ref(
            builder,
            self.payload
                .iter()
                .map(|s| s.value)
                .collect::<Vec<_>>()
                .as_ref(),
            self.pk_index,
        )?;
        // Check public key entry key.
        let expected_pk_entry_key = builder.constant(hash_string_to_field(SIGNER_PK_KEY));
        builder.connect(key_target, expected_pk_entry_key);

        // Check origin ID, which should be 1 for self.
        builder.assert_one(origin_id_target);

        // This suggests we are OK.
        Ok(value_target)
    }

    /// Verifies the signature over the hash_target, and returns a boolean indicating whether
    /// verification of the POD signature was successful.
    pub fn compute_targets_and_verify(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        hash_target: &HashOutTarget,
    ) -> Result<(SchnorrPublicKeyTarget, BoolTarget)> {
        // build the msg of the sig, from the given hash
        let msg_target = MessageTarget {
            msg: hash_target.elements.to_vec(),
        };
        // Extract signer's key.
        let pk_target = SchnorrPublicKeyTarget {
            pk: self.signer_pk_target(builder)?,
        };
        // Check signature.
        let sb = SchnorrBuilder;
        let verification_target = sb.verify_sig::<PoseidonGoldilocksConfig>(
            builder,
            &self.proof,
            &msg_target,
            &pk_target,
        );
        Ok((pk_target, verification_target))
    }
    pub fn set_witness(&self, pw: &mut PartialWitness<GoldilocksField>, pod: &POD) -> Result<()> {
        // Assign payload witness.
        zip(&self.payload, &pod.payload.statements_list)
            .try_for_each(|(s_target, (_, s))| s_target.set_witness(pw, s))?;
        // Assign signer's public key index witness.
        let pk_statement_name = format!("VALUEOF:{}", SIGNER_PK_KEY);
        let pk_index = pod
            .payload
            .statements_list
            .iter()
            .enumerate()
            .filter(|(i, (s_name, _))| s_name == &pk_statement_name)
            .map(|(i, _)| i)
            .next()
            .ok_or(anyhow!(
                "The following POD is missing its signer's public key: {:?}",
                pod
            ))? as u64;
        pw.set_target(self.pk_index, GoldilocksField::from_canonical_u64(pk_index))?;
        // Assign POD signature witness.
        match pod.proof {
            PODProof::Schnorr(sig) => self.proof.set_witness(pw, &sig),
            _ => Err(anyhow!("The following POD is not a Schnorr POD: {:?}", pod)),
        }
    }
}

/// NS stands for NumStatements, the number of statements checked in the POD.
pub struct SchnorrPODGadget<const NS: usize> {}

impl<const NS: usize> InnerCircuit for SchnorrPODGadget<NS> {
    type Input = POD;
    type Targets = SchnorrPODTarget;

    /// set up the circuit logic
    fn add_targets(
        builder: &mut CircuitBuilder<F, D>,
        selector_booltarg: &BoolTarget,
        hash_target: &HashOutTarget,
    ) -> Result<Self::Targets> {
        let schnorr_pod_target = SchnorrPODTarget::new_virtual(builder, NS);

        // add POD in-circuit verification logic
        let (_, verified) = schnorr_pod_target.compute_targets_and_verify(builder, hash_target)?;

        // if selector_booltarg=0, we check the verified.target (else the recursive tree will check
        // the plonky2 proof)
        assert_one_if_enabled(builder, verified.target, &selector_booltarg);

        Ok(schnorr_pod_target)
    }

    /// set the actual witness values for the current instance of the circuit
    fn set_targets(
        pw: &mut PartialWitness<F>,
        pod_target: &Self::Targets, // targets = schnorr_pod_target
        pod: &Self::Input,          // input = pod
    ) -> Result<()> {
        pod_target.set_witness(pw, pod)
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Field},
        iop::witness::PartialWitness,
        plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig},
    };

    use super::*;
    use crate::{
        pod::{entry::Entry, payload::HashablePayload, POD},
        signature::schnorr::SchnorrSecretKey,
    };
    use crate::{C, D, F};

    #[test]
    fn schnorr_pod_test() -> Result<()> {
        let scalar1 = GoldilocksField(36);
        let entry1 = Entry::new_from_scalar("some key", scalar1);
        let schnorr_pod3 =
            POD::execute_schnorr_gadget(&vec![entry1.clone()], &SchnorrSecretKey { sk: 25 });
        let payload_hash = schnorr_pod3.payload.hash_payload();

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        const NS: usize = 2; // NS: NumStatements

        let selector_targ = builder.add_virtual_target();
        let selector_booltarg = BoolTarget::new_unsafe(selector_targ);

        let hash_target = builder.add_virtual_hash_public_input();

        let schnorr_pod_target =
            SchnorrPODGadget::<NS>::add_targets(&mut builder, &selector_booltarg, &hash_target)?;

        // set selector=0, so that the pod is verified in the InnerCircuit
        let selector = F::ZERO;

        // Assign witnesses
        let mut pw: PartialWitness<F> = PartialWitness::new();
        pw.set_target(selector_targ, selector)?;
        pw.set_hash_target(hash_target, payload_hash)?;
        SchnorrPODGadget::<NS>::set_targets(&mut pw, &schnorr_pod_target, &schnorr_pod3)?;

        // Build and prove.
        let data = builder.build::<C>();
        let _proof = data.prove(pw)?;
        Ok(())
    }
}
