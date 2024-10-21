use anyhow::{anyhow, Result};
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::poseidon::PoseidonHash,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, config::PoseidonGoldilocksConfig},
};

use crate::{
    pod::{util::hash_string_to_field, PODProof, POD, SIGNER_PK_KEY},
    schnorr_prover::{
        MessageTarget, SchnorrBuilder, SchnorrPublicKeyTarget, SchnorrSignatureTarget,
        SignatureVerifierBuilder,
    },
};

use std::iter::zip;

use super::{statement::StatementTarget, util::vector_ref, D, F};

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
    pub fn payload_hash_target(&self, builder: &mut CircuitBuilder<F, D>) -> Target {
        let flattened_statement_targets = self
            .payload
            .iter()
            .flat_map(|s| s.to_targets())
            .collect::<Vec<_>>();
        builder
            .hash_n_to_hash_no_pad::<PoseidonHash>(flattened_statement_targets)
            .elements[0]
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
    /// Computes payload hash target as well as a boolean indicating
    /// whether verification of the POD signature was successful.
    pub fn compute_targets_and_verify(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Result<(Target, SchnorrPublicKeyTarget, BoolTarget)> {
        // Compute payload hash target.
        let payload_hash_target = self.payload_hash_target(builder);
        // Extract signer's key.
        let pk_target = SchnorrPublicKeyTarget {
            pk: self.signer_pk_target(builder)?,
        };
        // Check signature.
        let sb = SchnorrBuilder;
        let verification_target = sb.verify_sig::<PoseidonGoldilocksConfig>(
            builder,
            &self.proof,
            &MessageTarget {
                msg: vec![payload_hash_target],
            },
            &pk_target,
        );
        Ok((payload_hash_target, pk_target, verification_target))
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

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Field},
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };

    use crate::{
        pod::{circuit::pod::SchnorrPODTarget, entry::Entry, payload::HashablePayload, POD},
        schnorr::SchnorrSecretKey,
    };

    #[test]
    fn schnorr_pod_test() -> Result<()> {
        let scalar1 = GoldilocksField(36);
        let entry1 = Entry::new_from_scalar("some key", scalar1);
        let schnorr_pod3 =
            POD::execute_schnorr_gadget(&vec![entry1.clone()], &SchnorrSecretKey { sk: 25 });

        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let schnorr_pod_target = SchnorrPODTarget::new_virtual(&mut builder, 2);

        // Assign witnesses
        let mut pw: PartialWitness<F> = PartialWitness::new();
        schnorr_pod_target.set_witness(&mut pw, &schnorr_pod3)?;

        // Verify POD
        let (_, _, verified) = schnorr_pod_target.compute_targets_and_verify(&mut builder)?;
        // It should have been successfully verified.
        builder.assert_one(verified.target);

        // Build and prove.
        let data = builder.build::<C>();
        let _proof = data.prove(pw)?;
        Ok(())
    }
}
