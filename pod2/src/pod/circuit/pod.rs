use anyhow::{anyhow, Result};
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::{hash_types::HashOutTarget, poseidon::PoseidonHash},
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, config::PoseidonGoldilocksConfig},
};
use std::iter::zip;

use super::{statement::StatementTarget, util::vector_ref};
use crate::{
    pod::{util::hash_string_to_field, PODProof, Statement, POD, SIGNER_PK_KEY},
    signature::schnorr_prover::{
        MessageTarget, SchnorrBuilder, SchnorrPublicKeyTarget, SchnorrSignatureTarget,
        SignatureVerifierBuilder,
    },
    D, F,
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

    /// Checks that the payload is valid for a SchnorrPOD, i.e. that its statements
    /// are either of type `VALUE_OF` or `NONE`.
    pub fn check_payload(&self, builder: &mut CircuitBuilder<F, D>) {
        let valueof_target = builder.constant(Statement::VALUE_OF);
        let none_target = builder.constant(Statement::NONE);
        self.payload.iter().for_each(|s_target| {
            let s_type = s_target.predicate;
            let valueof_check = builder.sub(s_type, valueof_target);
            let none_check = builder.sub(s_type, none_target);
            let check = builder.mul(valueof_check, none_check);
            builder.assert_zero(check);
        });
    }

    pub fn compute_hash_target(&self, builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        builder.hash_n_to_hash_no_pad::<PoseidonHash>(
            self.payload.iter().flat_map(|s| s.to_targets()).collect(),
        )
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
            .filter(|(_, (s_name, _))| s_name == &pk_statement_name)
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
