use anyhow::Result;

use plonky2::field::{goldilocks_field::GoldilocksField, types::Field};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::{
    target::{BoolTarget, Target},
    witness::{PartialWitness, WitnessWrite},
};
use plonky2::plonk::{circuit_builder::CircuitBuilder, config::GenericConfig};

use crate::jubjubcurve::JubjubCurveTarget;
use crate::{
    mod65537::Mod65537Builder,
    schnorr::{SchnorrPublicKey, SchnorrSignature},
};

/* 
type GoldF = GoldilocksField;

pub struct MessageHashTarget {
    m: BigUintTarget,
}

pub struct EddsaSignatureTarget {
    r: JubjubCurveTarget,
    s: BigUintTarget,
}

pub struct EddsaPublicKeyTarget {
    a: JubjubCurveTarget,
}

pub struct EddsaBuilder {}

pub trait EddsaBuilder {
    fn verify_sig<C: GenericConfig<2, F = GoldF>> (
        &self,
        builder: &mut CircuitBuilder<GoldF, 2>,
        sig: &EddsaSignatureTarget,
        msg: &MessageHashTarget,
        pk: &EddsaPublicKeyTarget,
    ) -> BoolTarget;

    fn constrain_sig<C: GenericConfig<2, F = GoldF>> (
        &self,
        builder: &mut CircuitBuilder<GoldF, 2>,
        sig: &EddsaSignatureTarget,
        msg: &MessageHashTarget,
        pk: &EddsaPublicKeyTarget,
    );
}

impl EddsaBuilder for EddsaBuilder {
    fn verify_sig<C: GenericConfig<2, F = GoldF>> (
        &self,
        builder: &mut CircuitBuilder<GoldF, 2>,
        sig: &EddsaSignatureTarget,
        msg: &MessageHashTarget,
        pk: &EddsaPublicKeyTarget,
    ) -> BoolTarget {      
//        builder.verify_jubjub_point(sig.r);
//        builder.verify_jubjub_point(pk.a);
//        let h: BigUintTarget = p_hash_to_implement(sig.r, msg, pk);
//        let lhs: JubjubCurveTarget = B8.mul_scalar(&sig.s);
//        let rhs = pk.a.mul_scalar(h).add(sig.r);
//        self.is_equal(lhs, rhs)
    }
    
    fn constrain_sig<C: GenericConfig<2, F = GoldF>> (
        &self,
        builder: &mut CircuitBuilder<GoldF, 2>,
        sig: &EddsaSignatureTarget,
        msg: &MessageHashTarget,
        pk: &EddsaPublicKeyTarget,
    ) {
        let verification_output = self.verify_sig::<C>(builder, sig, msg, pk);
        let true_target = builder._true();
        builder.connect(verification_output.target, true_target.target);
    }
} */