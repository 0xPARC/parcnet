use anyhow::Error;
use num::BigUint;
use plonky2::field::{goldilocks_field::GoldilocksField, types::Field};
use plonky2::iop::generator::{GeneratedValues, SimpleGenerator};
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartitionWitness, Witness};
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::biguint::{BigUintTarget, CircuitBuilderBiguint, WitnessBigUint};
use crate::plonky2_u32::gadgets::arithmetic_u32::CircuitBuilderU32;

pub trait JubjubP {
    fn jubjub_p() -> Self;
}

impl JubjubP for BigUint {
    fn jubjub_p() -> BigUint {
        BigUint::new( {vec![
            4026531841, 1138881939, 2042196113, 674490440,
            2172737629, 3092268470, 3778125865, 811880050,
        ]})
    }
}

#[derive(Clone, Debug)]
pub struct JubjubFieldElementTarget (
    BigUintTarget,
);

pub trait CircuitBuilderJubjubField {
    const JUBJUB_P_NUM_LIMBS: usize;

    fn jubjub_p(&mut self) -> BigUintTarget;

    fn add_virtual_jubjubfield_target(&mut self) -> JubjubFieldElementTarget;

    fn zero_jubjubfield(&mut self) -> JubjubFieldElementTarget;

    fn one_jubjubfield(&mut self) -> JubjubFieldElementTarget;

    fn from_u32_jubjubfield(&mut self, a: u32) -> JubjubFieldElementTarget;

    fn from_biguint_jubjubfield(&mut self, a: &BigUintTarget) -> JubjubFieldElementTarget;

    fn connect_jubjubfield(
        &mut self, 
        a: &JubjubFieldElementTarget, 
        b: &JubjubFieldElementTarget
    );

    fn add_jubjubfield(
        &mut self, 
        a: &JubjubFieldElementTarget, 
        b: &JubjubFieldElementTarget
    ) -> JubjubFieldElementTarget;

    fn neg_jubjubfield(
        &mut self,
        a: &JubjubFieldElementTarget,
    ) -> JubjubFieldElementTarget;

    fn sub_jubjubfield(
        &mut self,
        a: &JubjubFieldElementTarget, 
        b: &JubjubFieldElementTarget
    ) -> JubjubFieldElementTarget;

    fn mul_jubjubfield(
        &mut self,
        a: &JubjubFieldElementTarget, 
        b: &JubjubFieldElementTarget
    ) -> JubjubFieldElementTarget;

    fn recip_jubjubfield(
        &mut self,
        a: &JubjubFieldElementTarget,
    ) -> JubjubFieldElementTarget;

    fn div_jubjubfield(
        &mut self,
        a: &JubjubFieldElementTarget, 
        b: &JubjubFieldElementTarget
    ) -> JubjubFieldElementTarget;
}

impl CircuitBuilderJubjubField for CircuitBuilder<GoldilocksField, 2> {
    const JUBJUB_P_NUM_LIMBS: usize = 8;

    fn jubjub_p(&mut self) -> BigUintTarget {
        BigUintTarget {
            limbs: vec![
                self.constant_u32(4026531841),
                self.constant_u32(1138881939),
                self.constant_u32(2042196113),
                self.constant_u32(674490440),
                self.constant_u32(2172737629),
                self.constant_u32(3092268470),
                self.constant_u32(3778125865),
                self.constant_u32(811880050),
            ]
        }
    }

    fn add_virtual_jubjubfield_target(&mut self) -> JubjubFieldElementTarget {
        JubjubFieldElementTarget (
            self.add_virtual_biguint_target(Self::JUBJUB_P_NUM_LIMBS)
        )
    }

    fn zero_jubjubfield(&mut self) -> JubjubFieldElementTarget {
        JubjubFieldElementTarget (
            BigUintTarget {
                limbs: vec![
                    self.constant_u32(0),
                ]        
            }
        )
    }

    fn one_jubjubfield(&mut self) -> JubjubFieldElementTarget {
        JubjubFieldElementTarget (
            BigUintTarget {
                limbs: vec![
                    self.constant_u32(1),
                ]        
            }
        )
    }

    fn from_u32_jubjubfield(&mut self, a: u32) -> JubjubFieldElementTarget {
        JubjubFieldElementTarget (
            BigUintTarget {
                limbs: vec![
                    self.constant_u32(a)
                ]
            }
        )
    }

    // reduces a mod jubjub_p, then converts to JubjubFieldElementTarget
    fn from_biguint_jubjubfield(&mut self, a: &BigUintTarget) -> JubjubFieldElementTarget {
        let p = self.jubjub_p();
        JubjubFieldElementTarget(self.rem_biguint(a, &p))
    }

    fn connect_jubjubfield(
        &mut self, 
        a: &JubjubFieldElementTarget, 
        b: &JubjubFieldElementTarget
    ) {
        self.connect_biguint(&a.0, &b.0);
    }

    fn add_jubjubfield(
        &mut self, 
        a: &JubjubFieldElementTarget, 
        b: &JubjubFieldElementTarget
    ) -> JubjubFieldElementTarget {
        let p = self.jubjub_p();
        let sum = self.add_biguint(&a.0, &b.0);
        JubjubFieldElementTarget(self.rem_biguint(&sum, &p))
    }

    fn neg_jubjubfield(
        &mut self,
        a: &JubjubFieldElementTarget,
    ) -> JubjubFieldElementTarget {
        let p = self.jubjub_p();
        let diff = self.sub_biguint(&p, &a.0);
        JubjubFieldElementTarget(self.rem_biguint(&diff, &p))
    }

    fn sub_jubjubfield(
        &mut self,
        a: &JubjubFieldElementTarget, 
        b: &JubjubFieldElementTarget
    ) -> JubjubFieldElementTarget {
        let neg_b = self.neg_jubjubfield(b);
        self.add_jubjubfield(a, &neg_b)
    }

    fn mul_jubjubfield(
        &mut self,
        a: &JubjubFieldElementTarget, 
        b: &JubjubFieldElementTarget
    ) -> JubjubFieldElementTarget {
        let p = self.jubjub_p();
        let prod = self.mul_biguint(&a.0, &b.0);
        JubjubFieldElementTarget(self.rem_biguint(&prod, &p))
    }

    fn recip_jubjubfield(
        &mut self,
        a: &JubjubFieldElementTarget,
    ) -> JubjubFieldElementTarget {
        let a_inv = self
                .add_virtual_jubjubfield_target();
        self.add_simple_generator(
            JubjubFieldReciprocalGenerator {
                a: a.clone(),
                a_inv: a_inv.clone(),
            }
        );
        let prod = self.mul_jubjubfield(a, &a_inv);
        let one = self.one_jubjubfield();
        self.connect_jubjubfield(&prod, &one);
        a_inv
    }

    fn div_jubjubfield(
        &mut self,
        a: &JubjubFieldElementTarget, 
        b: &JubjubFieldElementTarget
    ) -> JubjubFieldElementTarget {
        let a_inv = self.recip_jubjubfield(a);
        self.mul_jubjubfield(b, &a_inv)
    }
}

pub trait WitnessJubjubField {
    fn get_jubjubfield_target(
        &self, 
        target: JubjubFieldElementTarget
    ) -> BigUint;
    fn set_jubjubfield_target(
        &mut self, 
        target: &JubjubFieldElementTarget, 
        value: &BigUint
    );
}

impl<T: Witness<GoldilocksField>> WitnessJubjubField for T {
    fn get_jubjubfield_target(
        &self, 
        target: JubjubFieldElementTarget
    ) -> BigUint {
        self.get_biguint_target(target.0)
    }

    fn set_jubjubfield_target(
        &mut self, 
        target: &JubjubFieldElementTarget, 
        value: &BigUint
    ) {
        self.set_biguint_target(&target.0, value);
    }
}

struct JubjubFieldReciprocalGenerator {
    a: JubjubFieldElementTarget,
    a_inv: JubjubFieldElementTarget,
}

impl SimpleGenerator<GoldilocksField, 2> for JubjubFieldReciprocalGenerator {
    fn id(&self) -> String {
        "JubjubFieldReciprocalGenerator".to_string()
    }

    fn dependencies(&self) -> Vec<Target> {
        self.a.0.limbs.iter().map(|&l| l.0).collect()
    }

    fn run_once(
        &self, 
        witness: &PartitionWitness<F>, 
        out_buffer: &mut GeneratedValues<F>
    ) -> Result<(), Error> {
        let a = witness.get_jubjubfield_witness(self.a.clone());
        
    }

}
