use anyhow::Error;
use num::BigUint;
use plonky2::field::{goldilocks_field::GoldilocksField, types::Field};
use plonky2::iop::generator::{GeneratedValues, SimpleGenerator};
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartitionWitness, Witness};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::util::serialization::{Buffer, IoResult};
use std::fmt;
use std::fmt::Display;

use crate::biguint::{
    BigUintTarget, 
    CircuitBuilderBiguint, 
    GeneratedValuesBigUint,
    WitnessBigUint
};
use crate::plonky2_u32::gadgets::arithmetic_u32::{CircuitBuilderU32, U32Target};
use crate::serialization::{ReadBigUintTarget, WriteBigUintTarget};

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
pub struct JubjubFieldTarget (
    BigUintTarget,
);

pub trait CircuitBuilderJubjubField {
    const JUBJUB_P_NUM_LIMBS: usize;

    fn jubjub_p(&mut self) -> BigUintTarget;

    fn add_virtual_jubjubfield_target(&mut self) -> JubjubFieldTarget;

    fn zero_jubjubfield(&mut self) -> JubjubFieldTarget;

    fn one_jubjubfield(&mut self) -> JubjubFieldTarget;

    fn from_u32_jubjubfield(&mut self, a: u32) -> JubjubFieldTarget;

    fn from_biguint_jubjubfield(&mut self, a: &BigUintTarget) -> JubjubFieldTarget;

    fn connect_jubjubfield(
        &mut self, 
        a: &JubjubFieldTarget, 
        b: &JubjubFieldTarget
    );

    fn add_jubjubfield(
        &mut self, 
        a: &JubjubFieldTarget, 
        b: &JubjubFieldTarget
    ) -> JubjubFieldTarget;

    fn neg_jubjubfield(
        &mut self,
        a: &JubjubFieldTarget,
    ) -> JubjubFieldTarget;

    fn sub_jubjubfield(
        &mut self,
        a: &JubjubFieldTarget, 
        b: &JubjubFieldTarget
    ) -> JubjubFieldTarget;

    fn mul_jubjubfield(
        &mut self,
        a: &JubjubFieldTarget, 
        b: &JubjubFieldTarget
    ) -> JubjubFieldTarget;

    fn recip_jubjubfield(
        &mut self,
        a: &JubjubFieldTarget,
    ) -> JubjubFieldTarget;

    fn div_jubjubfield(
        &mut self,
        a: &JubjubFieldTarget, 
        b: &JubjubFieldTarget
    ) -> JubjubFieldTarget;
}

impl CircuitBuilderJubjubField for CircuitBuilder<GoldilocksField, 2> {
    const JUBJUB_P_NUM_LIMBS: usize = 8;

    fn jubjub_p(&mut self) -> BigUintTarget {
        let limbs: Vec::<U32Target> = BigUint::jubjub_p()
            .iter_u32_digits()
            .map(|x| self.constant_u32(x))
            .collect();
        BigUintTarget {limbs}
    }

    fn add_virtual_jubjubfield_target(&mut self) -> JubjubFieldTarget {
        JubjubFieldTarget (
            self.add_virtual_biguint_target(Self::JUBJUB_P_NUM_LIMBS)
        )
    }

    fn zero_jubjubfield(&mut self) -> JubjubFieldTarget {
        JubjubFieldTarget (
            BigUintTarget {
                limbs: vec![
                    self.constant_u32(0),
                ]        
            }
        )
    }

    fn one_jubjubfield(&mut self) -> JubjubFieldTarget {
        JubjubFieldTarget (
            BigUintTarget {
                limbs: vec![
                    self.constant_u32(1),
                ]        
            }
        )
    }

    fn from_u32_jubjubfield(&mut self, a: u32) -> JubjubFieldTarget {
        JubjubFieldTarget (
            BigUintTarget {
                limbs: vec![
                    self.constant_u32(a)
                ]
            }
        )
    }

    // reduces a mod jubjub_p, then converts to JubjubFieldTarget
    fn from_biguint_jubjubfield(&mut self, a: &BigUintTarget) -> JubjubFieldTarget {
        let p = self.jubjub_p();
        JubjubFieldTarget(self.rem_biguint(a, &p))
    }

    fn connect_jubjubfield(
        &mut self, 
        a: &JubjubFieldTarget, 
        b: &JubjubFieldTarget
    ) {
        self.connect_biguint(&a.0, &b.0);
    }

    fn add_jubjubfield(
        &mut self, 
        a: &JubjubFieldTarget, 
        b: &JubjubFieldTarget
    ) -> JubjubFieldTarget {
        let p = self.jubjub_p();
        let sum = self.add_biguint(&a.0, &b.0);
        JubjubFieldTarget(self.rem_biguint(&sum, &p))
    }

    fn neg_jubjubfield(
        &mut self,
        a: &JubjubFieldTarget,
    ) -> JubjubFieldTarget {
        let p = self.jubjub_p();
        let diff = self.sub_biguint(&p, &a.0);
        JubjubFieldTarget(self.rem_biguint(&diff, &p))
    }

    fn sub_jubjubfield(
        &mut self,
        a: &JubjubFieldTarget, 
        b: &JubjubFieldTarget
    ) -> JubjubFieldTarget {
        let neg_b = self.neg_jubjubfield(b);
        self.add_jubjubfield(a, &neg_b)
    }

    fn mul_jubjubfield(
        &mut self,
        a: &JubjubFieldTarget, 
        b: &JubjubFieldTarget
    ) -> JubjubFieldTarget {
        let p = self.jubjub_p();
        let prod = self.mul_biguint(&a.0, &b.0);
        JubjubFieldTarget(self.rem_biguint(&prod, &p))
    }

    fn recip_jubjubfield(
        &mut self,
        a: &JubjubFieldTarget,
    ) -> JubjubFieldTarget {
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
        a: &JubjubFieldTarget, 
        b: &JubjubFieldTarget
    ) -> JubjubFieldTarget {
        let a_inv = self.recip_jubjubfield(a);
        self.mul_jubjubfield(b, &a_inv)
    }
}

pub trait WitnessJubjubField {
    fn get_jubjubfield_target(
        &self, 
        target: JubjubFieldTarget
    ) -> BigUint;
    fn set_jubjubfield_target(
        &mut self, 
        target: &JubjubFieldTarget, 
        value: &BigUint
    );
}

impl<T: Witness<GoldilocksField>> WitnessJubjubField for T {
    fn get_jubjubfield_target(
        &self, 
        target: JubjubFieldTarget
    ) -> BigUint {
        self.get_biguint_target(target.0)
    }

    fn set_jubjubfield_target(
        &mut self, 
        target: &JubjubFieldTarget, 
        value: &BigUint
    ) {
        self.set_biguint_target(&target.0, value);
    }
}

pub trait GeneratedValuesJubjubField {
    fn set_jubjubfield_target(
        &mut self, 
        target: &JubjubFieldTarget, 
        value: &BigUint
    );
}

impl GeneratedValuesJubjubField for GeneratedValues<GoldilocksField> {
    fn set_jubjubfield_target(
        &mut self, 
        target: &JubjubFieldTarget, 
        value: &BigUint
    ) {
        self.set_biguint_target(&target.0, value);
    }
}

#[derive(Debug)]
struct DivisionByZeroError {}

impl Display for DivisionByZeroError {
     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
         write!(f, "Attempted division by zero in jubjub field.")
     }
}

impl std::error::Error for DivisionByZeroError {}

#[derive(Debug)]
struct JubjubFieldReciprocalGenerator {
    a: JubjubFieldTarget,
    a_inv: JubjubFieldTarget,
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
        witness: &PartitionWitness<GoldilocksField>, 
        out_buffer: &mut GeneratedValues<GoldilocksField>
    ) -> Result<(), Error> {
        let a: BigUint = witness.get_jubjubfield_target(self.a.clone());
        let p: BigUint = BigUint::jubjub_p();
        let a_inv: BigUint = a.modinv(&p)
                .ok_or(Error::new(DivisionByZeroError{}))?;
        out_buffer.set_jubjubfield_target(&self.a_inv, &a_inv);
        Ok(())
    }

    fn serialize(
        &self, 
        dst: &mut Vec<u8>, 
        _common_data: &CommonCircuitData<GoldilocksField, 2>
    ) -> IoResult<()> {
        dst.write_biguint_target(self.a.0.clone())?;
        dst.write_biguint_target(self.a_inv.0.clone())?;
        Ok(())
    }

    fn deserialize(
        src: &mut Buffer,
        _common_data: &CommonCircuitData<GoldilocksField, 2>
    ) -> IoResult<Self>
    where
        Self: Sized,
    {
        let a = JubjubFieldTarget(src.read_biguint_target()?);
        let a_inv = JubjubFieldTarget(src.read_biguint_target()?);
        Ok(Self {
            a,
            a_inv,
        })
    }
}
