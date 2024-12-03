use anyhow::Error;
use num::BigUint;
use paste::paste;
use plonky2::field::{goldilocks_field::GoldilocksField, types::Field};
use plonky2::iop::generator::{GeneratedValues, SimpleGenerator};
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartitionWitness, Witness};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::util::serialization::{Buffer, IoResult};
use std::fmt;
use std::fmt::Display;

use crate::plonky2_u32::gadgets::arithmetic_u32::{CircuitBuilderU32, U32Target};
use crate::signature::biguint::{
    BigUintTarget, CircuitBuilderBiguint, GeneratedValuesBigUint, WitnessBigUint,
};
use crate::signature::serialization::{ReadBigUintTarget, WriteBigUintTarget};


macro_rules! field_builder {
    ( $field_name:ident, ($($value:expr),*) ) => {
        paste! {
            // pub trait JubjubP
            pub trait [<$field_name:camel P>] {
                // fn jubjub_p -> Self
                fn [<$field_name:snake _p>]() -> Self;
            }

            impl [<$field_name:camel P>] for BigUint {
                // fn jubjub_p -> BigUint
                fn [<$field_name:snake _p>]() -> BigUint {
                    BigUint::new({vec![$($value),*]})
                }
            }

            #[derive(Clone, Debug)]
            pub struct [<$field_name:camel FieldTarget>](pub BigUintTarget);


            pub trait [<CircuitBuilder $field_name:camel Field>] {
                const [<$field_name:upper _P_NUM_LIMBS>]: usize;
            
                fn [<$field_name:snake _p>](&mut self) -> BigUintTarget;
            
                fn [<add_virtual_ $field_name:snake field_target>](&mut self) -> [<$field_name:camel FieldTarget>];
            
                fn [<zero_ $field_name:snake field>](&mut self) -> [<$field_name:camel FieldTarget>];
            
                fn [<one_ $field_name:snake field>](&mut self) -> [<$field_name:camel FieldTarget>];
            
                fn [<from_u32_ $field_name:snake field>](&mut self, a: u32) -> [<$field_name:camel FieldTarget>];
            
                fn [<from_biguint_ $field_name:snake field>](&mut self, a: &BigUintTarget) -> [<$field_name:camel FieldTarget>];
            
                fn [<connect_ $field_name:snake field>](&mut self, a: &[<$field_name:camel FieldTarget>], b: &[<$field_name:camel FieldTarget>]);
            
                fn [<is_equal_ $field_name:snake field>](
                    &mut self, 
                    a: &[<$field_name:camel FieldTarget>], 
                    b: &[<$field_name:camel FieldTarget>]
                ) -> BoolTarget;
            
                fn [<add_ $field_name:snake field>](
                    &mut self,
                    a: &[<$field_name:camel FieldTarget>],
                    b: &[<$field_name:camel FieldTarget>],
                ) -> [<$field_name:camel FieldTarget>];
            
                fn [<neg_ $field_name:snake field>](&mut self, a: &[<$field_name:camel FieldTarget>]) -> [<$field_name:camel FieldTarget>];
            
                fn [<sub_ $field_name:snake field>](
                    &mut self,
                    a: &[<$field_name:camel FieldTarget>],
                    b: &[<$field_name:camel FieldTarget>],
                ) -> [<$field_name:camel FieldTarget>];
            
                fn [<mul_ $field_name:snake field>](
                    &mut self,
                    a: &[<$field_name:camel FieldTarget>],
                    b: &[<$field_name:camel FieldTarget>],
                ) -> [<$field_name:camel FieldTarget>];
            
                fn [<recip_ $field_name:snake field>](&mut self, a: &[<$field_name:camel FieldTarget>]) -> [<$field_name:camel FieldTarget>];
            
                fn [<div_ $field_name:snake field>](
                    &mut self,
                    a: &[<$field_name:camel FieldTarget>],
                    b: &[<$field_name:camel FieldTarget>],
                ) -> [<$field_name:camel FieldTarget>];
            }

            impl [<CircuitBuilder $field_name:camel Field>] for CircuitBuilder<GoldilocksField, 2> {
                const [<$field_name:upper _P_NUM_LIMBS>]: usize = 8;

                fn [<$field_name:snake _p>](&mut self) -> BigUintTarget {
                    let limbs: Vec<U32Target> = BigUint::[<$field_name:snake _p>]()
                        .iter_u32_digits()
                        .map(|x| self.constant_u32(x))
                        .collect();
                    BigUintTarget { limbs }
                }

                fn [<add_virtual_ $field_name:snake field_target>](&mut self) -> [<$field_name:camel FieldTarget>] {
                    [<$field_name:camel FieldTarget>](self.add_virtual_biguint_target(Self::[<$field_name:upper _P_NUM_LIMBS>]))
                }

                fn [<zero_ $field_name:snake field>](&mut self) -> [<$field_name:camel FieldTarget>] {
                    [<$field_name:camel FieldTarget>](BigUintTarget {
                        limbs: vec![self.constant_u32(0)],
                    })
                }

                fn [<one_ $field_name:snake field>](&mut self) -> [<$field_name:camel FieldTarget>] {
                    [<$field_name:camel FieldTarget>](BigUintTarget {
                        limbs: vec![self.constant_u32(1)],
                    })
                }

                fn [<from_u32_ $field_name:snake field>](&mut self, a: u32) -> [<$field_name:camel FieldTarget>] {
                    [<$field_name:camel FieldTarget>](BigUintTarget {
                        limbs: vec![self.constant_u32(a)],
                    })
                }

                // reduces a mod p, then converts to *FieldTarget
                fn [<from_biguint_ $field_name:snake field>](
                    &mut self,
                    a: &BigUintTarget,
                ) -> [<$field_name:camel FieldTarget>] {
                    let p = self.[<$field_name:snake _p>]();
                    [<$field_name:camel FieldTarget>](self.rem_biguint(a, &p))
                }

                fn [<connect_ $field_name:snake field>](
                    &mut self,
                    a: &[<$field_name:camel FieldTarget>],
                    b: &[<$field_name:camel FieldTarget>],
                ) {
                    self.connect_biguint(&a.0, &b.0);
                }

                fn [<is_equal_ $field_name:snake field>](
                    &mut self,
                    a: &[<$field_name:camel FieldTarget>],
                    b: &[<$field_name:camel FieldTarget>],
                ) -> BoolTarget {
                    self.is_equal_biguint(&a.0, &b.0)
                }

                fn [<add_ $field_name:snake field>](
                    &mut self,
                    a: &[<$field_name:camel FieldTarget>],
                    b: &[<$field_name:camel FieldTarget>],
                ) -> [<$field_name:camel FieldTarget>] {
                    let p = self.[<$field_name:snake _p>]();
                    let sum = self.add_biguint(&a.0, &b.0);
                    [<$field_name:camel FieldTarget>](self.rem_biguint(&sum, &p))
                }

                fn [<neg_ $field_name:snake field>](
                    &mut self,
                    a: &[<$field_name:camel FieldTarget>],
                ) -> [<$field_name:camel FieldTarget>] {
                    let p = self.[<$field_name:snake _p>]();
                    let diff = self.sub_biguint(&p, &a.0);
                    [<$field_name:camel FieldTarget>](self.rem_biguint(&diff, &p))
                }

                fn [<sub_ $field_name:snake field>](
                    &mut self,
                    a: &[<$field_name:camel FieldTarget>],
                    b: &[<$field_name:camel FieldTarget>],
                ) -> [<$field_name:camel FieldTarget>] {
                    let neg_b = self.[<neg_ $field_name:snake field>](b);
                    self.[<add_ $field_name:snake field>](a, &neg_b)
                }

                fn [<mul_ $field_name:snake field>](
                    &mut self,
                    a: &[<$field_name:camel FieldTarget>],
                    b: &[<$field_name:camel FieldTarget>],
                ) -> [<$field_name:camel FieldTarget>] {
                    let p = self.[<$field_name:snake _p>]();
                    let prod = self.mul_biguint(&a.0, &b.0);
                    [<$field_name:camel FieldTarget>](self.rem_biguint(&prod, &p))
                }

                fn [<recip_ $field_name:snake field>](
                    &mut self,
                    a: &[<$field_name:camel FieldTarget>],
                ) -> [<$field_name:camel FieldTarget>] {
                    let a_inv = self.[<add_virtual_ $field_name:snake field_target>]();
                    self.add_simple_generator([<$field_name:camel FieldReciprocalGenerator>] {
                        a: a.clone(),
                        a_inv: a_inv.clone(),
                    });
                    let prod = self.[<mul_ $field_name:snake field>](a, &a_inv);
                    let one = self.[<one_ $field_name:snake field>]();
                    self.[<connect_ $field_name:snake field>](&prod, &one);
                    a_inv
                }

                fn [<div_ $field_name:snake field>](
                    &mut self,
                    a: &[<$field_name:camel FieldTarget>],
                    b: &[<$field_name:camel FieldTarget>],
                ) -> [<$field_name:camel FieldTarget>] {
                    let b_inv = self.[<recip_ $field_name:snake field>](b);
                    self.[<mul_ $field_name:snake field>](a, &b_inv)
                }
            }

            pub trait [<Witness $field_name:camel Field>] {
                fn [<get_ $field_name:snake field_target>](
                    &self, 
                    target: [<$field_name:camel FieldTarget>]
                ) -> BigUint;
                fn [<get_ $field_name:snake field_target_borrow>](
                    &self, 
                    target: &[<$field_name:camel FieldTarget>]
                ) -> BigUint;
                fn [<set_ $field_name:snake field_target>](
                    &mut self, 
                    target: &[<$field_name:camel FieldTarget>], 
                    value: &BigUint
                );
            }
            
            impl<T: Witness<GoldilocksField>> [<Witness $field_name:camel Field>] for T {
                fn [<get_ $field_name:snake field_target>](
                    &self, 
                    target: [<$field_name:camel FieldTarget>]
                ) -> BigUint {
                    self.get_biguint_target(target.0)
                }
            
                fn [<get_ $field_name:snake field_target_borrow>](
                    &self, 
                    target: &[<$field_name:camel FieldTarget>]
                ) -> BigUint {
                    self.get_biguint_target(target.0.clone())
                }
            
                fn [<set_ $field_name:snake field_target>](
                    &mut self, 
                    target: &[<$field_name:camel FieldTarget>], 
                    value: &BigUint
                ) {
                    self.set_biguint_target(&target.0, value);
                }
            }

            pub trait [<GeneratedValues $field_name:camel Field>] {
                fn [<set_ $field_name:snake field_target>](
                    &mut self, 
                    target: &[<$field_name:camel FieldTarget>], 
                    value: &BigUint
                );
            }
            
            impl [<GeneratedValues $field_name:camel Field>] for GeneratedValues<GoldilocksField> {
                fn [<set_ $field_name:snake field_target>](
                    &mut self, 
                    target: &[<$field_name:camel FieldTarget>], 
                    value: &BigUint
                ) {
                    self.set_biguint_target(&target.0, value);
                }
            }
            


            #[derive(Debug)]
            struct [<$field_name:camel FieldReciprocalGenerator>] {
                a: [<$field_name:camel FieldTarget>],
                a_inv: [<$field_name:camel FieldTarget>],
            }

            impl SimpleGenerator<GoldilocksField, 2> for [<$field_name:camel FieldReciprocalGenerator>] {
                fn id(&self) -> String {
                    concat!(stringify!([$field_name:Camel]), "FieldReciprocalGenerator").to_string()
                }

                fn dependencies(&self) -> Vec<Target> {
                    self.a.0.limbs.iter().map(|&l| l.0).collect()
                }

                fn run_once(
                    &self,
                    witness: &PartitionWitness<GoldilocksField>,
                    out_buffer: &mut GeneratedValues<GoldilocksField>,
                ) -> Result<(), Error> {
                    let a: BigUint = witness.[<get_ $field_name:snake field_target>](self.a.clone());
                    let p: BigUint = BigUint::[<$field_name:snake _p>]();
                    let a_inv: BigUint = a.modinv(&p).ok_or(Error::new(DivisionByZeroError {}))?;
                    out_buffer.[<set_$field_name:snake field_target>](&self.a_inv, &a_inv);
                    Ok(())
                }

                fn serialize(
                    &self,
                    dst: &mut Vec<u8>,
                    _common_data: &CommonCircuitData<GoldilocksField, 2>,
                ) -> IoResult<()> {
                    dst.write_biguint_target(self.a.0.clone())?;
                    dst.write_biguint_target(self.a_inv.0.clone())?;
                    Ok(())
                }

                fn deserialize(
                    src: &mut Buffer,
                    _common_data: &CommonCircuitData<GoldilocksField, 2>,
                ) -> IoResult<Self>
                where
                    Self: Sized,
                {
                    let a = [<$field_name:camel FieldTarget>](src.read_biguint_target()?);
                    let a_inv = [<$field_name:camel FieldTarget>](src.read_biguint_target()?);
                    Ok(Self { a, a_inv })
                }
            }


        }
    }
}

// 21888242871839275222246405745257275088548364400416034343698204186575808495617
field_builder!(
    Jubjub, (
        4026531841, 
        1138881939, 
        2042196113, 
        674490440, 
        2172737629, 
        3092268470, 
        3778125865,
        811880050
    ) 
);

// 2736030358979909402780800718157159386076813972158567259200215660948447373041
field_builder!(
    JubjubScalar, (
        958473969,
        1735563228,
        958459402,
        2873028024,
        3492817675,
        923404470,
        1546007557,
        101485006
    )
);


#[derive(Debug)]
struct DivisionByZeroError {}

impl Display for DivisionByZeroError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Attempted division by zero in some big field.")
    }
}

impl std::error::Error for DivisionByZeroError {}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use num::BigUint;
    use num::FromPrimitive;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        plonk::config::{GenericConfig, PoseidonGoldilocksConfig},
    };

    use crate::signature::jubjubfield::{
        CircuitBuilderJubjubField,
        CircuitBuilderJubjubScalarField,
        WitnessJubjubField,
        WitnessJubjubScalarField,
    };

    #[test]
    fn test_jubjubfield_arith() -> Result<()> {
        // compute and verify (1 + 1/3 + 4/3) * 3 = 8
        // 1 is one
        // x = 3, y = 4

        type C = PoseidonGoldilocksConfig;

        let config = CircuitConfig::standard_recursion_config();
        let mut pw: PartialWitness<GoldilocksField> = PartialWitness::new();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);

        let x = builder.add_virtual_jubjubfield_target();
        let y = builder.add_virtual_jubjubfield_target();
        let expected_result = builder.add_virtual_jubjubfield_target();

        let one = builder.one_jubjubfield();
        let one_over_x = builder.recip_jubjubfield(&x);
        let y_over_x = builder.div_jubjubfield(&y, &x);
        let sum_a = builder.add_jubjubfield(&one, &one_over_x);
        let sum = builder.add_jubjubfield(&sum_a, &y_over_x);
        let result = builder.mul_jubjubfield(&sum, &x);

        builder.connect_jubjubfield(&result, &expected_result);

        let x_value = BigUint::from_u32(3).unwrap();
        let y_value = BigUint::from_u32(4).unwrap();
        let expected_result_value = BigUint::from_u32(8).unwrap();

        pw.set_jubjubfield_target(&x, &x_value);
        pw.set_jubjubfield_target(&y, &y_value);
        pw.set_jubjubfield_target(&expected_result, &expected_result_value);

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof);

        Ok(())
    }

    #[test]
    fn test_jubjubfield_add() -> Result<()> {
        // compute and verify 3 + 4 = 8
        // this one is supposed to fail

        type C = PoseidonGoldilocksConfig;

        let config = CircuitConfig::standard_recursion_config();
        let mut pw: PartialWitness<GoldilocksField> = PartialWitness::new();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);

        let x = builder.add_virtual_jubjubfield_target();
        let y = builder.add_virtual_jubjubfield_target();
        let expected_result = builder.add_virtual_jubjubfield_target();

        let result = builder.add_jubjubfield(&x, &y);

        builder.connect_jubjubfield(&result, &expected_result);

        let x_value = BigUint::from_u32(3).unwrap();
        let y_value = BigUint::from_u32(4).unwrap();
        let expected_result_value = BigUint::from_u32(8).unwrap();

        pw.set_jubjubfield_target(&x, &x_value);
        pw.set_jubjubfield_target(&y, &y_value);
        pw.set_jubjubfield_target(&expected_result, &expected_result_value);

        let data = builder.build::<C>();
        let proof = data.prove(pw);
        assert!(proof.is_err());

        Ok(())
    }

    #[test]
    fn test_jubjubfield_divmul() -> Result<()> {
        type C = PoseidonGoldilocksConfig;

        let config = CircuitConfig::standard_recursion_config();
        let mut pw: PartialWitness<GoldilocksField> = PartialWitness::new();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);

        let x = builder.add_virtual_jubjubfield_target();
        let y = builder.add_virtual_jubjubfield_target();
        let expected_result = builder.add_virtual_jubjubfield_target();

        let y_over_x = builder.div_jubjubfield(&y, &x);
        let result = builder.mul_jubjubfield(&y_over_x, &x);

        builder.connect_jubjubfield(&result, &expected_result);

        let x_value = BigUint::from_u32(1).unwrap();
        let y_value = BigUint::from_u32(5).unwrap();
        let expected_result_value = BigUint::from_u32(5).unwrap();

        pw.set_jubjubfield_target(&x, &x_value);
        pw.set_jubjubfield_target(&y, &y_value);
        pw.set_jubjubfield_target(&expected_result, &expected_result_value);

        let data = builder.build::<C>();
        let try_proof = data.prove(pw);
        let proof = try_proof.unwrap();
        data.verify(proof);

        Ok(())
    }

    #[test]
    fn test_jubjubfield_muladd() -> Result<()> {
        // compute and verify (1 + 1/3 + 4/3) * 3 = 8
        // 1 is one
        // x = 3, y = 4

        type C = PoseidonGoldilocksConfig;

        let config = CircuitConfig::standard_recursion_config();
        let mut pw: PartialWitness<GoldilocksField> = PartialWitness::new();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);

        let x = builder.add_virtual_jubjubfield_target();
        let y = builder.add_virtual_jubjubfield_target();
        let expected_result = builder.add_virtual_jubjubfield_target();

        let sum = builder.mul_jubjubfield(&x, &y);
        let result = builder.add_jubjubfield(&sum, &x);

        builder.connect_jubjubfield(&result, &expected_result);

        let x_value = BigUint::from_u32(3).unwrap();
        let y_value = BigUint::from_u32(4).unwrap();
        let expected_result_value = BigUint::from_u32(15).unwrap();

        pw.set_jubjubfield_target(&x, &x_value);
        pw.set_jubjubfield_target(&y, &y_value);
        pw.set_jubjubfield_target(&expected_result, &expected_result_value);

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof);

        Ok(())
    }
    #[test]
    fn test_scalarfield_muladd() -> Result<()> {
        // compute and verify (1 + 1/3 + 4/3) * 3 = 8
        // 1 is one
        // x = 3, y = 4

        type C = PoseidonGoldilocksConfig;

        let config = CircuitConfig::standard_recursion_config();
        let mut pw: PartialWitness<GoldilocksField> = PartialWitness::new();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);

        let x = builder.add_virtual_jubjub_scalarfield_target();
        let y = builder.add_virtual_jubjub_scalarfield_target();
        let expected_result = builder.add_virtual_jubjub_scalarfield_target();

        let sum = builder.mul_jubjub_scalarfield(&x, &y);
        let result = builder.add_jubjub_scalarfield(&sum, &x);

        builder.connect_jubjub_scalarfield(&result, &expected_result);

        let x_value = BigUint::from_u32(3).unwrap();
        let y_value = BigUint::from_u32(4).unwrap();
        let expected_result_value = BigUint::from_u32(15).unwrap();

        pw.set_jubjub_scalarfield_target(&x, &x_value);
        pw.set_jubjub_scalarfield_target(&y, &y_value);
        pw.set_jubjub_scalarfield_target(&expected_result, &expected_result_value);

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof);

        Ok(())
    }
}
