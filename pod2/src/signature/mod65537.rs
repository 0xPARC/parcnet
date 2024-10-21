/// code forked from https://github.com/tideofwords/schnorr
use anyhow::Result;

use plonky2::field::{
    goldilocks_field::GoldilocksField,
    types::{Field, PrimeField64},
};
use plonky2::iop::{
    generator::{GeneratedValues, SimpleGenerator},
    target::Target,
    witness::{PartitionWitness, Witness, WitnessWrite},
};
use plonky2::plonk::{circuit_builder::CircuitBuilder, circuit_data::CommonCircuitData};
use plonky2::util::serialization::{Buffer, IoResult, Read, Write};

type GoldF = GoldilocksField;

// Helper function to constrain r = a % 65537 in a plonky2 circuit.

#[derive(Debug, Default)]
pub struct Mod65537Generator {
    a: Target,
    q: Target,
    r: Target,
}

impl SimpleGenerator<GoldF, 2> for Mod65537Generator {
    fn id(&self) -> String {
        "Mod65537Generator".to_string()
    }
    fn dependencies(&self) -> Vec<Target> {
        vec![self.a]
    }

    fn run_once(
        &self,
        witness: &PartitionWitness<GoldF>,
        out_buffer: &mut GeneratedValues<GoldF>,
    ) -> Result<()> {
        let a = witness.get_target(self.a);
        let a64 = a.to_canonical_u64();
        let q64 = a64 / 65537;
        let r64 = a64 % 65537;

        out_buffer.set_target(self.q, GoldF::from_canonical_u64(q64))?;
        out_buffer.set_target(self.r, GoldF::from_canonical_u64(r64))?;

        Ok(())
    }

    fn serialize(
        &self,
        dst: &mut Vec<u8>,
        _common_data: &CommonCircuitData<GoldF, 2>,
    ) -> IoResult<()> {
        dst.write_target(self.a)?;
        dst.write_target(self.q)?;
        dst.write_target(self.r)?;
        Ok(())
    }

    fn deserialize(src: &mut Buffer, _common_data: &CommonCircuitData<GoldF, 2>) -> IoResult<Self>
    where
        Self: Sized,
    {
        let a = src.read_target()?;
        let q = src.read_target()?;
        let r = src.read_target()?;
        Ok(Self { a, q, r })
    }
}

pub struct Mod65537Builder {}

impl Mod65537Builder {
    // Reduce a modulo the constant 65537
    // where a is the canonical representative for an element of the field
    // (meaning: 0 \leq a < p)

    // To prove this, write
    // a = 65537 * q + r, and do range checks to check that:
    // 0 <= q <= floor(p / 65537)
    // 0 <= r < 65537
    // (these first two checks guarantee that a lies in the range [0, p + 65536])
    // if q = floor(p / 65537) then r = 0
    // (note that p % 65537 == 1 so this is the only possibility)
    pub(crate) fn mod_65537(builder: &mut CircuitBuilder<GoldF, 2>, a: Target) -> Target {
        let q = builder.add_virtual_target();
        let r = builder.add_virtual_target();

        // the Mod65537Generator will assign values to q and r later
        builder.add_simple_generator(Mod65537Generator { a, q, r });

        // impose four constraints
        // 1. a = 65537 * q + r
        let t65537 = builder.constant(GoldF::from_canonical_u64(65537));
        let a_copy = builder.mul_add(t65537, q, r);
        builder.connect(a, a_copy);

        // 2. 0 <= q <= floor(p / 65537)
        // max_q is 281470681743360 = floor(p / 65537) = (p-1) / 65537 = 2^48 - 2^32
        let max_q = builder.constant(GoldF::from_canonical_u64(281470681743360));
        builder.range_check(q, 48);
        let diff_q = builder.sub(max_q, q);
        builder.range_check(diff_q, 48);

        // 3. 0 <= r < 65537
        let max_r = builder.constant(GoldF::from_canonical_u64(65537));
        builder.range_check(r, 17);
        let diff_r = builder.sub(max_r, r);
        builder.range_check(diff_r, 17);

        // 4. if q = floor(p / 65537) then r = 0
        let q_equals_max = builder.is_equal(q, max_q);
        let prod_temp = builder.mul(q_equals_max.target, r);
        let zero_temp = builder.zero();
        builder.connect(prod_temp, zero_temp);

        // throw in the Generator to tell builder how to compute r
        builder.add_simple_generator(Mod65537Generator { a, q, r });

        r
    }
}

#[cfg(test)]
mod tests {
    use super::Mod65537Builder;
    use plonky2::field::{goldilocks_field::GoldilocksField, types::Field};
    use plonky2::iop::{target::Target, witness::PartialWitness};
    use plonky2::plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitConfig,
        config::{GenericConfig, PoseidonGoldilocksConfig},
    };

    #[test]
    fn test_mod65537() {
        const D: usize = 2;
        const P: u64 = 18446744069414584321; // the Goldilocks prime
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let a64: Vec<u64> = vec![0, 1, 2, 65535, 65536, 65537, P - 4, P - 3, P - 2, P - 1];

        let a: Vec<Target> = a64
            .iter()
            .map(|x| builder.constant(GoldilocksField::from_canonical_u64(*x)))
            .collect();

        let r: Vec<Target> = a
            .iter()
            .map(|targ| Mod65537Builder::mod_65537(&mut builder, *targ))
            .collect();

        // check that the outputs are correct,
        // obviously you don't need this in your own code
        let r_expected64: Vec<u64> = a64.iter().map(|x| x % 65537).collect();
        println!("Expected residues mod 64: {:?}", r_expected64);
        let r_expected: Vec<Target> = r_expected64
            .iter()
            .map(|x| builder.constant(GoldilocksField::from_canonical_u64(*x)))
            .collect();
        r.iter()
            .zip(r_expected.iter())
            .for_each(|(x, y)| builder.connect(*x, *y));

        let pw: PartialWitness<F> = PartialWitness::new();
        let data = builder.build::<C>();
        let _proof = data.prove(pw).unwrap();
    }
}
