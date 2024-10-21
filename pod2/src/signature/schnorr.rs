/// code forked from https://github.com/tideofwords/schnorr
use log::info;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::field::types::PrimeField64;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::Hasher;
use rand::Rng;
use serde::Deserialize;
use serde::Serialize;

const BIG_GROUP_GEN: GoldilocksField = GoldilocksField(14293326489335486720);

// No ZK here.
// This is just a simple implementation of Schnorr signatures:
// keygen, sign, and verify.

// 8-bit security (i.e. totally insecure, DO NOT USE if you want any security at all)
// because it uses the multiplicative group of the Goldilocks field

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct SchnorrSigner {
    prime_group_gen: GoldilocksField,
    prime_group_order: u64,
}

#[derive(Copy, Clone, Debug, PartialEq)]

pub struct SchnorrSecretKey {
    pub sk: u64,
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SchnorrPublicKey {
    pub pk: GoldilocksField,
}

#[derive(Copy, Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct SchnorrSignature {
    pub s: u64,
    pub e: u64,
}

impl SchnorrSigner {
    pub fn new() -> Self {
        let quotient_order: u64 = (1 << 48) - (1 << 32);
        let prime_group_gen: GoldilocksField = Self::pow(BIG_GROUP_GEN, quotient_order);
        let prime_group_order: u64 = (1 << 16) + 1;
        SchnorrSigner {
            prime_group_gen,
            prime_group_order,
        }
    }

    pub fn pow(x: GoldilocksField, a: u64) -> GoldilocksField {
        let mut a_copy = a;
        let mut res = GoldilocksField(1);
        let mut x_pow_2n = x;
        while a_copy > 0 {
            if a_copy % 2 != 0 {
                res *= x_pow_2n;
            }
            a_copy /= 2;
            x_pow_2n *= x_pow_2n;
        }
        res
    }

    pub fn keygen(&self, sk: &SchnorrSecretKey) -> SchnorrPublicKey {
        let pk: GoldilocksField = Self::pow(self.prime_group_gen, sk.sk).inverse();
        // self.PRIME_GROUP_GEN is 6612579038192137166
        SchnorrPublicKey { pk }
    }

    pub fn hash_insecure(&self, r: &GoldilocksField, msg: &[GoldilocksField]) -> u64 {
        let poseidon_input: Vec<GoldilocksField> =
            std::iter::once(r).chain(msg.iter()).copied().collect();

        let h = PoseidonHash::hash_no_pad(&poseidon_input);
        h.elements[0].to_canonical_u64() % self.prime_group_order
    }

    pub fn rand_group_multiplier(&self, rng: &mut rand::rngs::ThreadRng) -> u64 {
        let group_order: u64 = (1 << 16) + 1;
        rng.gen_range(0..group_order)
    }

    pub fn u64_into_goldilocks_vec(&self, msg: Vec<u64>) -> Vec<GoldilocksField> {
        msg.into_iter()
            .map(GoldilocksField::from_noncanonical_u64)
            .collect()
    }

    pub fn sign(
        &self,
        msg: &[GoldilocksField],
        sk: &SchnorrSecretKey,
        rng: &mut rand::rngs::ThreadRng,
    ) -> SchnorrSignature {
        let k: u64 = self.rand_group_multiplier(rng);
        let r: GoldilocksField = Self::pow(self.prime_group_gen, k);
        let e: u64 = self.hash_insecure(&r, msg);
        info!("[SIGN] msg is: {:?}", msg);
        assert!(k < self.prime_group_order);
        assert!(sk.sk < self.prime_group_order);
        assert!(e < self.prime_group_order);
        let mut s128: u128 = (k as u128) + (sk.sk as u128) * (e as u128);
        s128 %= self.prime_group_order as u128;
        let s: u64 = s128 as u64;
        SchnorrSignature { e, s }
    }

    pub fn verify(
        &self,
        sig: &SchnorrSignature,
        msg: &Vec<GoldilocksField>,
        pk: &SchnorrPublicKey,
    ) -> bool {
        let r: GoldilocksField = Self::pow(self.prime_group_gen, sig.s) * Self::pow(pk.pk, sig.e);
        let e_v: u64 = self.hash_insecure(&r, msg);
        info!("[VERIFY] msg is: {:?}", msg);
        e_v == sig.e
    }
}

impl Default for SchnorrSigner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use plonky2::field::goldilocks_field::GoldilocksField;

    use super::{SchnorrPublicKey, SchnorrSecretKey, SchnorrSignature, SchnorrSigner};

    use log::info;

    #[test]
    fn test_pow() {
        let g = GoldilocksField(3);
        let res = GoldilocksField(16305451354880172407);
        assert_eq!(res, SchnorrSigner::pow(g, 1234567));
    }

    #[test]
    fn test_sig() {
        let mut rng: rand::rngs::ThreadRng = rand::thread_rng();
        let ss = SchnorrSigner::new();
        let sk: SchnorrSecretKey = SchnorrSecretKey { sk: 1422 };
        let pk: SchnorrPublicKey = ss.keygen(&sk);

        let msg0_u64: Vec<u64> = vec![17, 123985, 3, 12];
        let msg0: Vec<GoldilocksField> = ss.u64_into_goldilocks_vec(msg0_u64);
        let sig: SchnorrSignature = ss.sign(&msg0, &sk, &mut rng);
        let res: bool = ss.verify(&sig, &msg0, &pk);
        info!("Trying to verify:");
        info!("Secret key: {:?}", sk);
        info!("Public key: {:?}", pk);
        info!("Signature: {:?}", sig);
        assert!(res);
    }

    #[test]
    fn test_sig_2() {
        info!("=================TEST SIG 2=================");
        let mut rng: rand::rngs::ThreadRng = rand::thread_rng();
        let ss = SchnorrSigner::new();
        let sk: SchnorrSecretKey = SchnorrSecretKey { sk: 25 };
        let pk: SchnorrPublicKey = ss.keygen(&sk);

        let msg0_u64: Vec<u64> = vec![
            8066043497359175718,
            9159038346762061233,
            1329333430040973227,
            36,
            16682101190217481272,
            52,
        ];
        let msg0: Vec<GoldilocksField> = ss.u64_into_goldilocks_vec(msg0_u64);
        let sig: SchnorrSignature = ss.sign(&msg0, &sk, &mut rng);
        let res: bool = ss.verify(&sig, &msg0, &pk);
        info!("Trying to verify:");
        info!("Secret key: {:?}", sk);
        info!("Public key: {:?}", pk);
        info!("Signature: {:?}", sig);
        assert!(res);
    }
}
