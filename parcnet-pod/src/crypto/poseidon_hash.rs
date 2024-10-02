use num_bigint::BigInt;
use num_traits::Num;

use ff::PrimeField;
use poseidon_rs::{Fr, FrRepr, Poseidon};

fn bigint_to_fr(input: &BigInt) -> Fr {
    Fr::from_str(&input.to_string()).expect("Can't parse")
}

pub fn hash_bigints(inputs: &[BigInt]) -> Result<BigInt, &'static str> {
    if inputs.is_empty() {
        return Err("At least one input is required");
    }

    let poseidon = Poseidon::new();

    let input_fr: Vec<Fr> = inputs.iter().map(bigint_to_fr).collect();
    let hash = poseidon.hash(input_fr).map_err(|_| "Hashing failed")?;
    BigInt::from_str_radix(&hash.into_repr().to_string()[2..], 16)
        .map_err(|_| "Recover failed")
}

pub fn hash_int(int: i64) -> Result<BigInt, &'static str> {
    let uint: u64 = int as u64;
    let poseidon = Poseidon::new();

    let input_fr: Vec<Fr> = vec![Fr::from_repr(FrRepr::from(uint)).expect("can't parse")];
    let hash = poseidon.hash(input_fr).map_err(|_| "Hashing failed")?;
    BigInt::from_str_radix(&hash.into_repr().to_string()[2..], 16)
        .map_err(|_| "Recover failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn poseidon_hashing_2() {
        let input_strs = ["10", "20"];
        let inputs: Vec<BigInt> = input_strs
            .iter()
            .map(|s| BigInt::from_str(s).unwrap())
            .collect();
        let result = hash_bigints(&inputs);
        println!("result: {:?}", result);
        assert!(result.is_ok());
        let hash = result.unwrap();
        assert_eq!(
            hash.to_string(),
            "18520321019059006606511285595387750999043784958310087972051959520693448686063"
        );
    }
    #[test]
    fn poseidon_hashing_5() {
        let input_strs = ["10", "20", "30", "40", "50"];
        let inputs: Vec<BigInt> = input_strs
            .iter()
            .map(|s| BigInt::from_str(s).unwrap())
            .collect();
        let result = hash_bigints(&inputs);
        assert!(result.is_ok(), "Hashing failed");
        let hash = result.unwrap();
        assert_eq!(
            hash.to_string(),
            "14653700270114866156633892456692636108484330116476754215161758865742162164337"
        );
    }
    #[test]
    fn poseidon_hashing_big_values() {
        let input_strs = ["21284615185148058744145464869213078561432375102652127788101832398797259209749",
            "493923605195559733225268361260412516711970622262219802173917286605681055359",
            "16508917144752610602145963506823743115557101240265470506805505298395529637033",
            "18631654747796370155722974221085383534170330422926471002342567715267253236113",
            "17853941289740592551682164141790101668489478619664963356488634739728685875777"];
        let inputs: Vec<BigInt> = input_strs
            .iter()
            .map(|s| BigInt::from_str(s).unwrap())
            .collect();
        let result = hash_bigints(&inputs);
        assert!(result.is_ok(), "Hashing failed");
        let hash = result.unwrap();
        assert_eq!(
            hash.to_string(),
            "19432550535671177537417603483730386919598951173621560603290691481135423501260"
        );
    }
}
