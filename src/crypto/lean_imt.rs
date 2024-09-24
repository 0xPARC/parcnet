use crate::crypto::poseidon_hash::hash_bigints;
use num_bigint::BigInt;

pub fn lean_imt(inputs: &[BigInt]) -> Result<BigInt, &'static str> {
    if inputs.is_empty() {
        return Err("At least one input is required");
    }

    let mut items = inputs.to_vec();

    while items.len() > 1 {
        let mut new_items = Vec::new();
        for chunk in items.chunks(2) {
            if chunk.len() == 2 {
                let hash = hash_bigints(&[chunk[0].clone(), chunk[1].clone()])?;
                new_items.push(hash);
            } else {
                new_items.push(chunk[0].clone());
            }
        }
        items = new_items;
    }

    Ok(items[0].clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigInt;
    use std::str::FromStr;

    #[test]
    fn test_lean_imt() {
        let input_strs = vec!["1", "2", "3", "4", "5"];
        let inputs: Vec<BigInt> = input_strs
            .iter()
            .map(|s| BigInt::from_str(s).unwrap())
            .collect();

        let result = lean_imt(&inputs);
        assert!(result.is_ok());
        let hash = result.unwrap();
        assert_eq!(
            hash,
            BigInt::from_str(
                "11512324111804726054755717642058292259866309947044530224809882918003853859592"
            )
            .expect("can't parse")
        );
    }

    #[test]
    fn test_lean_imt_single_input() {
        let inputs = vec![BigInt::from(42)];
        let result = lean_imt(&inputs);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), BigInt::from(42));
    }

    #[test]
    fn test_lean_imt_empty_input() {
        let inputs: Vec<BigInt> = vec![];
        let result = lean_imt(&inputs);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "At least one input is required");
    }
}
