use babyjubjub_ark::Fq;
use poseidon_ark::Poseidon;

pub fn lean_poseidon_imt(inputs: &[Fq]) -> Result<Fq, &'static str> {
    let poseidon = Poseidon::new();
    
    if inputs.is_empty() {
        return Err("At least one input is required");
    }

    let mut items = inputs.to_vec();

    while items.len() > 1 {
        let mut new_items = Vec::new();
        for chunk in items.chunks(2) {
            if chunk.len() == 2 {
                let hash = poseidon.hash(vec![chunk[0].clone(), chunk[1].clone()]).map_err(|_| "Error hashing")?;
                new_items.push(hash);
            } else {
                new_items.push(chunk[0].clone());
            }
        }
        items = new_items;
    }

    Ok(items[0])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use babyjubjub_ark::Fq;

    type Error = Box<dyn std::error::Error>;
    
    #[test]
    fn test_lean_imt() -> Result<(), Error> {
        let inputs = ["1", "2", "3", "4", "5"].into_iter().map(|s| Fq::from_str(s)).collect::<Result<Vec<_>, ()>>().map_err(|_| "Error converting strings to fields.")?;

        let result = lean_poseidon_imt(&inputs);
        assert!(result.is_ok());
        let hash = result.unwrap();
        assert_eq!(
            hash,
            Fq::from_str(
                "11512324111804726054755717642058292259866309947044530224809882918003853859592"
            )
            .expect("can't parse")
        );

        Ok(())
    }

    #[test]
    fn test_lean_imt_single_input() {
        let inputs = vec![Fq::from(42)];
        let result = lean_poseidon_imt(&inputs);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Fq::from(42));
    }

    #[test]
    fn test_lean_imt_empty_input() {
        let inputs: Vec<Fq> = vec![];
        let result = lean_poseidon_imt(&inputs);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "At least one input is required");
    }
}
