use std::array;

use super::Fq;
use ark_std::str::FromStr;
use babyjubjub_ark::{decompress_point, Point};
use base64::{engine::general_purpose, Engine};
use num_traits::Num;
use ark_ff::PrimeField;


pub fn fq_to_string(x: &Fq) -> String {
    x.into_bigint().to_string()
}

pub fn null_ser<S>(s: S) -> Result<S::Ok, S::Error> where S: serde::Serializer {
    s.serialize_none()
}

pub fn null_de<'de, D>(data: D) -> Result<(), D::Error> where D: serde::de::Deserializer<'de> {
    let _: Option<()> = serde::de::Deserialize::deserialize(data)?;
    Ok(())
}

/// Serialisation procedure for elements of Fq. Yields a decimal string.
pub fn fq_ser<S>(x: &Fq, s: S) -> Result<S::Ok, S::Error> where S: serde::Serializer {
    s.serialize_str(&fq_to_string(x))
}

/// Deserialisation procedure for elements of Fq. Parses decimal and
/// hexadecimal strings. The latter must be prefixed with "0x".
pub fn fq_de<'de, D>(data: D) -> Result<Fq, D::Error> where D: serde::de::Deserializer<'de> {
    let s: &str = serde::de::Deserialize::deserialize(data)?;
    if &s[0..2] == "0x" {
        num_bigint::BigUint::from_str_radix(&s[2..], 16)
    } else {
        num_bigint::BigUint::from_str(s)
    }.map_err(serde::de::Error::custom).map(Fq::from)
}

/// Serialisation procedure for points (elements of Fq x Fq). Yields an unpadded Base64 string
/// representing the compressed point.
pub fn compressed_pt_ser<S>(pt: &Point, s: S) -> Result<S::Ok, S::Error> where S: serde::Serializer {
    let pt_string = general_purpose::STANDARD_NO_PAD.encode(pt.compress());
    s.serialize_str(&pt_string)
}

/// Deserialisation procedure for points.
pub fn compressed_pt_de<'de, D>(data: D) -> Result<Point, D::Error> where D: serde::de::Deserializer<'de> {
    let s: &str = serde::de::Deserialize::deserialize(data)?;
    let compressed_pt_bytes = general_purpose::STANDARD_NO_PAD.decode(s).map_err(serde::de::Error::custom)?;
    decompress_point(array::from_fn(|i| compressed_pt_bytes[i])).map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod tests {
    use crate::pod::Error;
    use super::*;
    
#[test]
fn serde_json_test() -> Result<(), Error> {
    let x = fq_de(&mut serde_json::Deserializer::from_str("\"0x1d5ac1f31407018b7d413a4f52c8f74463b30e6ac2238220ad8b254de4eaa3a2\""))?;
    let y = fq_de(&mut serde_json::Deserializer::from_str("\"0x1e1de8a908826c3f9ac2e0ceee929ecd0caf3b99b3ef24523aaab796a6f733c4\""))?;
    let example_pt = Point { x,y };
    let mut json_buffer = Vec::new();
    compressed_pt_ser(&example_pt, &mut serde_json::Serializer::new(&mut json_buffer))?;
    let json_string = String::from_utf8(json_buffer)?;
    assert!(json_string == "\"xDP3ppa3qjpSJO+zmTuvDM2eku7O4MKaP2yCCKnoHZ4\"");
    let deserialised_example_pt = compressed_pt_de(
        &mut serde_json::Deserializer::from_str(&json_string)
    )?;
    assert!(deserialised_example_pt == example_pt);
    Ok(())
}
}
