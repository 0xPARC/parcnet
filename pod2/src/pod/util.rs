use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::GenericHashOut;
use plonky2::plonk::config::Hasher;

pub fn hash_string_to_field(s: &str) -> GoldilocksField {
    PoseidonHash::hash_no_pad(&str_to_fields(s)).to_vec()[0]
}

/// String-slice-to-vector converter, where the vector is one of
/// (32-bit) field elements. This splits the underlying byte vector of
/// the string into 32-bit chunks with appropriate padding.
fn str_to_fields(s: &str) -> Vec<GoldilocksField> {
    // First convert string to bytevector.
    let mut s_bv = s.as_bytes().to_vec();

    // Padding
    let padding_len = 4 - (s_bv.len() % 4);
    let padding: Vec<u8> = if padding_len == 1 {
        vec![0x01 ^ 0x80]
    } else {
        [
            vec![0x01],
            (0..(padding_len - 2)).map(|_| 0).collect::<Vec<u8>>(),
            vec![0x80],
        ]
        .concat()
    };

    // Pad
    padding.iter().for_each(|p| s_bv.push(*p));

    // Split up into chunks of length 4 and convert these to u32s
    // (big-endian convention), embedding the result in the field.
    s_bv.chunks(4)
        .map(|chunk| chunk.iter().fold(0, |acc, b| 256 * acc + *b as u32))
        .map(|n| GoldilocksField(n as u64))
        .collect()
}
