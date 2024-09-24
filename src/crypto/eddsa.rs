use crate::crypto::blake512::blake512::Blake512;
use crate::crypto::poseidon_hash::hash_bigints;
use num_bigint::BigInt;

lazy_static! {
    static ref P: BigInt = BigInt::parse_bytes(
        b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10
    )
    .unwrap();
    static ref ORDER: BigInt = BigInt::parse_bytes(
        b"21888242871839275222246405745257275088614511777268538073601725287587578984328",
        10
    )
    .unwrap();
    static ref SUB_ORDER: BigInt = &*ORDER >> 3;
    static ref BJ_A: BigInt = BigInt::from(168700);
    static ref BJ_D: BigInt = BigInt::from(168696);
    static ref BASE8: (BigInt, BigInt) = (
        BigInt::parse_bytes(
            b"5299619240641551281634865583518297030282874472190772894086521144482721001553",
            10
        )
        .unwrap(),
        BigInt::parse_bytes(
            b"16950150798460657717958625567821834550301663161624707787222815936182638968203",
            10
        )
        .unwrap(),
    );
}

fn modulus(a: &BigInt, b: &BigInt) -> BigInt {
    let mut out = a % b;
    if out.sign() == num_bigint::Sign::Minus {
        out += b;
    }
    out
}

fn inv(a: &BigInt, n: &BigInt) -> BigInt {
    if *a == BigInt::from(0) {
        return BigInt::from(0);
    }
    let mut lm = BigInt::from(1);
    let mut hm = BigInt::from(0);
    let mut low = a % n;
    let mut high = n.clone();
    while low > BigInt::from(1) {
        let r = &high / &low;
        let nm = &hm - &lm * &r;
        let new = &high - &low * &r;
        hm = lm;
        lm = nm;
        high = low;
        low = new;
    }

    let out = modulus(&lm, n);
    out
}

fn add_bj(p1: &(BigInt, BigInt), p2: &(BigInt, BigInt)) -> (BigInt, BigInt) {
    let (x1, y1) = p1;
    let (x2, y2) = p2;

    let x3 = modulus(&(x1 * y2 + y1 * x2), &*P)
        * inv(
            &modulus(&(BigInt::from(1) + &*BJ_D * x1 * x2 * y1 * y2), &*P),
            &*P,
        );
    let y3 = modulus(&(y1 * y2 - &*BJ_A * x1 * x2), &*P)
        * inv(
            &modulus(&((&*P + 1) - &*BJ_D * x1 * x2 * y1 * y2), &*P),
            &*P,
        );
    let out = (modulus(&x3, &*P), modulus(&y3, &*P));
    return out;
}

fn multiply_bj(pt: &(BigInt, BigInt), n: &BigInt) -> Option<(BigInt, BigInt)> {
    if *n == BigInt::from(0) {
        None
    } else if *n == BigInt::from(1) {
        Some(pt.clone())
    } else if n % 2 == BigInt::from(0) {
        multiply_bj(&add_bj(pt, pt), &(n / 2))
    } else {
        Some(add_bj(&multiply_bj(&add_bj(pt, pt), &(n / 2)).unwrap(), pt))
    }
}

fn pack_point(a: &(BigInt, BigInt)) -> Vec<u8> {
    let mut buff = a.1.to_bytes_le().1;
    buff.resize(32, 0);
    let pm1d2 = (&*P - 1) * inv(&BigInt::from(2), &*P) % &*P;
    if a.0 > pm1d2 {
        buff[31] |= 0x80;
    }
    buff
}

pub fn eddsa_poseidon_sign(
    private_key: &[u8],
    message: &BigInt,
) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    let mut hasher = Blake512::default();
    hasher.write(private_key);
    let mut s_buff = hasher.digest(&[]);
    // println!("s_buff_length: {:?}", s_buff.len());

    // let mut s_buff = s_buff[..32].to_vec();
    s_buff[0] &= 0xF8;
    s_buff[31] &= 0x7F;
    s_buff[31] |= 0x40;

    // println!("s_buff: {:?}", hex::encode(&s_buff));

    let s = BigInt::from_bytes_le(num_bigint::Sign::Plus, &s_buff[..32]);
    let a = multiply_bj(&BASE8, &(s.clone() >> 3)).unwrap();

    let mut message_bytes = message.to_bytes_le().1;
    message_bytes.resize(32, 0);
    hasher = Blake512::default();
    hasher.write(&[&s_buff[32..], &message_bytes].concat());
    let r_buff = hasher.digest(&[]);

    let r = BigInt::from_bytes_le(num_bigint::Sign::Plus, &r_buff) % &*SUB_ORDER;
    let r8 = multiply_bj(&BASE8, &r).unwrap();

    let hm_inputs = vec![
        r8.0.clone(),
        r8.1.clone(),
        a.0.clone(),
        a.1.clone(),
        message.clone(),
    ];
    let hms = hash_bigints(&hm_inputs)?;

    let s = (r + hms * s) % &*SUB_ORDER;

    Ok((
        pack_point(&a),
        [pack_point(&r8), s.to_bytes_le().1].concat(),
    ))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use rand::Rng;

    #[test]
    fn test_eddsa_poseidon_sign() {
        let mut rng = rand::thread_rng();
        let private_key: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        let message = BigInt::from(1234567890u64);

        let result = eddsa_poseidon_sign(&private_key, &message);
        assert!(result.is_ok());

        let (public_key, signature) = result.unwrap();
        assert_eq!(public_key.len(), 32);
        assert_eq!(signature.len(), 64);
    }

    #[test]
    fn test_eddsa_poseidon_sign_eq() {
        let private_key: Vec<u8> = vec![0u8; 32];
        let message = hash_bigints(&[BigInt::from_str("10").expect("couldn't parse")])
            .expect("couldn't hash");

        let result = eddsa_poseidon_sign(&private_key, &message);
        assert!(result.is_ok());

        let (public_key, signature) = result.unwrap();
        assert_eq!(
            hex::encode(public_key),
            "91f1095ac019b50610b5cb56e5db3889177fee8b6422fca3dac04ee1932431a9"
        );
        assert_eq!(hex::encode(signature), "7fd6ab0bb4d859041339dde68d4a8e0ca15dd2e69e93ce074d465dbe048d17816ea920722a6e45fc03e21f5ce134dc7e87fe286b75290c88715643899fd68305");
    }

    #[test]
    fn inverse() {
        let a = BigInt::from_str(
            "13529330156957644146045673109750715822928191475445190942770658897954000469567",
        )
        .expect("can't parse");
        let b = BigInt::from_str(
            "218882428718392752222464057452572750885483644004160343436982041865758084956173",
        )
        .expect("can't parse");
        let inverse = inv(&a, &b);
        assert_eq!(
            inverse,
            BigInt::from_str(
                "205552321126743905863968109351884036780787092210808746100052953458322174595384"
            )
            .expect("can't parse")
        );
    }
}
