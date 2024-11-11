use chrono::Local;
use num::BigUint;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::iop::target::BoolTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use std::str::FromStr;

use crate::signature::biguint::{BigUintTarget, CircuitBuilderBiguint};
use crate::signature::jubjubfield::{CircuitBuilderJubjubField, JubjubFieldTarget};

#[derive(Clone, Debug)]
pub struct JubjubCurveTarget {
    pub x: JubjubFieldTarget,
    pub y: JubjubFieldTarget,
}

pub struct JubjubConstantsTarget {
    pub a: JubjubFieldTarget,
    pub d: JubjubFieldTarget,
}

pub trait CircuitBuilderJubjubCurve {
    fn jubjub_constants(&mut self) -> JubjubConstantsTarget;

    fn connect_jubjub_curve(&mut self, a: &JubjubCurveTarget, b: &JubjubCurveTarget);

    fn is_equal_jubjub_curve(
        &mut self, 
        a: &JubjubCurveTarget, 
        b: &JubjubCurveTarget
    ) -> BoolTarget;

    fn zero_jubjub_curve(&mut self) -> JubjubCurveTarget;

    fn B8_jubjub_curve(&mut self) -> JubjubCurveTarget;

    fn add_jubjub_curve(
        &mut self,
        p: &JubjubCurveTarget,
        q: &JubjubCurveTarget,
    ) -> JubjubCurveTarget;

    fn multiplex_biguint(
        &mut self,
        a0: &BigUintTarget,
        a1: &BigUintTarget,
        sel: BoolTarget,
    ) -> BigUintTarget;

    fn multiplex_jubjub_curve(
        &mut self,
        a0: &JubjubCurveTarget,
        a1: &JubjubCurveTarget,
        sel: BoolTarget,
    ) -> JubjubCurveTarget;

    fn verify_jubjub_point(&mut self, p: &JubjubCurveTarget);

    fn mul_scalar(&mut self, p: &JubjubCurveTarget, s: &BigUintTarget) -> JubjubCurveTarget;
}

impl CircuitBuilderJubjubCurve for CircuitBuilder<GoldilocksField, 2> {
    fn jubjub_constants(&mut self) -> JubjubConstantsTarget {
        let a_val = BigUint::from_str("168700").unwrap();
        let d_val = BigUint::from_str("168696").unwrap();
        let a = JubjubFieldTarget(self.constant_biguint(&a_val));
        let d = JubjubFieldTarget(self.constant_biguint(&d_val));
        JubjubConstantsTarget { a, d }
    }

    fn connect_jubjub_curve(&mut self, a: &JubjubCurveTarget, b: &JubjubCurveTarget) {
        self.connect_jubjubfield(&a.x, &b.x);
        self.connect_jubjubfield(&a.y, &b.y);
    }

    fn is_equal_jubjub_curve(
        &mut self, 
        a: &JubjubCurveTarget, 
        b: &JubjubCurveTarget
    ) -> BoolTarget {
        let x_is_equal = self.is_equal_jubjubfield(&a.x, &b.x).target;
        let y_is_equal = self.is_equal_jubjubfield(&a.y, &b.y).target;
        let result_is_equal = self.mul(x_is_equal, y_is_equal);
        BoolTarget::new_unsafe(result_is_equal)
    }

    fn zero_jubjub_curve(&mut self) -> JubjubCurveTarget {
        let x = self.zero_jubjubfield();
        let y = self.one_jubjubfield();
        JubjubCurveTarget { x, y }
    }

    fn B8_jubjub_curve(&mut self) -> JubjubCurveTarget {
        let x_val = BigUint::from_str(
            "5299619240641551281634865583518297030282874472190772894086521144482721001553",
        )
        .unwrap();
        let y_val = BigUint::from_str(
            "16950150798460657717958625567821834550301663161624707787222815936182638968203",
        )
        .unwrap();
        let x = JubjubFieldTarget(self.constant_biguint(&x_val));
        let y = JubjubFieldTarget(self.constant_biguint(&y_val));
        JubjubCurveTarget { x, y }
    }

    fn verify_jubjub_point(&mut self, p: &JubjubCurveTarget) {
        // a x^2 + y^2 = 1 + d x^2 y^2
        let JubjubConstantsTarget { a, d } = self.jubjub_constants();

        let x2 = self.mul_jubjubfield(&p.x, &p.x);
        let first_term = self.mul_jubjubfield(&a, &x2);
        let y2 = self.mul_jubjubfield(&p.y, &p.y);
        let lhs = self.add_jubjubfield(&first_term, &y2);

        let one = self.one_jubjubfield();
        let x2y2 = self.mul_jubjubfield(&x2, &y2);
        let last_term = self.mul_jubjubfield(&d, &x2y2);
        let rhs = self.add_jubjubfield(&one, &last_term);

        self.connect_jubjubfield(&lhs, &rhs);
    }

    fn add_jubjub_curve(
        &mut self,
        p: &JubjubCurveTarget,
        q: &JubjubCurveTarget,
    ) -> JubjubCurveTarget {
        // lamb = d * p.x * q.x * p.y * q.y
        // res.x = (p.x * q.y + p.y * q.x) / (1 + lamb)
        // res.y = (p.y * q.y - a * p.x * q.x) / (1 - lamb)
        let JubjubConstantsTarget { a, d } = self.jubjub_constants();

        let pxqy = self.mul_jubjubfield(&p.x, &q.y);
        let pyqx = self.mul_jubjubfield(&p.y, &q.x);
        let prod4 = self.mul_jubjubfield(&pxqy, &pyqx);
        let lambda = self.mul_jubjubfield(&d, &prod4);

        let one = self.one_jubjubfield();
        let x_num = self.add_jubjubfield(&pxqy, &pyqx);
        let x_den = self.add_jubjubfield(&one, &lambda);
        let res_x = self.div_jubjubfield(&x_num, &x_den);

        let pyqy = self.mul_jubjubfield(&p.y, &q.y);
        let pxqx = self.mul_jubjubfield(&p.x, &q.x);
        let apxqx = self.mul_jubjubfield(&a, &pxqx);
        let y_num = self.sub_jubjubfield(&pyqy, &apxqx);
        let y_den = self.sub_jubjubfield(&one, &lambda);
        let res_y = self.div_jubjubfield(&y_num, &y_den);

        JubjubCurveTarget { x: res_x, y: res_y }
    }

    fn multiplex_biguint(
        &mut self,
        a0: &BigUintTarget,
        a1: &BigUintTarget,
        sel: BoolTarget,
    ) -> BigUintTarget {
        let sel_opp = self.not(sel);
        let term0 = self.mul_biguint_by_bool(a0, sel_opp);
        let term1 = self.mul_biguint_by_bool(a1, sel);
        self.add_biguint(&term0, &term1)
    }

    fn multiplex_jubjub_curve(
        &mut self,
        a0: &JubjubCurveTarget,
        a1: &JubjubCurveTarget,
        sel: BoolTarget,
    ) -> JubjubCurveTarget {
        let x = self.multiplex_biguint(&a0.x.0, &a1.x.0, sel);
        let y = self.multiplex_biguint(&a0.y.0, &a1.y.0, sel);
        JubjubCurveTarget {
            x: JubjubFieldTarget(x),
            y: JubjubFieldTarget(y),
        }
    }

    fn mul_scalar(&mut self, p: &JubjubCurveTarget, s: &BigUintTarget) -> JubjubCurveTarget {
        // split s into bits
        let s_bits: Vec<BoolTarget> = s
            .limbs
            .iter()
            .flat_map(|limb| self.split_le(limb.0, 32))
            .collect();
        assert!(s_bits.len() <= 256);
        // compute powers of 2 times p
        // 0 to 255
        let mut p_muls: Vec<JubjubCurveTarget> = Vec::new();
        p_muls.push(p.clone());
        for _ in 1..s_bits.len() {
            let next = self.add_jubjub_curve(&p_muls[p_muls.len() - 1], &p_muls[p_muls.len() - 1]);
            p_muls.push(next);
        }

        // conditional mul-add
        let mut p_muls_conditional: Vec<JubjubCurveTarget> = Vec::new();
        let zero = self.zero_jubjub_curve();
        for idx in 0..s_bits.len() {
            p_muls_conditional.push(self.multiplex_jubjub_curve(&zero, &p_muls[idx], s_bits[idx]))
        }
        let mut p_muls_cml_sums: Vec<JubjubCurveTarget> = Vec::new();
        p_muls_cml_sums.push(self.zero_jubjub_curve());
        for idx in 0..s_bits.len() {
            p_muls_cml_sums.push(self.add_jubjub_curve(
                &p_muls_cml_sums[p_muls_cml_sums.len() - 1],
                &p_muls_conditional[idx],
            ));
        }

        p_muls_cml_sums.pop().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use chrono::Local;
    use num::BigUint;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use std::str::FromStr;

    use crate::signature::biguint::CircuitBuilderBiguint;
    use crate::signature::jubjubcurve::{CircuitBuilderJubjubCurve, JubjubCurveTarget};
    use crate::signature::jubjubfield::{CircuitBuilderJubjubField, JubjubFieldTarget};

    #[test]
    fn test_verify_jubjub_point() {
        type C = PoseidonGoldilocksConfig;

        let config = CircuitConfig::standard_recursion_config();
        let pw: PartialWitness<GoldilocksField> = PartialWitness::new();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);

        let x_val = BigUint::from_str(
            "5299619240641551281634865583518297030282874472190772894086521144482721001553",
        )
        .unwrap();
        let y_val = BigUint::from_str(
            "16950150798460657717958625567821834550301663161624707787222815936182638968203",
        )
        .unwrap();
        let x = JubjubFieldTarget(builder.constant_biguint(&x_val));
        let y = JubjubFieldTarget(builder.constant_biguint(&y_val));
        let p = JubjubCurveTarget { x, y };

        builder.verify_jubjub_point(&p);

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof);
    }

    #[test]
    fn test_add_jubjub_point() {
        type C = PoseidonGoldilocksConfig;

        let config = CircuitConfig::standard_recursion_config();
        let pw: PartialWitness<GoldilocksField> = PartialWitness::new();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);

        let px_val = BigUint::from_str(
            "17777552123799933955779906779655732241715742912184938656739573121738514868268",
        )
        .unwrap();
        let py_val = BigUint::from_str(
            "2626589144620713026669568689430873010625803728049924121243784502389097019475",
        )
        .unwrap();
        let qx_val = BigUint::from_str(
            "16540640123574156134436876038791482806971768689494387082833631921987005038935",
        )
        .unwrap();
        let qy_val = BigUint::from_str(
            "20819045374670962167435360035096875258406992893633759881276124905556507972311",
        )
        .unwrap();
        let res_x_val = BigUint::from_str(
            "7916061937171219682591368294088513039687205273691143098332585753343424131937",
        )
        .unwrap();
        let res_y_val = BigUint::from_str(
            "14035240266687799601661095864649209771790948434046947201833777492504781204499",
        )
        .unwrap();

        let px = JubjubFieldTarget(builder.constant_biguint(&px_val));
        let py = JubjubFieldTarget(builder.constant_biguint(&py_val));
        let qx = JubjubFieldTarget(builder.constant_biguint(&qx_val));
        let qy = JubjubFieldTarget(builder.constant_biguint(&qy_val));
        let res_x = JubjubFieldTarget(builder.constant_biguint(&res_x_val));
        let res_y = JubjubFieldTarget(builder.constant_biguint(&res_y_val));

        let p = JubjubCurveTarget { x: px, y: py };
        let q = JubjubCurveTarget { x: qx, y: qy };
        let res = builder.add_jubjub_curve(&p, &q);

        builder.connect_jubjubfield(&res.x, &res_x);
        builder.connect_jubjubfield(&res.y, &res_y);

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof);
    }

    #[test]
    fn test_scalar_mul_1() {
        // 340 s
        type C = PoseidonGoldilocksConfig;

        let config = CircuitConfig::standard_recursion_config();
        let pw: PartialWitness<GoldilocksField> = PartialWitness::new();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);

        let px_val = BigUint::from_str(
            "17777552123799933955779906779655732241715742912184938656739573121738514868268",
        )
        .unwrap();
        let py_val = BigUint::from_str(
            "2626589144620713026669568689430873010625803728049924121243784502389097019475",
        )
        .unwrap();
        let px = JubjubFieldTarget(builder.constant_biguint(&px_val));
        let py = JubjubFieldTarget(builder.constant_biguint(&py_val));
        let p = JubjubCurveTarget { x: px, y: py };

        let ten = builder.constant_biguint(&BigUint::new(vec![10]));
        let p_scalar_ten = builder.mul_scalar(&p, &ten);

        let p_2 = builder.add_jubjub_curve(&p, &p);
        let p_4 = builder.add_jubjub_curve(&p_2, &p_2);
        let p_5 = builder.add_jubjub_curve(&p_4, &p);
        let p_10 = builder.add_jubjub_curve(&p_5, &p_5);

        builder.connect_jubjub_curve(&p_10, &p_scalar_ten);

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof);
    }

    #[test]
    fn test_scalar_mul_2() {
        type C = PoseidonGoldilocksConfig;

        let config = CircuitConfig::standard_recursion_config();
        let pw: PartialWitness<GoldilocksField> = PartialWitness::new();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);

        let p = builder.B8_jubjub_curve();
        let r_val = BigUint::from_str(
            "2736030358979909402780800718157159386076813972158567259200215660948447373041",
        )
        .unwrap();
        let r = builder.constant_biguint(&r_val);
        let zero = builder.zero_jubjub_curve();

        let scalar_mul_res = builder.mul_scalar(&p, &r);

        builder.connect_jubjub_curve(&zero, &scalar_mul_res);

        let data = builder.build::<C>();

        let proof: plonky2::plonk::proof::ProofWithPublicInputs<GoldilocksField, PoseidonGoldilocksConfig, 2> = data.prove(pw).unwrap();
        data.verify(proof);
    }

    #[test]
    fn test_scalar_mul_3() {
        type C = PoseidonGoldilocksConfig;

        let config = CircuitConfig::standard_recursion_config();
        let pw: PartialWitness<GoldilocksField> = PartialWitness::new();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);

        let p = builder.B8_jubjub_curve();
        let r_val = BigUint::from_str(
            "2736030358979909402780800718157159386076813972158567259200215660948447373041",
        )
        .unwrap();
        let r = builder.constant_biguint(&r_val);

        let scalar_mul_res = builder.mul_scalar(&p, &r);

        builder.connect_jubjub_curve(&p, &scalar_mul_res);

        let data = builder.build::<C>();
        let proof_result = data.prove(pw);
        assert!(proof_result.is_err());
    }
}
