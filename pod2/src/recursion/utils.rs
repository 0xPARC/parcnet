use crate::{D, F};
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;

/// if s==0: returns x
/// if s==1: returns y
/// Warning: this method assumes all input values are ensured to be \in {0,1}
pub fn selector_gate(
    builder: &mut CircuitBuilder<F, D>,
    x: Target,
    y: Target,
    s: Target,
) -> Target {
    // z = x + s(y-x)
    let y_x = builder.sub(y, x);
    // z = x+s(y-x) <==> mul_add(s, yx, x)=s*(y-x)+x
    builder.mul_add(s, y_x, x)
}

/// ensures b \in {0,1}
pub fn binary_check(builder: &mut CircuitBuilder<F, D>, b: Target) {
    let zero = builder.zero();
    let one = builder.one();
    // b * (b-1) == 0
    let b_1 = builder.sub(b, one);
    let r = builder.mul(b, b_1);
    builder.connect(r, zero);
}

/// asserts that the given `v` is equal to `1` if the given `selector` is set to `0`,
/// otherwise not (in which case it asserts 1==1)
pub fn assert_one_if_enabled_inverted(
    builder: &mut CircuitBuilder<F, D>,
    v: Target,
    inverted_selector: &BoolTarget,
) {
    let selector = builder.not(*inverted_selector);
    // if inverted_selector==0: ensure v=1
    // if inverted_selector==1: don't care -> ensure one=1
    assert_one_if_enabled(builder, v, &selector);
}

/// asserts that the given `v` is equal to `1` if the given `selector` is set to `1`,
/// otherwise not (in which case it asserts 1==1)
pub fn assert_one_if_enabled(builder: &mut CircuitBuilder<F, D>, v: Target, selector: &BoolTarget) {
    // if selector==1: ensure v=1
    // if selector==0: don't care -> ensure one=1
    let one = builder.one();
    let expected = builder.select(*selector, v, one);
    builder.connect(expected, one);
}
