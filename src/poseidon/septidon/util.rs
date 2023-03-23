use halo2_proofs::circuit::Value;
use halo2_proofs::halo2curves::bn256::Fr as F;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};

pub fn map_array<IN, OUT, FN>(array: &[IN; 3], mut f: FN) -> [OUT; 3]
where
    FN: FnMut(&IN) -> OUT,
{
    let a = f(&array[0]);
    let b = f(&array[1]);
    let c = f(&array[2]);
    [a, b, c]
}

/// Helper to make queries to a ConstraintSystem. Escape the "create_gate" closures.
pub fn query<T>(cs: &mut ConstraintSystem<F>, f: impl FnOnce(&mut VirtualCells<'_, F>) -> T) -> T {
    let mut queries: Option<T> = None;
    cs.create_gate("query", |meta| {
        queries = Some(f(meta));
        [Expression::Constant(F::zero())]
    });
    queries.unwrap()
}

pub fn join_values(values: [Value<F>; 3]) -> Value<[F; 3]> {
    values[0]
        .zip(values[1])
        .zip(values[2])
        .map(|((v0, v1), v2)| [v0, v1, v2])
}

pub fn split_values(values: Value<[F; 3]>) -> [Value<F>; 3] {
    [
        values.map(|v| v[0]),
        values.map(|v| v[1]),
        values.map(|v| v[2]),
    ]
}

pub mod pow_5 {
    use super::super::params::F;
    use halo2_proofs::plonk::Expression;

    pub fn expr(v: Expression<F>) -> Expression<F> {
        let v2 = v.clone() * v.clone();
        v2.clone() * v2 * v
    }

    pub fn value(v: F) -> F {
        let v2 = v * v;
        v2 * v2 * v
    }
}

/// Matrix multiplication expressions and values.
pub mod matmul {
    use super::super::params::{Mds, F};
    use halo2_proofs::plonk::Expression;
    use std::convert::TryInto;

    /// Multiply a vector of expressions by a constant matrix.
    pub fn expr(matrix: &Mds, vector: [Expression<F>; 3]) -> [Expression<F>; 3] {
        (0..3)
            .map(|next_idx| {
                (0..3)
                    .map(|idx| vector[idx].clone() * matrix[next_idx][idx])
                    .reduce(|acc, term| acc + term)
                    .unwrap()
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    /// Multiply a vector of values by a constant matrix.
    pub fn value(matrix: &Mds, vector: [F; 3]) -> [F; 3] {
        (0..3)
            .map(|next_idx| {
                (0..3)
                    .map(|idx| vector[idx] * matrix[next_idx][idx])
                    .reduce(|acc, term| acc + term)
                    .unwrap()
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
}

/// Returns `when_true` when `selector == 1`, and returns `when_false` when
/// `selector == 0`. `selector` needs to be boolean.
pub mod select {
    use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};

    /// Returns the `when_true` expression when the selector is true, else
    /// returns the `when_false` expression.
    pub fn expr<F: FieldExt>(
        selector: Expression<F>,
        when_true: Expression<F>,
        when_false: Expression<F>,
    ) -> Expression<F> {
        let one = Expression::Constant(F::from(1));
        selector.clone() * when_true + (one - selector) * when_false
    }

    /// Returns the `when_true` value when the selector is true, else returns
    /// the `when_false` value.
    pub fn value<F: FieldExt>(selector: F, when_true: F, when_false: F) -> F {
        selector * when_true + (F::one() - selector) * when_false
    }
}

/// Gadget for boolean OR.
pub mod or {
    use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};

    /// Return (a OR b), assuming a and b are boolean expressions.
    pub fn expr<F: FieldExt>(a: Expression<F>, b: Expression<F>) -> Expression<F> {
        let one = Expression::Constant(F::from(1));
        // a OR b <=> !(!a AND !b)
        one.clone() - ((one.clone() - a) * (one.clone() - b))
    }

    /// Return (a OR b), assuming a and b are boolean values.
    pub fn value<F: FieldExt>(a: F, b: F) -> F {
        let one = F::one();
        // a OR b <=> !(!a AND !b)
        one - ((one - a) * (one - b))
    }
}
