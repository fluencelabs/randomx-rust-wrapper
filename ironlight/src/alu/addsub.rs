/*
 * Copyright 2024 Fluence Labs Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::Field;
use p3_matrix::Matrix;
use p3_field::AbstractField;


use crate::stark_primitives::{BIN_OP_ROW_SIZE, CARRY_START, LEFT_ARG, RESULT, RIGHT_ARG};

#[derive(Clone, Copy, Debug)]
pub struct AddSubCirc {}

impl<F: Field> BaseAir<F> for AddSubCirc {
    fn width(&self) -> usize {
        BIN_OP_ROW_SIZE
    }
}

pub fn eval_add<AB: AirBuilder>(builder: &mut AB, is_real: AB::Var) {
    let main = builder.main();
    let local = main.row_slice(0);
    // let next = main.row_slice(1);

    let base = AB::F::from_canonical_u32(256);
    let one = AB::F::one();
    let mut is_real = builder.when(is_real);

    // For each limb, assert that difference between the carried result and the non-carried
    // result is either zero or the base.
    let overflow_0 = local[LEFT_ARG] + local[RIGHT_ARG] - local[RESULT];
    let overflow_1 =
        local[LEFT_ARG + 1] + local[RIGHT_ARG + 1] - local[RESULT + 1] + local[CARRY_START];
    let overflow_2 =
        local[LEFT_ARG + 2] + local[RIGHT_ARG + 2] - local[RESULT + 2] + local[CARRY_START + 1];
    let overflow_3 =
        local[LEFT_ARG + 3] + local[RIGHT_ARG + 3] - local[RESULT + 3] + local[CARRY_START + 2];
    let overflow_4 =
        local[LEFT_ARG + 4] + local[RIGHT_ARG + 4] - local[RESULT + 4] + local[CARRY_START + 3];
    let overflow_5 =
        local[LEFT_ARG + 5] + local[RIGHT_ARG + 5] - local[RESULT + 5] + local[CARRY_START + 4];
    let overflow_6 =
        local[LEFT_ARG + 6] + local[RIGHT_ARG + 6] - local[RESULT + 6] + local[CARRY_START + 5];
    let overflow_7 =
        local[LEFT_ARG + 7] + local[RIGHT_ARG + 7] - local[RESULT + 7] + local[CARRY_START + 6];

    is_real.assert_zero(overflow_0.clone() * (overflow_0.clone() - base));
    is_real.assert_zero(overflow_1.clone() * (overflow_1.clone() - base));
    is_real.assert_zero(overflow_2.clone() * (overflow_2.clone() - base));
    is_real.assert_zero(overflow_3.clone() * (overflow_3.clone() - base));
    is_real.assert_zero(overflow_4.clone() * (overflow_4.clone() - base));
    is_real.assert_zero(overflow_5.clone() * (overflow_5.clone() - base));
    is_real.assert_zero(overflow_6.clone() * (overflow_6.clone() - base));
    is_real.assert_zero(overflow_7.clone() * (overflow_7.clone() - base));

    // If the carry is one, then the overflow must be the base.
    is_real.assert_zero(local[CARRY_START] * (overflow_0.clone() - base));
    is_real.assert_zero(local[CARRY_START + 1] * (overflow_1.clone() - base));
    is_real.assert_zero(local[CARRY_START + 2] * (overflow_2.clone() - base));
    is_real.assert_zero(local[CARRY_START + 3] * (overflow_3.clone() - base));
    is_real.assert_zero(local[CARRY_START + 4] * (overflow_4.clone() - base));
    is_real.assert_zero(local[CARRY_START + 5] * (overflow_5.clone() - base));
    is_real.assert_zero(local[CARRY_START + 6] * (overflow_6.clone() - base));

    // // If the carry is not one, then the overflow must be zero.
    is_real.assert_zero((local[CARRY_START] - one.clone()) * overflow_0.clone());
    is_real.assert_zero((local[CARRY_START + 1] - one.clone()) * overflow_1.clone());
    is_real.assert_zero((local[CARRY_START + 2] - one.clone()) * overflow_2.clone());
    is_real.assert_zero((local[CARRY_START + 3] - one.clone()) * overflow_3.clone());
    is_real.assert_zero((local[CARRY_START + 4] - one.clone()) * overflow_4.clone());
    is_real.assert_zero((local[CARRY_START + 5] - one.clone()) * overflow_5.clone());
    is_real.assert_zero((local[CARRY_START + 6] - one.clone()) * overflow_6.clone());

    // // Assert that the carry is either zero or one.
    builder.assert_bool(local[CARRY_START]);
    builder.assert_bool(local[CARRY_START + 1]);
    builder.assert_bool(local[CARRY_START + 2]);
    builder.assert_bool(local[CARRY_START + 3]);
    builder.assert_bool(local[CARRY_START + 4]);
    builder.assert_bool(local[CARRY_START + 5]);
    builder.assert_bool(local[CARRY_START + 6]);
}

impl<AB: AirBuilder> Air<AB> for AddSubCirc {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);

        eval_add(builder, local[1]);
        eval_add(builder, local[2]);
    }
}
