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
use std::sync::atomic::AtomicU64;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_baby_bear::BabyBear;
use p3_field::Field;
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_field::AbstractField;
use sp1_stark::{inner_perm, BabyBearPoseidon2Inner, InnerChallenger};
use p3_uni_stark::prove;

use crate::{alu::addsub::AddSubCirc, stark_primitives::BIN_OP_ROW_SIZE};



#[derive(Clone, Debug)]
pub struct RxCircuit{}

// This is a row size of a state representation.
// Includes register file ATM.
impl<F: Field> BaseAir<F> for RxCircuit {
    fn width(&self) -> usize {
        BIN_OP_ROW_SIZE
    }
}

impl<AB: AirBuilder> Air<AB> for RxCircuit {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let next = main.row_slice(1);

        let add_sub_circ = AddSubCirc {};

        // builder
        //     .when_transition()
        //     .assert_eq(next[0], local[0] + AB::Expr::one());
        
        add_sub_circ.eval(builder);
    }
}
