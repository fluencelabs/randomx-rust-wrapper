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
use std::marker::PhantomData;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, PrimeField};
use p3_matrix::dense::RowMajorMatrix;
use sp1_core_executor::{ExecutionRecord, Program};
use sp1_stark::air::MachineAir;

use crate::{alu::addsub::AddSubCirc, stark_primitives::BIN_OP_ROW_SIZE};



#[derive(Clone, Debug)]
pub struct RandomXCircuit<F: Field>{
    phantom: PhantomData<F>
}

impl<F: Field> RandomXCircuit<F> {
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

// This is a row size of a state representation.
// Includes register file ATM.
impl<F: Field> BaseAir<F> for RandomXCircuit<F> {
    fn width(&self) -> usize {
        BIN_OP_ROW_SIZE
    }
}

impl<AB: AirBuilder> Air<AB> for RandomXCircuit<AB::F> {
    fn eval(&self, builder: &mut AB) {

        let add_sub_circ = AddSubCirc {};

        add_sub_circ.eval(builder);
    }
}


impl<F: PrimeField> MachineAir<F> for RandomXCircuit<F>  {
    type Record = ExecutionRecord;

    type Program = Program;
    
    fn name(&self) -> String {
        "RandomXCircuit".to_string()
    }
    
    fn generate_trace(&self, _input: &Self::Record, _output: &mut Self::Record) -> RowMajorMatrix<F> {
        unimplemented!()
    }
    
    fn included(&self, _shard: &Self::Record) -> bool {
        unimplemented!()
    }

    fn preprocessed_width(&self) -> usize {
        BIN_OP_ROW_SIZE
    }
}