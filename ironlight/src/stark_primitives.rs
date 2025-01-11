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

use p3_baby_bear::BabyBear;
use p3_field::extension::BinomialExtensionField;
use p3_uni_stark::StarkConfig;

use sp1_stark::{InnerChallenger, InnerPcs};

use crate::bytecode_machine::InstructionType;

pub(crate) type Val = BabyBear;
pub(crate) type Challenge = BinomialExtensionField<Val, 4>;
pub(crate) type InnerBabyBearPoseidon2 = StarkConfig<InnerPcs, Challenge, InnerChallenger>;

// 1 instr cnt + InstructionType::Nop = 29 as ops flags + 8 arg1 + 8 arg2 + 8 res + 7 carry
// Possible to optimize replacing InstructionType::Nop with 10 cat-s of math ops
pub(crate) const BIN_OP_ROW_SIZE: usize = 61;
pub(crate) const WORD_SIZE: usize = 8;
pub(crate) const OP_TYPES: usize = InstructionType::Nop as usize;
pub(crate) const CARRY: usize = 7;
pub(crate) const LEFT_ARG: usize = 30;
pub(crate) const RIGHT_ARG: usize = 38;
pub(crate) const RESULT: usize = 46;
pub(crate) const CARRY_START: usize = 54;

// pub(crate) const BIN_OP_ROW_SIZE: usize = 32;
// pub(crate) const WORD_SIZE: usize = 8;
// pub(crate) const CARRY: usize = 7;
// pub(crate) const LEFT_ARG: usize = 1;
// pub(crate) const RIGHT_ARG: usize = 9;
// pub(crate) const RESULT: usize = 17;
// pub(crate) const CARRY_START: usize = 25;