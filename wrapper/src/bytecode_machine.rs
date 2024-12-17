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

use bitflags::iter::Iter;

use crate::{instruction::Instruction, registers::NativeFpuRegister};

pub(crate) struct BytecodeMachine {
    bytecode: Vec<InstructionBytecode>,
}

impl BytecodeMachine {
    pub(crate) fn empty() -> Self {
        Self {
            bytecode: Vec::new(),
        }
    }

    pub(crate) fn from_instructions(instructions: Iter<Instruction>) -> Self {
        Self {
            bytecode: Vec::new(),
        }
    }
}

#[repr(C, align(16))]
pub(crate)  struct IntegerBytecode {
    idst: *mut u64,
    isrc: *const u64,
    imm: u64,
    target: i16,
    shift: u16,
    mem_mask: u32,
}

#[repr(C, align(16))]
pub(crate)  struct FpBytecode {
    idst: *mut NativeFpuRegister,
    isrc: *const NativeFpuRegister,
    imm: u64,
    target: i16,
    shift: u16,
    mem_mask: u32,
}

pub(crate) enum InstructionBytecode {
    Integer(IntegerBytecode),
    Fp(FpBytecode),
}


