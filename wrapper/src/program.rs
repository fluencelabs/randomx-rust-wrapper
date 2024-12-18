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
use crate::{
    bindings::entropy::randomx_fill_aes_4rx4, bytecode_machine::BytecodeMachine, instruction::Instruction, ironlight::Aligned16
};
use std::fmt;

pub(crate) static RANDOMX_PROGRAM_SIZE: usize = 256;
pub(crate) static RANDOMX_PROGRAM_ITERATIONS: usize = 2048;

// WIP
#[repr(C, align(16))]
#[derive(Debug, Clone, Copy)]
pub struct ProgramConfiguration {
    pub e_mask: [u64; 2],
    pub read_reg0: u32,
    pub read_reg1: u32,
    pub read_reg2: u32,
    pub read_reg3: u32,
}

impl Default for ProgramConfiguration {
    fn default() -> Self {
        Self {
            e_mask: [0; 2],
            read_reg0: 0,
            read_reg1: 0,
            read_reg2: 0,
            read_reg3: 0,
        }
    }
}

impl ProgramConfiguration {
    pub fn new_with_entropy(
        e_mask_0: u64,
        e_mask_1: u64,
        address_registers: u64,
    ) -> Self {
        let mut address_registers = address_registers as u32;
        let read_reg0 = 0 + (address_registers & 1);
        address_registers >>= 1;
        let read_reg1 = 2 + (address_registers & 1);
        address_registers >>= 1;
        let read_reg2 = 4 + (address_registers & 1);
        address_registers >>= 1;
        let read_reg3 = 6 + (address_registers & 1);

        Self {
            e_mask: [e_mask_0, e_mask_1],
            read_reg0,
            read_reg1,
            read_reg2,
            read_reg3,
        }
    }
}

#[repr(C, align(64))]
#[derive(Debug, Clone, Copy)]
pub struct Program {
    pub entropy_buffer: [u64; 16],
    pub program_buffer: [Instruction; RANDOMX_PROGRAM_SIZE],
}

impl Program {
    pub fn new() -> Self {
        Self {
            entropy_buffer: [0; 16],
            program_buffer: [Instruction::default(); RANDOMX_PROGRAM_SIZE],
        }
    }

    pub fn with_seed(seed: &mut Aligned16) -> Self {
        let mut program = Self::new();
        let program_ptr = &mut program as *mut Program as *mut std::ffi::c_void;
        let seed_ptr = seed as *mut Aligned16 as *mut std::ffi::c_void;
        unsafe {
            randomx_fill_aes_4rx4(seed_ptr, size_of::<Program>(), program_ptr);
        }
        program
    }

    pub fn instruction(&self, pc: usize) -> &Instruction {
        if pc >= RANDOMX_PROGRAM_SIZE {
            panic!("Instruction index out of bounds: {}", pc);
        }
        &self.program_buffer[pc]
    }

    pub fn get_entropy(&self, i: usize) -> u64 {
        if i >= self.entropy_buffer.len() {
            panic!("Entropy buffer index out of bounds: {}", i);
        }
        self.entropy_buffer[i]
    }

    pub fn get_size(&self) -> usize {
        RANDOMX_PROGRAM_SIZE
    }

    pub fn print(&self) -> String {
        let mut result = String::new();
        for (i, instr) in self.program_buffer.iter().enumerate() {
            result.push_str(&format!("Instruction {}: {:?}\n", i, instr));
        }
        result
    }
}

impl fmt::Display for Program {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for instr in self.program_buffer.iter() {
            writeln!(f, "{:}", instr)?;
        }
        Ok(())
    }
}
