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

use std::{fs::File, io::Write, ptr};

use crate::{
    bindings::{
        entropy::{randomx_blake2b, randomx_fill_aes_1rx4},
        float_rounding::randomx_reset_rounding_mode,
    }, bytecode_machine, program::RANDOMX_PROGRAM_ITERATIONS, registers::{self, FpuRegister, MemoryRegisters, NativeRegisterFile}, result_hash::ToRawMut
};
use ccp_randomx_types::ResultHash;

use crate::{
    cache::CacheRawAPI,
    program::{Program, ProgramConfiguration},
    registers::RegisterFile,
    RResult, RandomXFlags, VmCreationError,
};

static RANDOMX_SCRATCHPAD_L2: usize = 2097152;

// WIP
#[repr(align(16))]
pub struct Aligned16(pub [u64; 8]);
const MANTISSA_MASK: u64 = 0x000F_FFFF_FFFF_FFFF;
const EXPONENT_BIAS: u64 = 0x3ff;
const EXPONENT_MASK: u64 = 0x7ff;
const MANTISSA_SIZE: u64 = 52;
const CONST_EXPONENT_BITS: u64 = 0x300;
const STATIC_EXPONENT_BITS: u64 = 4;
const DYNAMIC_EXPONENT_BITS: u64 = 4;
// constexpr
const DATASET_EXTRA_ITEMS: usize = 0x7ffff;
const CACHE_LINE_SIZE: usize = 64;

#[inline(always)]
fn get_small_positive_float_bits(entropy: u64) -> u64 {
    let exponent = (entropy >> 59) // 0..31
        + EXPONENT_BIAS;
    let exponent = (exponent & EXPONENT_MASK) << MANTISSA_SIZE;
    let mantissa = entropy & MANTISSA_MASK;
    exponent | mantissa
}

#[inline(always)]
fn get_static_exponent(entropy: u64) -> u64 {
    let mut exponent = CONST_EXPONENT_BITS;
    exponent |= (entropy >> (64 - STATIC_EXPONENT_BITS)) << DYNAMIC_EXPONENT_BITS;
    exponent <<= MANTISSA_SIZE;
    exponent
}

#[inline(always)]
fn get_float_mask(entropy: u64) -> u64 {
    const MASK_22BIT: u64 = (1u64 << 22) - 1;
    (entropy & MASK_22BIT) | get_static_exponent(entropy)
}

pub struct IronLightVM<T> {
    // program: Program,
    reg: RegisterFile,
    mem: MemoryRegisters,
    config: ProgramConfiguration,
    scratchpad: Vec<u8>,
    cache_key: String,
    temp_hash: [u64; 8],
    randomx_cache: T,
    dataset_offset: usize,
}

impl<T: CacheRawAPI> IronLightVM<T> {
    pub fn new(randomx_cache: T, flags: RandomXFlags) -> RResult<Self> {
        if !flags.is_light_mode() {
            // WIP
            return Err(VmCreationError::IncorrectLightModeFlag { flags })?;
        }

        let config = ProgramConfiguration::default();
        let scratchpad = vec![0; RANDOMX_SCRATCHPAD_L2];
        let reg = RegisterFile::default();
        let temp_hash = [0; 8];
        let cache_key = String::new();
        let mem = MemoryRegisters::default();
        let dataset_offset = 0;

        let vm = Self {
            mem,
            config,
            scratchpad,
            reg,
            temp_hash,
            cache_key,
            randomx_cache,
            dataset_offset,
        };

        Ok(vm)
    }

    /// Calculates a RandomX hash value.
    /// mut is strange. need to decided whether to preserve an existing VM API or not
    pub fn hash(&mut self, local_nonce: &[u8]) -> ResultHash {
        // Watch out USE_CSR_INTRINSICS macro in randomx.cpp

        // let mut hash = ResultHash::empty();

        let mut temp_hash = Aligned16([0u64; 8]);
        let temp_hash_ptr = temp_hash.0.as_mut_ptr() as *mut std::ffi::c_void;
        let local_nonce_ptr = local_nonce.as_ptr() as *const std::ffi::c_void;
        unsafe {
            randomx_blake2b(
                temp_hash_ptr,
                64,
                local_nonce_ptr,
                local_nonce.len(),
                ptr::null(),
                0usize,
            );
        }

        let hex_string: String = temp_hash.0.iter().map(|b| format!("{:x}", b)).collect();

        println!("Result hash: {}", hex_string);
        println! {""};
        self.init_scratchpad(&mut temp_hash);
        unsafe {
            randomx_reset_rounding_mode();
        }

        // let mut f = File::create("./scratchpad").unwrap();
        // f.write(&self.scratchpad).unwrap();

        // machine->resetRoundingMode();
        // for (int chain = 0; chain < RANDOMX_PROGRAM_COUNT - 1; ++chain) {
        // 	machine->run(&tempHash);
        // 	blakeResult = blake2b(tempHash, sizeof(tempHash), machine->getRegisterFile(), sizeof(randomx::RegisterFile), nullptr, 0);
        // 	assert(blakeResult == 0);
        // }

        // machine->run(&tempHash);
        // machine->getFinalResult(output, RANDOMX_HASH_SIZE);

        self.run_final(&mut temp_hash).get_final_result()
    }

    // test
    fn initialize(&mut self, program: &Program) {
        let fpu_entropy = (0..8)
            .into_iter()
            .map(|i| f64::from_bits(program.get_entropy(i)))
            .collect::<Vec<f64>>();
        self.reg.initialise_fpu_a(&fpu_entropy);

        let mem_ma_entropy = program.get_entropy(8);
        let mem_mx = program.get_entropy(10);
        self.mem.initialise_mem(mem_ma_entropy, mem_mx);

        let address_registers = program.get_entropy(12);
        self.dataset_offset =
            program.get_entropy(13) as usize % (DATASET_EXTRA_ITEMS + 1) * CACHE_LINE_SIZE;
        let config_emask_0 = get_float_mask(program.get_entropy(14));
        let config_emask_1 = get_float_mask(program.get_entropy(15));

        self.config = ProgramConfiguration::new_with_entropy(
            address_registers,
            config_emask_0,
            config_emask_1,
        );
    }

    fn execute(&mut self, program: &Program) {
        let mut nreg = NativeRegisterFile::from_fp_registers(&self.reg.a);
        let bytecode_machine = program.compile();

        let sp_addr_0 = self.mem.mx;
		let sp_addr_1 = self.mem.ma;

        for _ in 0..RANDOMX_PROGRAM_ITERATIONS {
            // do something
        }

        self.reg.r = nreg.r;
        self.reg.store_fpu_f(&nreg.f);
        self.reg.store_fpu_e(&nreg.e);
    }

    fn generate_and_run(&mut self, seed: &mut Aligned16) {
        let program = Program::with_seed(seed);
        // println!("{:}", program);
        self.initialize(&program);
        self.execute(&program);
    }

    fn run_final(&mut self, seed: &mut Aligned16) -> &mut Self {
        self.generate_and_run(seed);
        self
    }

    fn get_final_result(&self) -> ResultHash {
        ResultHash::empty()
    }

    fn init_scratchpad(&mut self, seed: &mut Aligned16) {
        let seed = seed.0.as_mut_ptr() as *mut std::ffi::c_void;
        let scratchpad = self.scratchpad.as_mut_ptr() as *mut std::ffi::c_void;
        unsafe {
            randomx_fill_aes_1rx4(seed, RANDOMX_SCRATCHPAD_L2, scratchpad);
        }
    }
}
