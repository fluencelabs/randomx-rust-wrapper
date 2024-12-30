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

use core::hash;
use std::{fs::File, io::Write, os::raw::c_void, ptr};

use crate::{
    bindings::{
        cache::randomx_cache,
        dataset::randomx_init_dataset_item,
        entropy::{randomx_blake2b, randomx_fill_aes_1rx4, randomx_hash_aes_1rx4},
        float_rounding::randomx_reset_rounding_mode,
    },
    bytecode_machine::{self, BytecodeMachine, BytecodeStorage, InstructionByteCode},
    constants::{CACHE_LINE_ALIGN_MASK, RANDOMX_SCRATCHPAD_L3, SCRATCHPAD_L3_MASK64},
    intrinsics::{
        mask_register_exponent_mantissa, rx_cvt_packed_int_vec_f128, rx_store_vec_f128,
        rx_xor_vec_f128, NativeFpuRegister,
    },
    program::{RANDOMX_PROGRAM_COUNT, RANDOMX_PROGRAM_ITERATIONS, RANDOMX_PROGRAM_SIZE},
    registers::{
        self, FpuRegister, IntRegisterArray, MemoryRegisters, NativeRegisterFile, REGISTER_COUNT,
        REGISTER_COUNT_FLT,
    },
    result_hash::ToRawMut,
};
use ccp_randomx_types::ResultHash;

use crate::{
    cache::CacheRawAPI,
    program::{Program, ProgramConfiguration},
    registers::RegisterFile,
    RResult, RandomXFlags, VmCreationError,
};

// WIP
#[repr(C, align(16))]
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

fn dataset_read(
    cache: *const randomx_cache,
    address: usize,
    r: &IntRegisterArray,
) -> IntRegisterArray {
    let item_number = (address / CACHE_LINE_SIZE) as u64;
    let mut rl: IntRegisterArray = [0; REGISTER_COUNT];
    let rl_ptr = rl.as_ptr() as *mut c_void;

    unsafe {
        randomx_init_dataset_item(cache, rl_ptr, item_number);
    }

    // println!("dataset_read r: {:?}", r);
    // println!("dataset_read rl: {:?}", rl);

    for i in 0..REGISTER_COUNT {
        rl[i] = r[i] ^ rl[i];
    }
    // println!("dataset_read rl: {:?}", rl);

    rl
}

pub struct IronLightVM<T> {
    // program: Program,
    reg: RegisterFile,
    mem: MemoryRegisters,
    config: ProgramConfiguration,
    scratchpad: Vec<u8>, // replace with Box<[u8]> || aligned_alloc prims
    cache_key: String,
    temp_hash: [u64; 8],
    randomx_cache: T,
    dataset_offset: usize,
    bytecode: BytecodeStorage,
}

impl<T: CacheRawAPI> IronLightVM<T>
where
    T: CacheRawAPI,
{
    pub fn new(randomx_cache: T, flags: RandomXFlags) -> RResult<Self> {
        if !flags.is_light_mode() {
            // WIP
            return Err(VmCreationError::IncorrectLightModeFlag { flags })?;
        }

        let config = ProgramConfiguration::default();
        let scratchpad = vec![0; RANDOMX_SCRATCHPAD_L3];
        let reg = RegisterFile::default();
        let temp_hash = [0; 8];
        let cache_key = String::new();
        let mem = MemoryRegisters::default();
        let dataset_offset = 0;
        let bytecode = [InstructionByteCode::default(); RANDOMX_PROGRAM_SIZE];

        let vm = Self {
            mem,
            config,
            scratchpad,
            reg,
            temp_hash,
            cache_key,
            randomx_cache,
            dataset_offset,
            bytecode,
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
                std::mem::size_of::<Aligned16>(),
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

        for _ in 0..RANDOMX_PROGRAM_COUNT-1 {
        // for _ in 0..1 {
            // WIP run doesn't need mut temp_hash TBH. Replace temp_hash with hash mb.
            self.run(&mut temp_hash);
            let reg_ptr = &self.reg as *const RegisterFile as *const std::ffi::c_void;
            unsafe {
                let result = randomx_blake2b(
                    temp_hash_ptr,
                    std::mem::size_of::<Aligned16>(),
                    reg_ptr,
                    std::mem::size_of::<RegisterFile>(),
                    ptr::null(),
                    0usize,
                );
                // assert(result == 0);
            }
        }

        // let mut f = File::create("./scratchpad").unwrap();
        // f.write(&self.scratchpad).unwrap();

        // for (int chain = 0; chain < RANDOMX_PROGRAM_COUNT - 1; ++chain) {
        // 	machine->run(&tempHash);
        // 	blakeResult = blake2b(tempHash, sizeof(tempHash), machine->getRegisterFile(), sizeof(randomx::RegisterFile), nullptr, 0);
        // 	assert(blakeResult == 0);
        // }

        // machine->run(&tempHash);
        // machine->getFinalResult(output, RANDOMX_HASH_SIZE);

        // WIP run_final doesn't need mut temp_hash TBH. Replace temp_hash with hash mb.
        self.run_final(&mut temp_hash).get_final_result()
    }

    // test
    fn initialize(&mut self, program: &Program) {
        let fpu_entropy = (0..8)
            .into_iter()
            .map(|i| f64::from_bits(get_small_positive_float_bits(program.get_entropy(i))))
            .collect::<Vec<f64>>();
        // println!("fpu_entropy: {:?}", fpu_entropy);
        self.reg.initialise_fpu_a(&fpu_entropy);
        // println!("reg.a: {:?}", self.reg.a);

        let mem_ma_entropy = program.get_entropy(8);
        let mem_mx = program.get_entropy(10);
        self.mem.initialise_mem(mem_ma_entropy, mem_mx);

        let address_registers = program.get_entropy(12);
        self.dataset_offset =
            program.get_entropy(13) as usize % (DATASET_EXTRA_ITEMS + 1) * CACHE_LINE_SIZE;
        let config_emask_0 = get_float_mask(program.get_entropy(14));
        let config_emask_1 = get_float_mask(program.get_entropy(15));

        self.config = ProgramConfiguration::new_with_entropy(
            config_emask_0,
            config_emask_1,
            address_registers,
        );
    }

    fn execute(&mut self, program: &Program) {
        let mut nreg = NativeRegisterFile::from_fp_registers(&self.reg.a);

        let bytecode_machine = BytecodeMachine::from_components(
            &program.program_buffer,
            &mut nreg,
            &mut self.bytecode,
        );

        // WIP types
        let mut sp_addr0 = self.mem.mx as u64;
        let mut sp_addr1 = self.mem.ma as u64;

        // println!("execute in reg.r[0]: {:?}", nreg.r[0]);

        // let a = bytecode_machine.bytecode[19];
        // unsafe {
        //     println!("bytecode_machine.bytecode[19]: {:?} *isrc {}", a, *bytecode_machine.bytecode[19].isrc);
        // }

        for ic in 0..RANDOMX_PROGRAM_ITERATIONS {
            let sp_mix: u64 =
                nreg.r[self.config.read_reg0 as usize] ^ nreg.r[self.config.read_reg1 as usize];
            // println!(
            //     "RUN!!!! ic {} sp_mix {} {}",
            //     ic, self.config.read_reg0, self.config.read_reg1
            // );

            sp_addr0 ^= sp_mix;
            sp_addr0 &= SCRATCHPAD_L3_MASK64 as u64;
            sp_addr1 ^= sp_mix >> 32;
            sp_addr1 &= SCRATCHPAD_L3_MASK64 as u64;

            // WIP consider using vectorized xor here
            for i in 0..REGISTER_COUNT {
                let entropy_address = sp_addr0 as usize + 8usize * i;
                let scratchpad_entropy =
                    &self.scratchpad[entropy_address] as *const u8 as *const u64;
                unsafe {
                    nreg.r[i] ^= *scratchpad_entropy;
                }
                // println!(
                //     "execute init from sp_addr0 {} load in reg.r: {:?}",
                //     sp_addr0, nreg.r[i]
                // );
            }

            for i in 0..REGISTER_COUNT_FLT {
                let entropy_address = sp_addr1 as usize + 8usize * i;
                let scratchpad_entropy =
                    &self.scratchpad[entropy_address] as *const u8 as *const c_void;
                unsafe {
                    nreg.f[i] = rx_cvt_packed_int_vec_f128(scratchpad_entropy);
                }
                // println!("execute init load in reg.f[i]: {:?}", nreg.f[i]);
            }

            for i in 0..REGISTER_COUNT_FLT {
                let entropy_address = sp_addr1 as usize + 8usize * (REGISTER_COUNT_FLT + i);
                let scratchpad_entropy =
                    &self.scratchpad[entropy_address] as *const u8 as *const c_void;
                unsafe {
                    let scratchpad_entropy_vector = rx_cvt_packed_int_vec_f128(scratchpad_entropy);
                    nreg.e[i] = mask_register_exponent_mantissa(
                        &self.config.e_mask,
                        scratchpad_entropy_vector,
                    );
                    // println!("init e in reg.e[i]: {:?} a {:?} e_mask {:?}", nreg.e[i], scratchpad_entropy_vector, &self.config.e_mask);
                }
            }
            // println!("before dataset_read nreg.r: {:?}", nreg.r);
            bytecode_machine.execute_bytecode(&mut self.scratchpad, &self.config.e_mask, &nreg, ic);

            self.mem.mx ^= (nreg.r[self.config.read_reg2 as usize]
                ^ nreg.r[self.config.read_reg3 as usize]) as u32;
            self.mem.mx &= CACHE_LINE_ALIGN_MASK;
            // prefetch
            // read into nreg.r
            // dataset_read
            let dataset_offset = self.dataset_offset + self.mem.ma as usize;

            nreg.r = dataset_read(self.randomx_cache.raw(), dataset_offset, &nreg.r);
            // println!("after dataset_read nreg.r[0]: {:?}", nreg.r[0]);

            std::mem::swap(&mut self.mem.mx, &mut self.mem.ma);

            for i in 0..REGISTER_COUNT {
                let entropy_address = sp_addr1 as usize + 8usize * i;
                let scratchpad_entropy =
                    &mut self.scratchpad[entropy_address] as *mut u8 as *mut u64;
                unsafe {
                    *scratchpad_entropy = nreg.r[i];
                }
            }

            for i in 0..REGISTER_COUNT_FLT {
                // println!("execute before bc exec nreg.e[i]:  {:?} nreg.f[i] {:?}", nreg.e[i], nreg.f[i]);
                nreg.f[i] = rx_xor_vec_f128(nreg.f[i], nreg.e[i]);
            }

            for i in 0..REGISTER_COUNT_FLT {
                // scratchpad + spAddr0 + 16 * i
                let entropy_address = sp_addr0 as usize + 16usize * i;
                let scratchpad_dst = &mut self.scratchpad[entropy_address] as *mut u8 as *mut f64;
                rx_store_vec_f128(scratchpad_dst, &nreg.f[i]);
            }

            sp_addr0 = 0;
            sp_addr1 = 0;
            // println!("execute loop nreg.r[0]: {:?}", nreg.r[0]);
            // if ic == 197 || ic == 196 {
            //     println!("execute reg.r: {:?}", nreg.r);
            // }
        }

        self.reg.r = nreg.r;
        // println!("execute reg.r: {:?}", self.reg.r);

        self.reg.store_fpu_f(&nreg.f);
        // println!("execute after bc exec reg.f {:?}", self.reg.f);
        self.reg.store_fpu_e(&nreg.e);
        // println!("execute after bc exec reg.e {:?}", self.reg.e);
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
        let mut hash = ResultHash::empty();
        let hash_ptr = hash.as_mut() as *const u8 as *mut std::ffi::c_void;
        let scratchpad = self.scratchpad.as_ptr() as *mut std::ffi::c_void;
        let aes_dst_ptr = self.reg.a.as_ptr() as *mut std::ffi::c_void;
        // println!("final reg.r[0]: {:?}", self.reg.r[0]);

        unsafe {
            randomx_hash_aes_1rx4(scratchpad, RANDOMX_SCRATCHPAD_L3, aes_dst_ptr);
            // println!("execute after bc exec self.reg.a[0]:  {:?}", self.reg.a[0]);
            // println!("execute after bc exec self.reg.a[1]:  {:?}", self.reg.a[1]);
            // println!("execute after bc exec self.reg.a[2]:  {:?}", self.reg.a[2]);
            // println!("execute after bc exec self.reg.a[3]:  {:?}", self.reg.a[3]);
            // println!("execute after bc exec self.reg.f[0]:  {:?}", self.reg.f[0]);
            // println!("execute after bc exec self.reg.f[1]:  {:?}", self.reg.f[1]);
            // println!("execute after bc exec self.reg.f[2]:  {:?}", self.reg.f[2]);
            // println!("execute after bc exec self.reg.f[3]:  {:?}", self.reg.f[3]);
            // println!("execute after bc exec self.reg.e[0]:  {:?}", self.reg.e[0]);
            // println!("execute after bc exec self.reg.e[1]:  {:?}", self.reg.e[1]);
            // println!("execute after bc exec self.reg.e[2]:  {:?}", self.reg.e[2]);
            // println!("execute after bc exec self.reg.e[3]:  {:?}", self.reg.e[3]);
            let reg_ptr = &self.reg as *const RegisterFile as *const std::ffi::c_void;
            randomx_blake2b(
                hash_ptr,
                32,
                reg_ptr,
                std::mem::size_of::<RegisterFile>(),
                ptr::null(),
                0usize,
            );
        }

        hash
    }

    fn init_scratchpad(&mut self, seed: &mut Aligned16) {
        let seed = seed.0.as_mut_ptr() as *mut std::ffi::c_void;
        let scratchpad = self.scratchpad.as_mut_ptr() as *mut std::ffi::c_void;
        unsafe {
            randomx_fill_aes_1rx4(seed, RANDOMX_SCRATCHPAD_L3, scratchpad);
        }
    }

    fn run(&mut self, seed: &mut Aligned16) {
        self.generate_and_run(seed)
    }
}
