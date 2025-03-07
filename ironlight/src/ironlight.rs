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

use std::{alloc::Layout, os::raw::c_void, ptr};

use ccp_randomx::bindings::{
    cache::randomx_cache,
    dataset::randomx_init_dataset_item,
    entropy::{randomx_blake2b, randomx_fill_aes_1rx4},
    hashing::randomx_hash_aes_1rx4,
};

use ccp_randomx::cache::CacheRawAPI;
use ccp_randomx::result_hash::ToRawMut;
use p3_baby_bear::BabyBear;
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{get_log_quotient_degree, prove, verify};
use sp1_prover::components::DefaultProverComponents;
use sp1_sdk::{SP1Proof, SP1ProofWithPublicValues, SP1Prover, SP1PublicValues, SP1Stdin, SP1_CIRCUIT_VERSION};
use sp1_stark::{
    air::SP1_PROOF_NUM_PV_ELTS, baby_bear_poseidon2::BabyBearPoseidon2, inner_perm,
    BabyBearPoseidon2Inner, Chip, InnerChallenger, SP1ProverOpts, StarkMachine,
};

use crate::{
    bytecode_machine::{BytecodeMachine, BytecodeStorage, InstructionByteCode},
    constants::{
        CACHE_LINE_ALIGN_MASK, CACHE_LINE_SIZE, CONST_EXPONENT_BITS, DATASET_EXTRA_ITEMS,
        DYNAMIC_EXPONENT_BITS, EXPONENT_BIAS, EXPONENT_MASK, MANTISSA_MASK, MANTISSA_SIZE,
        RANDOMX_SCRATCHPAD_L3, SCRATCHPAD_L3_MASK64, STATIC_EXPONENT_BITS,
    },
    intrinsics::{
        get_csr, mask_register_exponent_mantissa, rx_cvt_packed_int_vec_f128, rx_reset_float_state,
        rx_store_vec_f128, rx_xor_vec_f128, set_csr,
    },
    program::{RANDOMX_PROGRAM_COUNT, RANDOMX_PROGRAM_ITERATIONS, RANDOMX_PROGRAM_SIZE},
    randomx_circuit::RandomXCircuit,
    registers::{
        IntRegisterArray, MemoryRegisters, NativeRegisterFile, REGISTER_COUNT, REGISTER_COUNT_FLT,
    },
    stark_primitives::{InnerBabyBearPoseidon2, BIN_OP_ROW_SIZE},
    utils::p3_proof_to_shardproof,
};
use ccp_randomx_types::{ResultHash, RANDOMX_RESULT_SIZE};

use crate::{
    program::{Program, ProgramConfiguration},
    registers::RegisterFile,
    RResult, RandomXFlags, VmCreationError,
};

#[derive(Clone, Debug)]
pub struct HashWithGroth16Proof {
    pub hash: ResultHash,
    pub proof: Vec<u8>,
}

impl HashWithGroth16Proof {
    fn new(hash: ResultHash, proof: Vec<u8>) -> Self {
        Self { hash, proof }
    }
}

#[repr(C, align(16))]
pub struct Aligned16(pub [u64; 8]);

impl ToRawMut for Aligned16 {
    fn empty() -> Self {
        Aligned16([0u64; 8])
    }

    fn as_raw_mut(&mut self) -> *mut std::ffi::c_void {
        self.0.as_mut().as_mut_ptr() as *mut std::ffi::c_void
    }
}

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

fn blake_hash<OUT: ToRawMut, IN: ?Sized>(
    out: &mut OUT,
    out_size: usize,
    input: *const IN,
    input_size: usize,
) {
    unsafe {
        randomx_blake2b(
            out.as_raw_mut(),
            out_size,
            input as *const std::ffi::c_void,
            input_size,
            ptr::null(),
            0usize,
        );
    }
}

pub fn aes_1rx4_hash<OUT, IN>(input: *const IN, input_size: usize, hash: *mut OUT) {
    unsafe {
        randomx_hash_aes_1rx4(
            input as *const std::ffi::c_void,
            input_size,
            hash as *mut std::ffi::c_void,
        );
    }
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

    for i in 0..REGISTER_COUNT {
        rl[i] = r[i] ^ rl[i];
    }

    rl
}

pub struct IronLightVM<T> {
    reg: RegisterFile,
    mem: MemoryRegisters,
    config: ProgramConfiguration,
    scratchpad: Vec<u8>, // replace with Box<[u8]> || aligned_alloc prims
    randomx_cache: T,
    dataset_offset: usize,
    bytecode: BytecodeStorage,
}

impl<T: CacheRawAPI> IronLightVM<T>
where
    T: CacheRawAPI,
{
    pub fn new(randomx_cache: T, flags: RandomXFlags) -> RResult<Self> {
        if !flags.is_ironlight_mode() {
            return Err(VmCreationError::IncorrectIronLightModeFlag { flags })?;
        }

        let config = ProgramConfiguration::default();
        // TBD move into a separate f
        let scratchpad: Vec<u8>;
        unsafe {
            let size = RANDOMX_SCRATCHPAD_L3 * std::mem::size_of::<u8>();
            let align = 16;
            let layout = Layout::from_size_align(size, align).expect("Invalid layout");
            let scratchpad_buf = std::alloc::alloc(layout) as *mut u8;
            scratchpad = Vec::from_raw_parts(scratchpad_buf, size, size);
        }

        let reg = RegisterFile::default();
        let mem = MemoryRegisters::default();
        let dataset_offset = 0;
        let bytecode = [InstructionByteCode::default(); RANDOMX_PROGRAM_SIZE];

        let vm = Self {
            mem,
            config,
            scratchpad,
            reg,
            randomx_cache,
            dataset_offset,
            bytecode,
        };

        Ok(vm)
    }

    /// Calculates a RandomX hash value.
    pub fn hash(&mut self, local_nonce: &[u8]) -> ResultHash {
        let fpstate = get_csr();

        let mut temp_hash = Aligned16::empty();
        let temp_hash_size = std::mem::size_of::<Aligned16>();
        blake_hash(
            &mut temp_hash,
            temp_hash_size,
            local_nonce,
            local_nonce.len(),
        );

        self.init_scratchpad(&mut temp_hash);
        rx_reset_float_state();

        for _ in 0..RANDOMX_PROGRAM_COUNT - 1 {
            self.run(&mut temp_hash);
            blake_hash(
                &mut temp_hash,
                temp_hash_size,
                self.reg.to_raw(),
                std::mem::size_of::<RegisterFile>(),
            );
        }

        let result = self.run_final(&mut temp_hash).get_final_result();
        set_csr(fpstate);
        result
    }

    /// Calculates a RandomX hash value.
    pub fn prove_light(&mut self, local_nonce: &[u8]) -> HashWithGroth16Proof {
        let fpstate = get_csr();

        let mut temp_hash = Aligned16([0u64; 8]);
        let temp_hash_size = std::mem::size_of::<Aligned16>();

        let states = BIN_OP_ROW_SIZE
            * RANDOMX_PROGRAM_SIZE
            * RANDOMX_PROGRAM_COUNT
            * RANDOMX_PROGRAM_ITERATIONS;
        let mut stark_states: Vec<BabyBear> = Vec::with_capacity(states);

        blake_hash(
            &mut temp_hash,
            temp_hash_size,
            local_nonce,
            local_nonce.len(),
        );

        self.init_scratchpad(&mut temp_hash);
        rx_reset_float_state();

        for _ in 0..RANDOMX_PROGRAM_COUNT - 1 {
            let mut next_records_batch = self.run_with_trace(&mut temp_hash);
            blake_hash(
                &mut temp_hash,
                temp_hash_size,
                self.reg.to_raw(),
                std::mem::size_of::<RegisterFile>(),
            );
            stark_states.append(&mut next_records_batch);
        }

        let mut next_records_batch = self.run_with_trace(&mut temp_hash);
        stark_states.append(&mut next_records_batch);

        let result = self.get_final_result();

        set_csr(fpstate);

        let perm = inner_perm();
        let mut challenger = InnerChallenger::new(perm.clone());
        let inner = BabyBearPoseidon2Inner::default();
        let config = InnerBabyBearPoseidon2::new(inner.pcs);
        let rx_circuit = RandomXCircuit::<BabyBear>::new();

        // TBD use split_off() with a separate tail prooving.
        // stark_states.truncate(4194304 * BIN_OP_ROW_SIZE);
        stark_states.truncate(
            RANDOMX_PROGRAM_SIZE
                * RANDOMX_PROGRAM_ITERATIONS
                * RANDOMX_PROGRAM_COUNT
                * BIN_OP_ROW_SIZE,
        );

        let stark_trace = RowMajorMatrix::new(stark_states, BIN_OP_ROW_SIZE);

        let public_values = vec![];        
        let initial_stark_proof =
            prove(&config, &rx_circuit, &mut challenger, stark_trace, &public_values);

        let mut challenger = InnerChallenger::new(perm.clone());
        // WIP
        verify(
            &config,
            &rx_circuit,
            &mut challenger,
            &initial_stark_proof,
            &vec![],
        )
        .unwrap();

        let log_quotient_degree = get_log_quotient_degree(&rx_circuit, 0, 0);
        let chip = Chip::new_(rx_circuit, log_quotient_degree);
        let chips = vec![chip];
        let machine: StarkMachine<BabyBearPoseidon2, _> = StarkMachine::new(
            BabyBearPoseidon2::new(),
            chips,
            SP1_PROOF_NUM_PV_ELTS,
            false,
        );

        let prover = SP1Prover::<DefaultProverComponents>::new();
        let opts = SP1ProverOpts::default();

        let shard_proof = p3_proof_to_shardproof(initial_stark_proof);
        let outer_proof = prover.wrap_bn254_(shard_proof, opts, &machine).unwrap();

        let groth16_bn254_artifacts = if sp1_prover::build::sp1_dev_mode() {
            sp1_prover::build::try_build_groth16_bn254_artifacts_dev(
                &outer_proof.vk,
                &outer_proof.proof,
            )
        } else {
            sp1_sdk::install::try_install_circuit_artifacts("groth16")
        };

        let wrapped_bn254_proof = prover.wrap_groth16_bn254(outer_proof, &groth16_bn254_artifacts);

        prover
            .verify_groth16_bn254_(&wrapped_bn254_proof, &groth16_bn254_artifacts)
            .unwrap();

        let public_values = SP1PublicValues::from(&vec![]);        
        let stdin = SP1Stdin::new();
        let groth16_proof = SP1ProofWithPublicValues {
            proof: SP1Proof::Groth16(wrapped_bn254_proof),
            stdin,
            public_values,
            sp1_version: SP1_CIRCUIT_VERSION.to_string(),
        };

        HashWithGroth16Proof::new(result, groth16_proof.bytes()) 
    }

    // test
    fn initialize(&mut self, program: &Program) {
        let fpu_entropy = (0..8)
            .into_iter()
            .map(|i| f64::from_bits(get_small_positive_float_bits(program.get_entropy(i))))
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
            config_emask_0,
            config_emask_1,
            address_registers,
        );
    }

    fn execute<F: Field>(&mut self, program: &Program) -> Vec<F> {
        let mut stark_states =
            Vec::with_capacity(BIN_OP_ROW_SIZE * RANDOMX_PROGRAM_SIZE * RANDOMX_PROGRAM_ITERATIONS);

        let mut nreg = NativeRegisterFile::from_fp_registers(&self.reg.a);

        let bytecode_machine = BytecodeMachine::from_components(
            &program.program_buffer,
            &mut nreg,
            &mut self.bytecode,
        );

        let mut sp_addr0 = self.mem.mx as u64;
        let mut sp_addr1 = self.mem.ma as u64;

        for _ in 0..RANDOMX_PROGRAM_ITERATIONS {
            let sp_mix: u64 =
                nreg.r[self.config.read_reg0 as usize] ^ nreg.r[self.config.read_reg1 as usize];

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
            }

            for i in 0..REGISTER_COUNT_FLT {
                let entropy_address = sp_addr1 as usize + 8usize * i;
                let scratchpad_entropy =
                    &self.scratchpad[entropy_address] as *const u8 as *const c_void;
                unsafe {
                    nreg.f[i] = rx_cvt_packed_int_vec_f128(scratchpad_entropy);
                }
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
                }
            }
            let mut next_records_batch =
                bytecode_machine.execute_bytecode(&mut self.scratchpad, &self.config.e_mask);

            stark_states.append(&mut next_records_batch);

            self.mem.mx ^= (nreg.r[self.config.read_reg2 as usize]
                ^ nreg.r[self.config.read_reg3 as usize]) as u32;
            self.mem.mx &= CACHE_LINE_ALIGN_MASK;
            let dataset_offset = self.dataset_offset + self.mem.ma as usize;

            // TBD optionally dataset prefetch
            nreg.r = dataset_read(self.randomx_cache.raw(), dataset_offset, &nreg.r);

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
                nreg.f[i] = rx_xor_vec_f128(nreg.f[i], nreg.e[i]);
            }

            for i in 0..REGISTER_COUNT_FLT {
                let entropy_address = sp_addr0 as usize + 16usize * i;
                let scratchpad_dst = &mut self.scratchpad[entropy_address] as *mut u8 as *mut f64;
                rx_store_vec_f128(scratchpad_dst, &nreg.f[i]);
            }

            sp_addr0 = 0;
            sp_addr1 = 0;
        }

        self.reg.r = nreg.r;

        self.reg.store_fpu_f(&nreg.f);
        self.reg.store_fpu_e(&nreg.e);
        stark_states
    }

    fn generate_and_run(&mut self, seed: &mut Aligned16) {
        let program = Program::with_seed(seed);
        self.initialize(&program);
        let _: Vec<BabyBear> = self.execute(&program);
    }

    fn generate_and_run_with_trace<F: Field>(&mut self, seed: &mut Aligned16) -> Vec<F> {
        let program = Program::with_seed(seed);
        self.initialize(&program);
        self.execute(&program)
    }

    fn run_final(&mut self, seed: &mut Aligned16) -> &mut Self {
        self.generate_and_run(seed);
        self
    }

    fn get_final_result(&mut self) -> ResultHash {
        let mut hash = ResultHash::empty();

        aes_1rx4_hash(
            self.scratchpad.as_ptr(),
            RANDOMX_SCRATCHPAD_L3,
            self.reg.a.as_mut_ptr(),
        );
        blake_hash(
            &mut hash,
            RANDOMX_RESULT_SIZE,
            self.reg.to_raw(),
            std::mem::size_of::<RegisterFile>(),
        );

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

    fn run_with_trace<F: Field>(&mut self, seed: &mut Aligned16) -> Vec<F> {
        self.generate_and_run_with_trace(seed)
    }
}
