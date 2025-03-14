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

use std::cell::UnsafeCell;
use std::os::raw::c_void;
use std::ptr::{null, null_mut};

use p3_field::Field;

use crate::program::{InstructionsStorage, ProgramConfigurationEntropy, RANDOMX_PROGRAM_SIZE};
use crate::stark_primitives::{BIN_OP_ROW_SIZE, CARRY};
use crate::{
    constants::{
        CONDITION_MASK, CONDITION_OFFSET, SCRATCHPAD_L1_MASK, SCRATCHPAD_L2_MASK,
        SCRATCHPAD_L3_MASK, STORE_L3_CONDITION,
    },
    instruction::{Instruction, NAMES_FREQS},
    intrinsics::{
        mask_register_exponent_mantissa, mulh, rx_add_vec_f128, rx_cvt_packed_int_vec_f128,
        rx_div_vec_f128, rx_mul_vec_f128, rx_set1_vec_f128, rx_set_rounding_mode, rx_sqrt_vec_f128,
        rx_sub_vec_f128, rx_swap_vec_f128, rx_xor_vec_f128, smulh, NativeFpuRegister,
    },
    registers::{NativeRegisterFile, REGISTER_COUNT_FLT},
};

const CEIL_NULL: i16 = 0;
const CEIL_IADD_RS: i16 = CEIL_NULL + NAMES_FREQS[0].1 as i16;
const CEIL_IADD_M: i16 = CEIL_IADD_RS + NAMES_FREQS[1].1 as i16;
const CEIL_ISUB_R: i16 = CEIL_IADD_M + NAMES_FREQS[2].1 as i16;
const CEIL_ISUB_M: i16 = CEIL_ISUB_R + NAMES_FREQS[3].1 as i16;
const CEIL_IMUL_R: i16 = CEIL_ISUB_M + NAMES_FREQS[4].1 as i16;
const CEIL_IMUL_M: i16 = CEIL_IMUL_R + NAMES_FREQS[5].1 as i16;
const CEIL_IMULH_R: i16 = CEIL_IMUL_M + NAMES_FREQS[6].1 as i16;
const CEIL_IMULH_M: i16 = CEIL_IMULH_R + NAMES_FREQS[7].1 as i16;
const CEIL_ISMULH_R: i16 = CEIL_IMULH_M + NAMES_FREQS[8].1 as i16;
const CEIL_ISMULH_M: i16 = CEIL_ISMULH_R + NAMES_FREQS[9].1 as i16;
const CEIL_IMUL_RCP: i16 = CEIL_ISMULH_M + NAMES_FREQS[10].1 as i16;
const CEIL_INEG_R: i16 = CEIL_IMUL_RCP + NAMES_FREQS[11].1 as i16;
const CEIL_IXOR_R: i16 = CEIL_INEG_R + NAMES_FREQS[12].1 as i16;
const CEIL_IXOR_M: i16 = CEIL_IXOR_R + NAMES_FREQS[13].1 as i16;
const CEIL_IROR_R: i16 = CEIL_IXOR_M + NAMES_FREQS[14].1 as i16;
const CEIL_IROL_R: i16 = CEIL_IROR_R + NAMES_FREQS[15].1 as i16;
const CEIL_ISWAP_R: i16 = CEIL_IROL_R + NAMES_FREQS[16].1 as i16;
const CEIL_FSWAP_R: i16 = CEIL_ISWAP_R + NAMES_FREQS[17].1 as i16;
const CEIL_FADD_R: i16 = CEIL_FSWAP_R + NAMES_FREQS[18].1 as i16;
const CEIL_FADD_M: i16 = CEIL_FADD_R + NAMES_FREQS[19].1 as i16;
const CEIL_FSUB_R: i16 = CEIL_FADD_M + NAMES_FREQS[20].1 as i16;
const CEIL_FSUB_M: i16 = CEIL_FSUB_R + NAMES_FREQS[21].1 as i16;
const CEIL_FSCAL_R: i16 = CEIL_FSUB_M + NAMES_FREQS[22].1 as i16;
const CEIL_FMUL_R: i16 = CEIL_FSCAL_R + NAMES_FREQS[23].1 as i16;
const CEIL_FDIV_M: i16 = CEIL_FMUL_R + NAMES_FREQS[24].1 as i16;
const CEIL_FSQRT_R: i16 = CEIL_FDIV_M + NAMES_FREQS[25].1 as i16;
const CEIL_CBRANCH: i16 = CEIL_FSQRT_R + NAMES_FREQS[26].1 as i16;
const CEIL_CFROUND: i16 = CEIL_CBRANCH + NAMES_FREQS[27].1 as i16;
const CEIL_ISTORE: i16 = CEIL_CFROUND + NAMES_FREQS[28].1 as i16;
const CEIL_NOP: i16 = CEIL_ISTORE + NAMES_FREQS[29].1 as i16;

static ZERO: u64 = 0;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InstructionType {
    IAddRs,
    IAddM,
    ISubR,
    ISubM,
    IMulR,
    IMulM,
    IMulhR,
    IMulhM,
    ISMulhR,
    ISMulhM,
    IMulRcp,
    INegR,
    IXorR,
    IXorM,
    IRorR,
    IRolR,
    ISwapR,
    FSwapR,
    FAddR,
    FAddM,
    FSubR,
    FSubM,
    FScalR,
    FMulR,
    FDivM,
    FSqrtR,
    CBranch,
    CFround,
    IStore,
    Nop,
}

const REGISTER_COUNT: usize = 8;
const REGISTER_NEEDS_DISPLACEMENT: usize = 5;

fn randomx_reciprocal(divisor: u32) -> u64 {
    assert!(divisor != 0);

    let p2exp63: u64 = 1u64 << 63;
    let q = p2exp63 / divisor as u64;
    let r = p2exp63 % divisor as u64;

    let shift = 64 - (divisor as u64).leading_zeros();

    (q << shift) + ((r << shift) / divisor as u64)
}

fn sign_extend2s_compl(x: u32) -> u64 {
    if x > i32::MAX as u32 {
        x as u64 | 0xffffffff00000000u64
    } else {
        x as u64
    }
}

pub fn populate_flags<F: Field>(instr: InstructionType) -> Vec<F> {
    let mut flags = vec![F::zero(); InstructionType::Nop as usize];
    flags[instr as usize] = F::one();
    flags
}

pub fn populate_add_trace_record<F: Field>(
    op: InstructionType,
    cnt: u32,
    left: i64,
    right: i64,
    res: i64,
) -> Vec<F> {
    let mut trace_record = Vec::with_capacity(BIN_OP_ROW_SIZE);

    trace_record.push(F::from_canonical_u32(cnt));

    let mut flags = populate_flags(op);
    trace_record.append(&mut flags);

    let left_as_b = left.to_le_bytes();
    let right_as_b = right.to_le_bytes();
    let res_as_b = res.to_le_bytes();

    for el in left_as_b {
        trace_record.push(F::from_canonical_u8(el));
    }

    for el in right_as_b {
        trace_record.push(F::from_canonical_u8(el));
    }

    for el in res_as_b {
        trace_record.push(F::from_canonical_u8(el));
    }

    let mut prev_carry_value = 0u8;
    for i in 0..CARRY {
        if (left_as_b[i] as u32) + (right_as_b[i] as u32) + (prev_carry_value as u32) > 255 {
            trace_record.push(F::one());
            prev_carry_value = 1;
        } else {
            trace_record.push(F::zero());
            prev_carry_value = 0;
        };
    }

    trace_record
}

type RegistersCount = [i32; REGISTER_COUNT];
pub(crate) struct BCExecutionResult<F: Field>(i16, Vec<F>);

#[repr(C, align(16))]
#[derive(Debug, Copy, Clone)]
pub struct InstructionByteCode {
    pub idst: *mut u64,
    pub isrc: *const u64, // not so const (
    pub fdst: *mut NativeFpuRegister,
    pub fsrc: *const NativeFpuRegister,
    pub imm: u64,
    pub target: i16,
    pub shift: u16,
    pub mem_mask: u32,
    pub instr_type: InstructionType,
}

pub type BytecodeStorage = [InstructionByteCode; RANDOMX_PROGRAM_SIZE];

impl Default for InstructionByteCode {
    fn default() -> Self {
        bc_noop()
    }
}

fn bc_noop() -> InstructionByteCode {
    InstructionByteCode {
        idst: null_mut(),
        isrc: null(),
        fdst: null_mut(),
        fsrc: null(),
        imm: 0,
        target: 0,
        shift: 0,
        mem_mask: 0,
        instr_type: InstructionType::Nop,
    }
}

impl InstructionByteCode {
    pub fn modify_with_instruction(
        &mut self,
        instr: &Instruction,
        pc: i32,
        nreg: &mut NativeRegisterFile,
        register_usage: &mut RegistersCount,
    ) {
        let opcode = instr.opcode as i16;

        if opcode < CEIL_IADD_RS {
            let dst = instr.dst as usize % REGISTER_COUNT;
            let src = instr.src as usize % REGISTER_COUNT;
            self.instr_type = InstructionType::IAddRs;
            self.idst = &mut nreg.r[dst];
            if dst != REGISTER_NEEDS_DISPLACEMENT {
                self.isrc = &nreg.r[src];
                self.shift = instr.get_mod_shift().into();
                self.imm = 0;
            } else {
                self.isrc = &nreg.r[src];
                self.shift = instr.get_mod_shift().into();
                self.imm = sign_extend2s_compl(instr.get_imm32());
            }

            register_usage[dst] = pc;
            return;
        }

        if opcode < CEIL_IADD_M {
            let dst = instr.dst as usize % REGISTER_COUNT;
            let src = instr.src as usize % REGISTER_COUNT;
            self.instr_type = InstructionType::IAddM;
            self.idst = &mut nreg.r[dst];
            self.imm = sign_extend2s_compl(instr.get_imm32());
            if src != dst {
                self.isrc = &nreg.r[src];
                self.mem_mask = if instr.get_mod_mem() != 0 {
                    SCRATCHPAD_L1_MASK
                } else {
                    SCRATCHPAD_L2_MASK
                };
            } else {
                self.isrc = &ZERO;
                self.mem_mask = SCRATCHPAD_L3_MASK;
            }
            register_usage[dst] = pc;
            return;
        }

        if opcode < CEIL_ISUB_R {
            let dst = instr.dst as usize % REGISTER_COUNT;
            let src = instr.src as usize % REGISTER_COUNT;
            self.instr_type = InstructionType::ISubR;
            self.idst = &mut nreg.r[dst];
            register_usage[dst] = pc;
            if src != dst {
                self.isrc = &nreg.r[src];

                return;
            } else {
                self.imm = sign_extend2s_compl(instr.get_imm32());

                self.isrc = &self.imm;
                return;
            }
        }

        if opcode < CEIL_ISUB_M {
            let dst = instr.dst as usize % REGISTER_COUNT;
            let src = instr.src as usize % REGISTER_COUNT;
            self.instr_type = InstructionType::ISubM;
            self.idst = &mut nreg.r[dst];
            self.imm = sign_extend2s_compl(instr.get_imm32());
            register_usage[dst] = pc;

            if src != dst {
                self.isrc = &nreg.r[src];
                self.mem_mask = if instr.get_mod_mem() != 0 {
                    SCRATCHPAD_L1_MASK
                } else {
                    SCRATCHPAD_L2_MASK
                };
                return;
            } else {
                self.isrc = &ZERO;
                self.mem_mask = SCRATCHPAD_L3_MASK;
                return;
            }
        }

        if opcode < CEIL_IMUL_R {
            let dst = instr.dst as usize % REGISTER_COUNT;
            let src = instr.src as usize % REGISTER_COUNT;
            self.instr_type = InstructionType::IMulR;
            register_usage[dst] = pc;

            self.idst = &mut nreg.r[dst];
            return if src != dst {
                self.isrc = &nreg.r[src];
            } else {
                self.imm = sign_extend2s_compl(instr.get_imm32());
                self.isrc = &self.imm;
            };
        }

        if opcode < CEIL_IMUL_M {
            let dst = instr.dst as usize % REGISTER_COUNT;
            let src = instr.src as usize % REGISTER_COUNT;
            self.instr_type = InstructionType::IMulM;
            self.idst = &mut nreg.r[dst];
            self.imm = sign_extend2s_compl(instr.get_imm32());
            if src != dst {
                self.isrc = &nreg.r[src];
                self.mem_mask = if instr.get_mod_mem() != 0 {
                    SCRATCHPAD_L1_MASK
                } else {
                    SCRATCHPAD_L2_MASK
                };
            } else {
                self.isrc = &ZERO;
                self.mem_mask = SCRATCHPAD_L3_MASK;
            }
            register_usage[dst] = pc;
            return;
        }

        if opcode < CEIL_IMULH_R {
            let dst = instr.dst as usize % REGISTER_COUNT;
            let src = instr.src as usize % REGISTER_COUNT;
            self.instr_type = InstructionType::IMulhR;
            self.idst = &mut nreg.r[dst];
            self.isrc = &nreg.r[src];
            register_usage[dst] = pc;
            return;
        }

        if opcode < CEIL_IMULH_M {
            let dst = instr.dst as usize % REGISTER_COUNT;
            let src = instr.src as usize % REGISTER_COUNT;
            self.instr_type = InstructionType::IMulhM;
            self.idst = &mut nreg.r[dst];
            self.imm = sign_extend2s_compl(instr.get_imm32());
            if src != dst {
                self.isrc = &nreg.r[src];
                self.mem_mask = if instr.get_mod_mem() != 0 {
                    SCRATCHPAD_L1_MASK
                } else {
                    SCRATCHPAD_L2_MASK
                };
            } else {
                self.isrc = &ZERO;
                self.mem_mask = SCRATCHPAD_L3_MASK;
            }
            register_usage[dst] = pc;
            return;
        }

        if opcode < CEIL_ISMULH_R {
            let dst = instr.dst as usize % REGISTER_COUNT;
            let src = instr.src as usize % REGISTER_COUNT;
            self.instr_type = InstructionType::ISMulhR;
            self.idst = &mut nreg.r[dst];
            self.isrc = &nreg.r[src];
            register_usage[dst] = pc;
            return;
        }

        if opcode < CEIL_ISMULH_M {
            let dst = instr.dst as usize % REGISTER_COUNT;
            let src = instr.src as usize % REGISTER_COUNT;
            self.instr_type = InstructionType::ISMulhM;
            self.idst = &mut nreg.r[dst];
            self.imm = sign_extend2s_compl(instr.get_imm32());
            if src != dst {
                self.isrc = &nreg.r[src];
                self.mem_mask = if instr.get_mod_mem() != 0 {
                    SCRATCHPAD_L1_MASK
                } else {
                    SCRATCHPAD_L2_MASK
                };
            } else {
                self.isrc = &ZERO;
                self.mem_mask = SCRATCHPAD_L3_MASK;
            }
            register_usage[dst] = pc;
            return;
        }

        if opcode < CEIL_IMUL_RCP {
            let divisor = instr.get_imm32() as u32;
            if !(divisor.is_power_of_two() || divisor == 0) {
                let dst = instr.dst as usize % REGISTER_COUNT;
                self.instr_type = InstructionType::IMulR;
                self.idst = &mut nreg.r[dst];
                self.imm = randomx_reciprocal(divisor);
                self.isrc = &self.imm;
                register_usage[dst] = pc;
            } else {
                self.instr_type = InstructionType::Nop;
            }
            return;
        }

        if opcode < CEIL_INEG_R {
            let dst = instr.dst as usize % REGISTER_COUNT;
            self.instr_type = InstructionType::INegR;
            self.idst = &mut nreg.r[dst];
            register_usage[dst] = pc;
            return;
        }

        if opcode < CEIL_IXOR_R {
            let dst = instr.dst as usize % REGISTER_COUNT;
            let src = instr.src as usize % REGISTER_COUNT;
            self.instr_type = InstructionType::IXorR;
            self.idst = &mut nreg.r[dst];
            register_usage[dst] = pc;

            if src != dst {
                self.isrc = &nreg.r[src];
                return;
            } else {
                self.imm = sign_extend2s_compl(instr.get_imm32());
                self.isrc = &self.imm;
                return;
            }
        }

        if opcode < CEIL_IXOR_M {
            let dst = instr.dst as usize % REGISTER_COUNT;
            let src = instr.src as usize % REGISTER_COUNT;
            self.instr_type = InstructionType::IXorM;
            self.idst = &mut nreg.r[dst];
            self.imm = sign_extend2s_compl(instr.get_imm32());
            if src != dst {
                self.isrc = &nreg.r[src];
                self.mem_mask = if instr.get_mod_mem() != 0 {
                    SCRATCHPAD_L1_MASK
                } else {
                    SCRATCHPAD_L2_MASK
                };
            } else {
                self.isrc = &ZERO;
                self.mem_mask = SCRATCHPAD_L3_MASK;
            }
            register_usage[dst] = pc;
            return;
        }

        if opcode < CEIL_IROR_R {
            let dst = instr.dst as usize % REGISTER_COUNT;
            let src = instr.src as usize % REGISTER_COUNT;
            self.instr_type = InstructionType::IRorR;
            self.idst = &mut nreg.r[dst];
            register_usage[dst] = pc;

            if src != dst {
                self.isrc = &nreg.r[src];
                return;
            } else {
                self.imm = instr.get_imm32() as u64;
                self.isrc = &self.imm;
                return;
            }
        }

        if opcode < CEIL_IROL_R {
            let dst = instr.dst as usize % REGISTER_COUNT;
            let src = instr.src as usize % REGISTER_COUNT;
            self.instr_type = InstructionType::IRolR;
            self.idst = &mut nreg.r[dst];
            register_usage[dst] = pc;

            if src != dst {
                self.isrc = &nreg.r[src];
                return;
            } else {
                self.imm = instr.get_imm32() as u64;
                self.isrc = &self.imm;
                return;
            }
        }

        if opcode < CEIL_ISWAP_R {
            let dst = instr.dst as usize % REGISTER_COUNT;
            let src = instr.src as usize % REGISTER_COUNT;
            if src != dst {
                self.idst = &mut nreg.r[dst];
                self.isrc = &nreg.r[src];
                self.instr_type = InstructionType::ISwapR;
                register_usage[dst] = pc;
                register_usage[src] = pc;
            } else {
                self.instr_type = InstructionType::Nop;
            }
            return;
        }

        //////////////

        if opcode < CEIL_FSWAP_R {
            let dst = instr.dst as usize % REGISTER_COUNT;
            self.instr_type = InstructionType::FSwapR;
            if dst < REGISTER_COUNT_FLT as usize {
                self.fdst = &mut nreg.f[dst];
            } else {
                self.fdst = &mut nreg.e[dst - REGISTER_COUNT_FLT as usize];
            }
            return;
        }

        if opcode < CEIL_FADD_R {
            let dst = instr.dst as usize % REGISTER_COUNT_FLT;
            let src = instr.src as usize % REGISTER_COUNT_FLT;
            self.instr_type = InstructionType::FAddR;
            self.fdst = &mut nreg.f[dst];
            self.fsrc = &nreg.a[src];
            return;
        }

        if opcode < CEIL_FADD_M {
            let dst = instr.dst as usize % REGISTER_COUNT_FLT;
            let src = instr.src as usize % REGISTER_COUNT;
            self.instr_type = InstructionType::FAddM;
            self.fdst = &mut nreg.f[dst];
            self.isrc = &nreg.r[src];
            self.mem_mask = if instr.get_mod_mem() != 0 {
                SCRATCHPAD_L1_MASK
            } else {
                SCRATCHPAD_L2_MASK
            };
            self.imm = sign_extend2s_compl(instr.get_imm32());
            return;
        }

        if opcode < CEIL_FSUB_R {
            let dst = instr.dst as usize % REGISTER_COUNT_FLT;
            let src = instr.src as usize % REGISTER_COUNT_FLT;
            self.instr_type = InstructionType::FSubR;
            self.fdst = &mut nreg.f[dst];
            self.fsrc = &nreg.a[src];
            return;
        }

        if opcode < CEIL_FSUB_M {
            let dst = instr.dst as usize % REGISTER_COUNT_FLT;
            let src = instr.src as usize % REGISTER_COUNT;
            self.instr_type = InstructionType::FSubM;
            self.fdst = &mut nreg.f[dst];
            self.isrc = &nreg.r[src];
            self.mem_mask = if instr.get_mod_mem() != 0 {
                SCRATCHPAD_L1_MASK
            } else {
                SCRATCHPAD_L2_MASK
            };
            self.imm = sign_extend2s_compl(instr.get_imm32());
            return;
        }

        if opcode < CEIL_FSCAL_R {
            let dst = instr.dst as usize % REGISTER_COUNT_FLT;
            self.instr_type = InstructionType::FScalR;
            self.fdst = &mut nreg.f[dst];
            return;
        }

        if opcode < CEIL_FMUL_R {
            let dst = instr.dst as usize % REGISTER_COUNT_FLT;
            let src = instr.src as usize % REGISTER_COUNT_FLT;
            self.instr_type = InstructionType::FMulR;
            self.fdst = &mut nreg.e[dst];
            self.fsrc = &nreg.a[src];
            return;
        }

        if opcode < CEIL_FDIV_M {
            let dst = instr.dst as usize % REGISTER_COUNT_FLT;
            let src = instr.src as usize % REGISTER_COUNT;
            self.instr_type = InstructionType::FDivM;
            self.fdst = &mut nreg.e[dst];
            self.isrc = &nreg.r[src];
            self.mem_mask = if instr.get_mod_mem() != 0 {
                SCRATCHPAD_L1_MASK
            } else {
                SCRATCHPAD_L2_MASK
            };
            self.imm = sign_extend2s_compl(instr.get_imm32());
            return;
        }

        if opcode < CEIL_FSQRT_R {
            let dst = instr.dst as usize % REGISTER_COUNT_FLT;
            self.instr_type = InstructionType::FSqrtR;
            self.fdst = &mut nreg.e[dst];
            return;
        }

        if opcode < CEIL_CBRANCH {
            self.instr_type = InstructionType::CBranch;
            let creg = instr.dst as usize % REGISTER_COUNT;
            self.idst = &mut nreg.r[creg];
            self.target = register_usage[creg] as i16;
            let cond_shift = instr.get_mod_cond() + CONDITION_OFFSET;
            self.imm = sign_extend2s_compl(instr.get_imm32() | (1 << cond_shift));
            if CONDITION_OFFSET > 0 || cond_shift > 0 {
                self.imm &= !(1u64 << (cond_shift - 1));
            }
            self.mem_mask = CONDITION_MASK << cond_shift;
            // mark all registers as used
            for j in 0..REGISTER_COUNT {
                register_usage[j] = pc;
            }
            return;
        }

        if opcode < CEIL_CFROUND {
            let src = instr.src as usize % REGISTER_COUNT;
            self.isrc = &nreg.r[src];
            self.instr_type = InstructionType::CFround;
            self.imm = (instr.get_imm32() & 63) as u64;
            return;
        }

        if opcode < CEIL_ISTORE {
            let dst = instr.dst as usize % REGISTER_COUNT;
            let src = instr.src as usize % REGISTER_COUNT;
            self.instr_type = InstructionType::IStore;
            self.idst = &mut nreg.r[dst];
            self.isrc = &nreg.r[src];
            self.imm = sign_extend2s_compl(instr.get_imm32());
            self.mem_mask = if instr.get_mod_cond() < STORE_L3_CONDITION {
                if instr.get_mod_mem() != 0 {
                    SCRATCHPAD_L1_MASK
                } else {
                    SCRATCHPAD_L2_MASK
                }
            } else {
                SCRATCHPAD_L3_MASK
            };
            return;
        }

        if opcode < CEIL_NOP {
            self.instr_type = InstructionType::Nop;
            return;
        }

        unreachable!("UNREACHABLE");
    }

    fn get_u64_from_scratchpad(&self, scratchpad: &[u8]) -> u64 {
        unsafe {
            let scratchpad_addr =
                ((*self.isrc).wrapping_add(self.imm)) as usize & self.mem_mask as usize;
            let scratchpad_addr_as_u64_ptr =
                &scratchpad[scratchpad_addr] as *const u8 as *const u64;
            *scratchpad_addr_as_u64_ptr
        }
    }

    fn get_scratchpad_address(&self, scratchpad: &[u8]) -> *const c_void {
        unsafe {
            let scratchpad_addr =
                ((*self.isrc).wrapping_add(self.imm)) as usize & self.mem_mask as usize;
            &scratchpad[scratchpad_addr] as *const u8 as *const c_void
        }
    }

    fn execute<F: Field>(
        &self,
        pc: i16,
        scratchpad: &mut [u8],
        config_entropy: &ProgramConfigurationEntropy,
    ) -> BCExecutionResult<F> {
        let mut new_pc = pc;
        let next_record = unsafe {
            match self.instr_type {
                InstructionType::IAddRs => {
                    let shifted_src = (*self.isrc << self.shift).wrapping_add(self.imm);
                    let original_idst_value = *self.idst as i64;
                    *self.idst = (*self.idst).wrapping_add(shifted_src);
                    populate_add_trace_record(
                        self.instr_type,
                        pc as u32,
                        original_idst_value,
                        shifted_src as i64,
                        *self.idst as i64,
                    )
                }
                InstructionType::IAddM => {
                    let original_idst_value = *self.idst as i64;
                    let entropy_value = self.get_u64_from_scratchpad(scratchpad) as i64;
                    *self.idst =
                        (*self.idst).wrapping_add(self.get_u64_from_scratchpad(scratchpad));
                    populate_add_trace_record(
                        self.instr_type,
                        pc as u32,
                        original_idst_value,
                        entropy_value,
                        *self.idst as i64,
                    )
                }
                InstructionType::ISubR => {
                    *self.idst = (*self.idst).wrapping_sub(*self.isrc);
                    vec![F::zero(); BIN_OP_ROW_SIZE]
                }
                InstructionType::ISubM => {
                    *self.idst =
                        (*self.idst).wrapping_sub(self.get_u64_from_scratchpad(scratchpad));
                    vec![F::zero(); BIN_OP_ROW_SIZE]
                }
                InstructionType::IMulR | InstructionType::IMulRcp => {
                    *self.idst = (*self.idst).wrapping_mul(*self.isrc);
                    vec![F::zero(); BIN_OP_ROW_SIZE]
                }
                InstructionType::IMulM => {
                    *self.idst =
                        (*self.idst).wrapping_mul(self.get_u64_from_scratchpad(scratchpad));
                    vec![F::zero(); BIN_OP_ROW_SIZE]
                }
                InstructionType::IMulhR => {
                    *self.idst = mulh(*self.idst, *self.isrc);
                    vec![F::zero(); BIN_OP_ROW_SIZE]
                }
                InstructionType::IMulhM => {
                    *self.idst = mulh(*self.idst, self.get_u64_from_scratchpad(scratchpad));
                    vec![F::zero(); BIN_OP_ROW_SIZE]
                }
                InstructionType::ISMulhR => {
                    *self.idst = smulh(*self.idst as i64, *self.isrc as i64) as u64;
                    vec![F::zero(); BIN_OP_ROW_SIZE]
                }
                InstructionType::ISMulhM => {
                    *self.idst = smulh(
                        *self.idst as i64,
                        self.get_u64_from_scratchpad(scratchpad) as i64,
                    ) as u64;
                    vec![F::zero(); BIN_OP_ROW_SIZE]
                }
                InstructionType::INegR => {
                    *self.idst = (!(*self.idst)).wrapping_add(1);
                    vec![F::zero(); BIN_OP_ROW_SIZE]
                }
                InstructionType::IXorR => {
                    *self.idst ^= *self.isrc;
                    vec![F::zero(); BIN_OP_ROW_SIZE]
                }
                InstructionType::IXorM => {
                    *self.idst ^= self.get_u64_from_scratchpad(scratchpad);
                    vec![F::zero(); BIN_OP_ROW_SIZE]
                }
                InstructionType::IRorR => {
                    *self.idst = {
                        let val = *self.idst;
                        val.rotate_right((*self.isrc & 63) as u32)
                    };
                    vec![F::zero(); BIN_OP_ROW_SIZE]
                }
                InstructionType::IRolR => {
                    *self.idst = {
                        let val = *self.idst;
                        val.rotate_left((*self.isrc & 63) as u32)
                    };
                    vec![F::zero(); BIN_OP_ROW_SIZE]
                }
                InstructionType::ISwapR => {
                    let temp = *self.isrc;
                    // never do like this
                    let mut_isrc = self.isrc as *mut u64;
                    *mut_isrc = *self.idst;
                    *self.idst = temp;
                    vec![F::zero(); BIN_OP_ROW_SIZE]
                }
                InstructionType::FSwapR => {
                    *self.fdst = rx_swap_vec_f128(*self.fdst);
                    vec![F::zero(); BIN_OP_ROW_SIZE]
                }
                InstructionType::FAddR => {
                    *self.fdst = rx_add_vec_f128(*self.fdst, *self.fsrc);
                    vec![F::zero(); BIN_OP_ROW_SIZE]
                }
                InstructionType::FAddM => {
                    let fsrc = rx_cvt_packed_int_vec_f128(self.get_scratchpad_address(scratchpad));
                    *self.fdst = rx_add_vec_f128(*self.fdst, fsrc);
                    vec![F::zero(); BIN_OP_ROW_SIZE]
                }
                InstructionType::FSubR => {
                    *self.fdst = rx_sub_vec_f128(*self.fdst, *self.fsrc);
                    vec![F::zero(); BIN_OP_ROW_SIZE]
                }
                InstructionType::FSubM => {
                    let fsrc = rx_cvt_packed_int_vec_f128(self.get_scratchpad_address(scratchpad));
                    *self.fdst = rx_sub_vec_f128(*self.fdst, fsrc);
                    vec![F::zero(); BIN_OP_ROW_SIZE]
                }
                InstructionType::FScalR => {
                    let mask = rx_set1_vec_f128(0x80F0000000000000);
                    *self.fdst = rx_xor_vec_f128(*self.fdst, mask);
                    vec![F::zero(); BIN_OP_ROW_SIZE]
                }
                InstructionType::FMulR => {
                    *self.fdst = rx_mul_vec_f128(*self.fdst, *self.fsrc);
                    vec![F::zero(); BIN_OP_ROW_SIZE]
                }
                InstructionType::FDivM => {
                    let fsrc = mask_register_exponent_mantissa(
                        config_entropy,
                        rx_cvt_packed_int_vec_f128(self.get_scratchpad_address(scratchpad)),
                    );
                    *self.fdst = rx_div_vec_f128(*self.fdst, fsrc);
                    vec![F::zero(); BIN_OP_ROW_SIZE]
                }
                InstructionType::FSqrtR => {
                    *self.fdst = rx_sqrt_vec_f128(*self.fdst);
                    vec![F::zero(); BIN_OP_ROW_SIZE]
                }
                InstructionType::CBranch => {
                    *self.idst = (*self.idst).wrapping_add(self.imm);
                    if (*self.idst & self.mem_mask as u64) == 0 {
                        new_pc = self.target;
                    };
                    vec![F::zero(); BIN_OP_ROW_SIZE]
                }
                InstructionType::CFround => {
                    let val = *self.isrc;
                    let mode = (val.rotate_right(self.imm as u32) % 4) as u32;
                    rx_set_rounding_mode(mode);
                    vec![F::zero(); BIN_OP_ROW_SIZE]
                }
                InstructionType::IStore => {
                    let scratchpad_addr =
                        ((*self.idst).wrapping_add(self.imm)) & self.mem_mask as u64;
                    let scratchpad_space =
                        &scratchpad[scratchpad_addr as usize] as *const u8 as *mut UnsafeCell<u64>;
                    (*scratchpad_space).get().write(*self.isrc);
                    vec![F::zero(); BIN_OP_ROW_SIZE]
                }
                InstructionType::Nop => {
                    vec![F::zero(); BIN_OP_ROW_SIZE]
                }
            }
        };
        BCExecutionResult(new_pc, next_record)
    }
}

pub(crate) struct BytecodeMachine<'bytecode> {
    pub bytecode: &'bytecode mut BytecodeStorage,
}

impl<'bytecode> BytecodeMachine<'bytecode> {
    pub(crate) fn from_components<'instr>(
        instructions: &'instr InstructionsStorage,
        nreg: &mut NativeRegisterFile,
        bytecode: &'bytecode mut BytecodeStorage,
    ) -> Self {
        let mut register_usage = [-1i32; REGISTER_COUNT];

        for pc in 0..RANDOMX_PROGRAM_SIZE {
            let instr = &instructions[pc];
            bytecode[pc].modify_with_instruction(instr, pc as i32, nreg, &mut register_usage);
        }

        Self { bytecode }
    }

    pub(crate) fn execute_bytecode<F: Field>(
        &self,
        scratchpad: &mut [u8],
        config_entropy: &[u64; 2],
    ) -> Vec<F> {
        let mut stark_states = Vec::with_capacity(BIN_OP_ROW_SIZE * RANDOMX_PROGRAM_SIZE);
        let mut pc = 0;
        let bytecode_len = self.bytecode.len() as i16;
        while 0 <= pc && pc < bytecode_len {
            let ibc = &self.bytecode[pc as usize];
            let BCExecutionResult(new_pc, mut next_records_batch) =
                ibc.execute(pc, scratchpad, config_entropy);
            stark_states.append(&mut next_records_batch);
            pc = new_pc + 1;
        }
        stark_states
    }
}

#[allow(dead_code, unused_imports)]
mod tests {
    use p3_baby_bear::BabyBear;

    use crate::constants::RANDOMX_SCRATCHPAD_L3;

    use super::*;

    fn setup() -> (NativeRegisterFile, RegistersCount) {
        let nreg = NativeRegisterFile::default();
        let register_usage = [-1i32; REGISTER_COUNT];
        (nreg, register_usage)
    }

    #[test]
    fn test_modify_iadd_rs() {
        let opcode = CEIL_IADD_RS - 1;
        let instr = Instruction::new(opcode as u8, 1, 2, 123, 3);
        let mut bc = InstructionByteCode::default();

        let (mut nreg, mut register_usage) = setup();
        let pc = 10;

        bc.modify_with_instruction(&instr, pc, &mut nreg, &mut register_usage);

        assert_eq!(bc.instr_type, InstructionType::IAddRs);
        assert_eq!(bc.idst, &mut nreg.r[1] as *mut u64);
        assert_eq!(bc.isrc, &nreg.r[2] as *const u64);
        assert_eq!(bc.shift, instr.get_mod_shift() as u16);
        assert_eq!(bc.imm, 0);
        assert_eq!(register_usage[1], pc);
    }

    #[test]
    fn test_modify_iadd_rs_w_displacement_dst() {
        let opcode = CEIL_IADD_RS - 1; // попадаем в первую ветку: if opcode < CEIL_IADD_RS
        let dst_reg_id = 5;
        let instr = Instruction::new(opcode as u8, dst_reg_id, 2, 123, 3);
        let mut bc = InstructionByteCode::default();

        let (mut nreg, mut register_usage) = setup();
        let pc = 10;

        bc.modify_with_instruction(&instr, pc, &mut nreg, &mut register_usage);

        assert_eq!(bc.instr_type, InstructionType::IAddRs);
        assert_eq!(bc.idst, &mut nreg.r[dst_reg_id as usize] as *mut u64);
        assert_eq!(bc.isrc, &nreg.r[2] as *const u64);
        assert_eq!(bc.shift, instr.get_mod_shift() as u16);
        assert_eq!(bc.imm, sign_extend2s_compl(instr.get_imm32()));
        assert_eq!(register_usage[dst_reg_id as usize], pc);
    }

    #[test]
    fn test_execute_iadd_rs() {
        let opcode = CEIL_IADD_RS - 1;
        let dst_reg_id = 1;
        let src_reg_id = 2;
        let instr = Instruction::new(opcode as u8, dst_reg_id, src_reg_id, 123, 3);
        let mut bc = InstructionByteCode::default();

        let (mut nreg, mut register_usage) = setup();
        nreg.r[dst_reg_id as usize] = 342;
        nreg.r[src_reg_id as usize] = 343;
        let pc = 10;

        bc.modify_with_instruction(&instr, pc, &mut nreg, &mut register_usage);

        let mut scratchpad = vec![0; RANDOMX_SCRATCHPAD_L3];
        let config_entropy = ProgramConfigurationEntropy::default();
        let BCExecutionResult(new_pc, next_records_batch) =
            bc.execute::<BabyBear>(pc as i16, &mut scratchpad, &config_entropy);

        assert_eq!(new_pc, pc as i16);
        assert_eq!(next_records_batch.len(), BIN_OP_ROW_SIZE);
    }
}
