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
use std::ptr::{null, null_mut};
use std::{os::raw::c_void, slice::Iter};

use crate::program::{InstructionsStorage, RANDOMX_PROGRAM_SIZE};
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

// const SCRATCHPAD_L1: u32 = RANDOMX_SCRATCHPAD_L1 as u32 / 8;
// const SCRATCHPAD_L2: u32 = RANDOMX_SCRATCHPAD_L2 as u32 / 8;
// const SCRATCHPAD_L3: u32 = RANDOMX_SCRATCHPAD_L3 as u32 / 8;
// const SCRATCHPAD_L1_MASK: u32 = (SCRATCHPAD_L1 - 1) * 8;
// const SCRATCHPAD_L2_MASK: u32 = (SCRATCHPAD_L2 - 1) * 8;
// const SCRATCHPAD_L3_MASK: u32 = (SCRATCHPAD_L3 - 1) * 8;
// pub const SCRATCHPAD_L3_MASK64: i32 = ((SCRATCHPAD_L3 / 8 - 1) * 64) as i32;
// const STORE_L3_CONDITION: i32 = 14;
// const CONDITION_OFFSET: i32 = RANDOMX_JUMP_OFFSET;
// const CONDITION_MASK:u32  = (1 << RANDOMX_JUMP_BITS) - 1;

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

type RegistersCount = [i32; REGISTER_COUNT];

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

fn bc(
    instr_type: InstructionType,
    idst: *mut u64,
    isrc: *const u64,
    fdst: *mut NativeFpuRegister,
    fsrc: *const NativeFpuRegister,
    imm: u64,
    target: i16,
    shift: u16,
    mem_mask: u32,
) -> InstructionByteCode {
    InstructionByteCode {
        idst,
        isrc,
        fdst,
        fsrc,
        imm,
        target,
        shift,
        mem_mask,
        instr_type,
    }
}
// rename
fn bc_imm_replaces_isrc(
    instr_type: InstructionType,
    idst: *mut u64,
    fdst: *mut NativeFpuRegister,
    fsrc: *const NativeFpuRegister,
    imm: u64,
    target: i16,
    shift: u16,
    mem_mask: u32,
) -> InstructionByteCode {
    let mut bc = InstructionByteCode {
        idst,
        isrc: null(),
        fdst,
        fsrc,
        imm,
        target,
        shift,
        mem_mask,
        instr_type,
    };
    bc.isrc = &bc.imm;
    bc
}

impl InstructionByteCode {
    // pub fn from_instruction(
    //     instr: &Instruction,
    //     pc: i32,
    //     nreg: &mut NativeRegisterFile,
    //     register_usage: &mut RegistersCount,
    // ) -> Self {
    //     let opcode = instr.opcode as i16;
    //     println!("pc {} opcode: {}", pc, opcode);

    //     let mut instr_type = InstructionType::Nop;
    //     let mut imm: u64 = 0;
    //     let mut target: i16 = 0;
    //     let mut shift: u16 = 0;
    //     let mut mem_mask: u32 = 0;

    //     let mut idst: *mut u64 = std::ptr::null_mut();
    //     let mut isrc: *const u64 = std::ptr::null();
    //     let mut fdst: *mut NativeFpuRegister = std::ptr::null_mut();
    //     let mut fsrc: *const NativeFpuRegister = std::ptr::null();

    //     if opcode < CEIL_IADD_RS {
    //         let dst = instr.dst as usize % REGISTER_COUNT;
    //         let src = instr.src as usize % REGISTER_COUNT;
    //         instr_type = InstructionType::IAddRs;
    //         idst = &mut nreg.r[dst];
    //         if dst != REGISTER_NEEDS_DISPLACEMENT {
    //             isrc = &nreg.r[src];
    //             shift = instr.get_mod_shift().into();
    //             imm = 0;
    //         } else {
    //             isrc = &nreg.r[src];
    //             shift = instr.get_mod_shift().into();
    //             imm = sign_extend2s_compl(instr.get_imm32());
    //         }
    //         // println!("CEIL_IADD_RS dst: {}, src: {} imm64 {} ", dst, src, imm);

    //         register_usage[dst] = pc;
    //         return bc(
    //             instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
    //         );
    //     }

    //     if opcode < CEIL_IADD_M {
    //         let dst = instr.dst as usize % REGISTER_COUNT;
    //         let src = instr.src as usize % REGISTER_COUNT;
    //         instr_type = InstructionType::IAddM;
    //         idst = &mut nreg.r[dst];
    //         imm = sign_extend2s_compl(instr.get_imm32());
    //         if src != dst {
    //             isrc = &nreg.r[src];
    //             mem_mask = if instr.get_mod_mem() != 0 {
    //                 SCRATCHPAD_L1_MASK
    //             } else {
    //                 SCRATCHPAD_L2_MASK
    //             };
    //         } else {
    //             isrc = &ZERO;
    //             mem_mask = SCRATCHPAD_L3_MASK;
    //         }
    //         register_usage[dst] = pc;
    //         return bc(
    //             instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
    //         );
    //     }

    //     if opcode < CEIL_ISUB_R {
    //         let dst = instr.dst as usize % REGISTER_COUNT;
    //         let src = instr.src as usize % REGISTER_COUNT;
    //         instr_type = InstructionType::ISubR;
    //         idst = &mut nreg.r[dst];
    //         register_usage[dst] = pc;

    //         if src != dst {
    //             isrc = &nreg.r[src];
    //             return bc(
    //                 instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
    //             );
    //         } else {
    //             imm = sign_extend2s_compl(instr.get_imm32());
    //             // isrc = &imm;
    //             return bc_imm_replaces_isrc(
    //                 instr_type, idst, fdst, fsrc, imm, target, shift, mem_mask,
    //             );
    //         }
    //     }

    //     if opcode < CEIL_IMUL_R {
    //         let dst = instr.dst as usize % REGISTER_COUNT;
    //         let src = instr.src as usize % REGISTER_COUNT;
    //         println!("IMUL_R");
    //         instr_type = InstructionType::IMulR;
    //         register_usage[dst] = pc;

    //         idst = &mut nreg.r[dst];
    //         return if src != dst {
    //             isrc = &nreg.r[src];
    //             bc(
    //                 instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
    //             )
    //         } else {
    //             imm = sign_extend2s_compl(instr.get_imm32());
    //             println!("IMUL_R imm: {}", imm);
    //             bc_imm_replaces_isrc(instr_type, idst, fdst, fsrc, imm, target, shift, mem_mask)
    //         };
    //     }

    //     if opcode < CEIL_IMUL_M {
    //         let dst = instr.dst as usize % REGISTER_COUNT;
    //         let src = instr.src as usize % REGISTER_COUNT;
    //         instr_type = InstructionType::IMulM;
    //         idst = &mut nreg.r[dst];
    //         imm = sign_extend2s_compl(instr.get_imm32());
    //         if src != dst {
    //             isrc = &nreg.r[src];
    //             mem_mask = if instr.get_mod_mem() != 0 {
    //                 SCRATCHPAD_L1_MASK
    //             } else {
    //                 SCRATCHPAD_L2_MASK
    //             };
    //         } else {
    //             isrc = &ZERO;
    //             mem_mask = SCRATCHPAD_L3_MASK;
    //         }
    //         register_usage[dst] = pc;
    //         return bc(
    //             instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
    //         );
    //     }

    //     if opcode < CEIL_IMULH_R {
    //         let dst = instr.dst as usize % REGISTER_COUNT;
    //         let src = instr.src as usize % REGISTER_COUNT;
    //         instr_type = InstructionType::IMulhR;
    //         idst = &mut nreg.r[dst];
    //         isrc = &nreg.r[src];
    //         register_usage[dst] = pc;
    //         return bc(
    //             instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
    //         );
    //     }

    //     if opcode < CEIL_IMULH_M {
    //         let dst = instr.dst as usize % REGISTER_COUNT;
    //         let src = instr.src as usize % REGISTER_COUNT;
    //         instr_type = InstructionType::IMulhM;
    //         idst = &mut nreg.r[dst];
    //         imm = sign_extend2s_compl(instr.get_imm32());
    //         if src != dst {
    //             isrc = &nreg.r[src];
    //             mem_mask = if instr.get_mod_mem() != 0 {
    //                 SCRATCHPAD_L1_MASK
    //             } else {
    //                 SCRATCHPAD_L2_MASK
    //             };
    //         } else {
    //             isrc = &ZERO;
    //             mem_mask = SCRATCHPAD_L3_MASK;
    //         }
    //         register_usage[dst] = pc;
    //         return bc(
    //             instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
    //         );
    //     }

    //     if opcode < CEIL_ISMULH_R {
    //         let dst = instr.dst as usize % REGISTER_COUNT;
    //         let src = instr.src as usize % REGISTER_COUNT;
    //         instr_type = InstructionType::ISMulhR;
    //         idst = &mut nreg.r[dst];
    //         isrc = &nreg.r[src];
    //         register_usage[dst] = pc;
    //         return bc(
    //             instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
    //         );
    //     }

    //     if opcode < CEIL_ISMULH_M {
    //         let dst = instr.dst as usize % REGISTER_COUNT;
    //         let src = instr.src as usize % REGISTER_COUNT;
    //         instr_type = InstructionType::ISMulhM;
    //         idst = &mut nreg.r[dst];
    //         imm = sign_extend2s_compl(instr.get_imm32());
    //         if src != dst {
    //             isrc = &nreg.r[src];
    //             mem_mask = if instr.get_mod_mem() != 0 {
    //                 SCRATCHPAD_L1_MASK
    //             } else {
    //                 SCRATCHPAD_L2_MASK
    //             };
    //         } else {
    //             isrc = &ZERO;
    //             mem_mask = SCRATCHPAD_L3_MASK;
    //         }
    //         register_usage[dst] = pc;
    //         return bc(
    //             instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
    //         );
    //     }

    //     if opcode < CEIL_IMUL_RCP {
    //         println!("IMUL_RCP");
    //         let divisor = instr.get_imm32() as u32;
    //         if !(divisor.is_power_of_two() || divisor == 0) {
    //             let dst = instr.dst as usize % REGISTER_COUNT;
    //             instr_type = InstructionType::IMulR;
    //             idst = &mut nreg.r[dst];
    //             // imm = randomx_reciprocal(divisor);
    //             imm = randomx_reciprocal(divisor);
    //             // isrc = &imm;
    //             register_usage[dst] = pc;
    //             let bc = bc_imm_replaces_isrc(
    //                 instr_type, idst, fdst, fsrc, imm, target, shift, mem_mask,
    //             );
    //             unsafe {
    //                 println!(
    //                     "IMUL_RCP dst {} imm: {} bc.isrc {} *bc.isrc {}",
    //                     dst, imm, bc.isrc as u64, *bc.isrc
    //                 );
    //             }
    //             return bc;
    //         } else {
    //             instr_type = InstructionType::Nop;
    //             return bc(
    //                 instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
    //             );
    //         }
    //         // return bc(
    //         //     instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
    //         // );
    //     }

    //     if opcode < CEIL_INEG_R {
    //         let dst = instr.dst as usize % REGISTER_COUNT;
    //         instr_type = InstructionType::INegR;
    //         idst = &mut nreg.r[dst];
    //         register_usage[dst] = pc;
    //         return bc(
    //             instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
    //         );
    //     }

    //     if opcode < CEIL_IXOR_R {
    //         let dst = instr.dst as usize % REGISTER_COUNT;
    //         let src = instr.src as usize % REGISTER_COUNT;
    //         instr_type = InstructionType::IXorR;
    //         idst = &mut nreg.r[dst];
    //         register_usage[dst] = pc;

    //         if src != dst {
    //             isrc = &nreg.r[src];
    //             return bc(
    //                 instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
    //             );
    //         } else {
    //             imm = sign_extend2s_compl(instr.get_imm32());
    //             // isrc = &imm;
    //             return bc_imm_replaces_isrc(
    //                 instr_type, idst, fdst, fsrc, imm, target, shift, mem_mask,
    //             );
    //         }
    //     }

    //     if opcode < CEIL_IXOR_M {
    //         let dst = instr.dst as usize % REGISTER_COUNT;
    //         let src = instr.src as usize % REGISTER_COUNT;
    //         instr_type = InstructionType::IXorM;
    //         idst = &mut nreg.r[dst];
    //         imm = sign_extend2s_compl(instr.get_imm32());
    //         if src != dst {
    //             isrc = &nreg.r[src];
    //             mem_mask = if instr.get_mod_mem() != 0 {
    //                 SCRATCHPAD_L1_MASK
    //             } else {
    //                 SCRATCHPAD_L2_MASK
    //             };
    //         } else {
    //             isrc = &ZERO;
    //             mem_mask = SCRATCHPAD_L3_MASK;
    //         }
    //         register_usage[dst] = pc;
    //         return bc(
    //             instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
    //         );
    //     }

    //     if opcode < CEIL_IROR_R {
    //         let dst = instr.dst as usize % REGISTER_COUNT;
    //         let src = instr.src as usize % REGISTER_COUNT;
    //         instr_type = InstructionType::IRorR;
    //         idst = &mut nreg.r[dst];
    //         register_usage[dst] = pc;

    //         if src != dst {
    //             isrc = &nreg.r[src];
    //             return bc(
    //                 instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
    //             );
    //         } else {
    //             imm = instr.get_imm32() as u64;
    //             // isrc = &imm;
    //             return bc_imm_replaces_isrc(
    //                 instr_type, idst, fdst, fsrc, imm, target, shift, mem_mask,
    //             );
    //         }
    //     }

    //     if opcode < CEIL_IROL_R {
    //         let dst = instr.dst as usize % REGISTER_COUNT;
    //         let src = instr.src as usize % REGISTER_COUNT;
    //         instr_type = InstructionType::IRolR;
    //         idst = &mut nreg.r[dst];
    //         register_usage[dst] = pc;

    //         if src != dst {
    //             isrc = &nreg.r[src];
    //             return bc(
    //                 instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
    //             );
    //         } else {
    //             imm = instr.get_imm32() as u64;
    //             // isrc = &imm;
    //             return bc_imm_replaces_isrc(
    //                 instr_type, idst, fdst, fsrc, imm, target, shift, mem_mask,
    //             );
    //         }
    //     }

    //     if opcode < CEIL_ISWAP_R {
    //         let dst = instr.dst as usize % REGISTER_COUNT;
    //         let src = instr.src as usize % REGISTER_COUNT;
    //         if src != dst {
    //             idst = &mut nreg.r[dst];
    //             isrc = &nreg.r[src];
    //             instr_type = InstructionType::ISwapR;
    //             register_usage[dst] = pc;
    //             register_usage[src] = pc;
    //         } else {
    //             instr_type = InstructionType::Nop;
    //         }
    //         return bc(
    //             instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
    //         );
    //     }

    //     //////////////

    //     if opcode < CEIL_FSWAP_R {
    //         let dst = instr.dst as usize % REGISTER_COUNT;
    //         instr_type = InstructionType::FSwapR;
    //         if dst < REGISTER_COUNT_FLT as usize {
    //             fdst = &mut nreg.f[dst];
    //         } else {
    //             fdst = &mut nreg.e[dst - REGISTER_COUNT_FLT as usize];
    //         }
    //         return bc(
    //             instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
    //         );
    //     }

    //     if opcode < CEIL_FADD_R {
    //         let dst = instr.dst as usize % REGISTER_COUNT_FLT;
    //         let src = instr.src as usize % REGISTER_COUNT_FLT;
    //         instr_type = InstructionType::FAddR;
    //         fdst = &mut nreg.f[dst];
    //         fsrc = &nreg.a[src];
    //         return bc(
    //             instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
    //         );
    //     }

    //     if opcode < CEIL_FADD_M {
    //         let dst = instr.dst as usize % REGISTER_COUNT_FLT;
    //         let src = instr.src as usize % REGISTER_COUNT;
    //         instr_type = InstructionType::FAddM;
    //         fdst = &mut nreg.f[dst];
    //         isrc = &nreg.r[src];
    //         mem_mask = if instr.get_mod_mem() != 0 {
    //             SCRATCHPAD_L1_MASK
    //         } else {
    //             SCRATCHPAD_L2_MASK
    //         };
    //         imm = sign_extend2s_compl(instr.get_imm32());
    //         return bc(
    //             instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
    //         );
    //     }

    //     if opcode < CEIL_FSUB_R {
    //         let dst = instr.dst as usize % REGISTER_COUNT_FLT;
    //         let src = instr.src as usize % REGISTER_COUNT_FLT;
    //         instr_type = InstructionType::FSubR;
    //         fdst = &mut nreg.f[dst];
    //         fsrc = &nreg.a[src];
    //         return bc(
    //             instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
    //         );
    //     }

    //     if opcode < CEIL_FSUB_M {
    //         let dst = instr.dst as usize % REGISTER_COUNT_FLT;
    //         let src = instr.src as usize % REGISTER_COUNT;
    //         instr_type = InstructionType::FSubM;
    //         fdst = &mut nreg.f[dst];
    //         isrc = &nreg.r[src];
    //         mem_mask = if instr.get_mod_mem() != 0 {
    //             SCRATCHPAD_L1_MASK
    //         } else {
    //             SCRATCHPAD_L2_MASK
    //         };
    //         imm = sign_extend2s_compl(instr.get_imm32());
    //         return bc(
    //             instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
    //         );
    //     }

    //     if opcode < CEIL_FSCAL_R {
    //         let dst = instr.dst as usize % REGISTER_COUNT_FLT;
    //         instr_type = InstructionType::FScalR;
    //         fdst = &mut nreg.f[dst];
    //         return bc(
    //             instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
    //         );
    //     }

    //     if opcode < CEIL_FMUL_R {
    //         let dst = instr.dst as usize % REGISTER_COUNT_FLT;
    //         let src = instr.src as usize % REGISTER_COUNT_FLT;
    //         instr_type = InstructionType::FMulR;
    //         fdst = &mut nreg.e[dst];
    //         fsrc = &nreg.a[src];
    //         return bc(
    //             instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
    //         );
    //     }

    //     if opcode < CEIL_FDIV_M {
    //         let dst = instr.dst as usize % REGISTER_COUNT_FLT;
    //         let src = instr.src as usize % REGISTER_COUNT;
    //         instr_type = InstructionType::FDivM;
    //         fdst = &mut nreg.e[dst];
    //         isrc = &nreg.r[src];
    //         mem_mask = if instr.get_mod_mem() != 0 {
    //             SCRATCHPAD_L1_MASK
    //         } else {
    //             SCRATCHPAD_L2_MASK
    //         };
    //         imm = sign_extend2s_compl(instr.get_imm32());
    //         return bc(
    //             instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
    //         );
    //     }

    //     if opcode < CEIL_FSQRT_R {
    //         let dst = instr.dst as usize % REGISTER_COUNT_FLT;
    //         instr_type = InstructionType::FSqrtR;
    //         fdst = &mut nreg.e[dst];
    //         return bc(
    //             instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
    //         );
    //     }

    //     if opcode < CEIL_CBRANCH {
    //         instr_type = InstructionType::CBranch;
    //         let creg = instr.dst as usize % REGISTER_COUNT;
    //         idst = &mut nreg.r[creg];
    //         target = register_usage[creg] as i16;
    //         let cond_shift = instr.get_mod_cond() + CONDITION_OFFSET;
    //         imm = sign_extend2s_compl(instr.get_imm32() | (1 << cond_shift));
    //         if CONDITION_OFFSET > 0 || cond_shift > 0 {
    //             imm &= !(1u64 << (cond_shift - 1));
    //         }
    //         mem_mask = CONDITION_MASK << cond_shift;
    //         // mark all registers as used
    //         for j in 0..REGISTER_COUNT {
    //             register_usage[j] = pc;
    //         }
    //         return bc(
    //             instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
    //         );
    //     }

    //     if opcode < CEIL_CFROUND {
    //         let src = instr.src as usize % REGISTER_COUNT;
    //         isrc = &nreg.r[src];
    //         instr_type = InstructionType::CFround;
    //         imm = (instr.get_imm32() & 63) as u64;
    //         return bc(
    //             instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
    //         );
    //     }

    //     if opcode < CEIL_ISTORE {
    //         let dst = instr.dst as usize % REGISTER_COUNT;
    //         let src = instr.src as usize % REGISTER_COUNT;
    //         instr_type = InstructionType::IStore;
    //         idst = &mut nreg.r[dst];
    //         isrc = &nreg.r[src];
    //         imm = sign_extend2s_compl(instr.get_imm32());
    //         mem_mask = if instr.get_mod_cond() < STORE_L3_CONDITION {
    //             if instr.get_mod_mem() != 0 {
    //                 SCRATCHPAD_L1_MASK
    //             } else {
    //                 SCRATCHPAD_L2_MASK
    //             }
    //         } else {
    //             SCRATCHPAD_L3_MASK
    //         };
    //         return bc(
    //             instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
    //         );
    //     }

    //     if opcode < CEIL_NOP {
    //         instr_type = InstructionType::Nop;
    //         return bc(
    //             instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
    //         );
    //     }

    //     unreachable!("UNREACHABLE");
    // }

    pub fn modify_with_instruction(
        &mut self,
        instr: &Instruction,
        pc: i32,
        nreg: &mut NativeRegisterFile,
        register_usage: &mut RegistersCount,
    ) {
        let opcode = instr.opcode as i16;
        println!("pc {} opcode: {}", pc, opcode);

        // let mut instr_type = InstructionType::Nop;
        // let mut imm: u64 = 0;
        // let mut target: i16 = 0;
        // let mut shift: u16 = 0;
        // let mut mem_mask: u32 = 0;

        // let mut idst: *mut u64 = std::ptr::null_mut();
        // let mut isrc: *const u64 = std::ptr::null();
        // let mut fdst: *mut NativeFpuRegister = std::ptr::null_mut();
        // let mut fsrc: *const NativeFpuRegister = std::ptr::null();

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
            // println!("CEIL_IADD_RS dst: {}, src: {} imm64 {} ", dst, src, imm);

            register_usage[dst] = pc;
            return; // return bc(
                    //     instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
                    // );
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
            // return bc(
            //     instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
            // );
        }

        if opcode < CEIL_ISUB_R {
            let dst = instr.dst as usize % REGISTER_COUNT;
            let src = instr.src as usize % REGISTER_COUNT;
            self.instr_type = InstructionType::ISubR;
            self.idst = &mut nreg.r[dst];
            register_usage[dst] = pc;

            if src != dst {
                self.isrc = &nreg.r[src];
                return; // return bc(
                        //     instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
                        // );
            } else {
                self.imm = sign_extend2s_compl(instr.get_imm32());
                self.isrc = &self.imm;
                return; // return bc_imm_replaces_isrc(
                        //     instr_type, idst, fdst, fsrc, imm, target, shift, mem_mask,
                        // );
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
                return; // return bc(
                        //     instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
                        // );
            } else {
                self.isrc = &ZERO;
                self.mem_mask = SCRATCHPAD_L3_MASK;
                return; // return bc_imm_replaces_isrc(
                        //     instr_type, idst, fdst, fsrc, imm, target, shift, mem_mask,
                        // );
            }
        }

        if opcode < CEIL_IMUL_R {
            let dst = instr.dst as usize % REGISTER_COUNT;
            let src = instr.src as usize % REGISTER_COUNT;
            println!("IMUL_R");
            self.instr_type = InstructionType::IMulR;
            register_usage[dst] = pc;

            self.idst = &mut nreg.r[dst];
            return if src != dst {
                self.isrc = &nreg.r[src];
                // bc(
                //     instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
                // )
            } else {
                self.imm = sign_extend2s_compl(instr.get_imm32());
                self.isrc = &self.imm;
                println!("IMUL_R imm: {}", self.imm);
                // bc_imm_replaces_isrc(instr_type, idst, fdst, fsrc, imm, target, shift, mem_mask)
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
            return; // return bc(
                    //     instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
                    // );
        }

        if opcode < CEIL_IMULH_R {
            let dst = instr.dst as usize % REGISTER_COUNT;
            let src = instr.src as usize % REGISTER_COUNT;
            self.instr_type = InstructionType::IMulhR;
            self.idst = &mut nreg.r[dst];
            self.isrc = &nreg.r[src];
            register_usage[dst] = pc;
            return; // return bc(
                    //     instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
                    // );
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
            return; // return bc(
                    //     instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
                    // );
        }

        if opcode < CEIL_ISMULH_R {
            let dst = instr.dst as usize % REGISTER_COUNT;
            let src = instr.src as usize % REGISTER_COUNT;
            self.instr_type = InstructionType::ISMulhR;
            self.idst = &mut nreg.r[dst];
            self.isrc = &nreg.r[src];
            register_usage[dst] = pc;
            return; // return bc(
                    //     instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
                    // );
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
            return; // return bc(
                    //     instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
                    // );
        }

        if opcode < CEIL_IMUL_RCP {
            println!("IMUL_RCP");
            let divisor = instr.get_imm32() as u32;
            if !(divisor.is_power_of_two() || divisor == 0) {
                let dst = instr.dst as usize % REGISTER_COUNT;
                self.instr_type = InstructionType::IMulR;
                self.idst = &mut nreg.r[dst];
                self.imm = randomx_reciprocal(divisor);
                self.isrc = &self.imm;
                register_usage[dst] = pc;
                // let bc = bc_imm_replaces_isrc(
                //     instr_type, idst, fdst, fsrc, imm, target, shift, mem_mask,
                // );
                unsafe {
                    println!(
                        "IMUL_RCP dst {} imm: {} bc.isrc {} *bc.isrc {}",
                        dst, self.imm, self.isrc as u64, *self.isrc
                    );
                }
                // return bc;
            } else {
                self.instr_type = InstructionType::Nop;
                return; // return bc(
                        //     instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
                        // );
            }
            return; // return bc(
                    //     instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
                    // );
        }

        if opcode < CEIL_INEG_R {
            let dst = instr.dst as usize % REGISTER_COUNT;
            self.instr_type = InstructionType::INegR;
            self.idst = &mut nreg.r[dst];
            register_usage[dst] = pc;
            return; // return bc(
                    //     instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
                    // );
        }

        if opcode < CEIL_IXOR_R {
            let dst = instr.dst as usize % REGISTER_COUNT;
            let src = instr.src as usize % REGISTER_COUNT;
            self.instr_type = InstructionType::IXorR;
            self.idst = &mut nreg.r[dst];
            register_usage[dst] = pc;

            if src != dst {
                self.isrc = &nreg.r[src];
                return; // return bc(
                        //     instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
                        // );
            } else {
                self.imm = sign_extend2s_compl(instr.get_imm32());
                self.isrc = &self.imm;
                return; // return bc_imm_replaces_isrc(
                        //     instr_type, idst, fdst, fsrc, imm, target, shift, mem_mask,
                        // );
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
            // register_usage[dst] = pc;
            return; // return bc(
                    //     instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
                    // );
        }

        if opcode < CEIL_IROR_R {
            let dst = instr.dst as usize % REGISTER_COUNT;
            let src = instr.src as usize % REGISTER_COUNT;
            self.instr_type = InstructionType::IRorR;
            self.idst = &mut nreg.r[dst];
            register_usage[dst] = pc;

            if src != dst {
                self.isrc = &nreg.r[src];
                return; // return bc(
                        // instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
                        // );
            } else {
                self.imm = instr.get_imm32() as u64;
                self.isrc = &self.imm;
                return; // return bc_imm_replaces_isrc(
                        //     instr_type, idst, fdst, fsrc, imm, target, shift, mem_mask,
                        // );
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
                return; // return bc(
                        // instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
                        // );
            } else {
                self.imm = instr.get_imm32() as u64;
                self.isrc = &self.imm;
                return; // return bc_imm_replaces_isrc(
                        //     instr_type, idst, fdst, fsrc, imm, target, shift, mem_mask,
                        // );
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
            return; // return bc(
                    //     instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
                    // );
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
            return; // return bc(
                    //     instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
                    // );
        }

        if opcode < CEIL_FADD_R {
            let dst = instr.dst as usize % REGISTER_COUNT_FLT;
            let src = instr.src as usize % REGISTER_COUNT_FLT;
            self.instr_type = InstructionType::FAddR;
            self.fdst = &mut nreg.f[dst];
            self.fsrc = &nreg.a[src];
            return; // return bc(
                    //     instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
                    // );
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
            return; // return bc(
                    //     instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
                    // );
        }

        if opcode < CEIL_FSUB_R {
            let dst = instr.dst as usize % REGISTER_COUNT_FLT;
            let src = instr.src as usize % REGISTER_COUNT_FLT;
            self.instr_type = InstructionType::FSubR;
            self.fdst = &mut nreg.f[dst];
            self.fsrc = &nreg.a[src];
            return; // return bc(
                    //     instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
                    // );
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
            return; // return bc(
                    //     instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
                    // );
        }

        if opcode < CEIL_FSCAL_R {
            let dst = instr.dst as usize % REGISTER_COUNT_FLT;
            self.instr_type = InstructionType::FScalR;
            self.fdst = &mut nreg.f[dst];
            return; // return bc(
                    //     instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
                    // );
        }

        if opcode < CEIL_FMUL_R {
            let dst = instr.dst as usize % REGISTER_COUNT_FLT;
            let src = instr.src as usize % REGISTER_COUNT_FLT;
            self.instr_type = InstructionType::FMulR;
            self.fdst = &mut nreg.e[dst];
            self.fsrc = &nreg.a[src];
            return; // return bc(
                    //     instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
                    // );
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
            return; // return bc(
                    //     instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
                    // );
        }

        if opcode < CEIL_FSQRT_R {
            let dst = instr.dst as usize % REGISTER_COUNT_FLT;
            self.instr_type = InstructionType::FSqrtR;
            self.fdst = &mut nreg.e[dst];
            return; // return bc(
                    //     instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
                    // );
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
            return; // return bc(
                    //     instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
                    // );
        }

        if opcode < CEIL_CFROUND {
            let src = instr.src as usize % REGISTER_COUNT;
            self.isrc = &nreg.r[src];
            self.instr_type = InstructionType::CFround;
            self.imm = (instr.get_imm32() & 63) as u64;
            return; // return bc(
                    //     instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
                    // );
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
            return; // return bc(
                    //     instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
                    // );
        }

        if opcode < CEIL_NOP {
            self.instr_type = InstructionType::Nop;
            return; // return bc(
                    //     instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask,
                    // );
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

    fn execute(&self, pc: i16, scratchpad: &[u8], config_entropy: &[u64; 2]) -> i16 {
        let mut new_pc = pc + 1;
        // println!("instr_type: {:?}", self.instr_type);
        println!("execute bc {:?}", self);
        unsafe {
            match self.instr_type {
                InstructionType::IAddRs => {
                    let a = (*self.isrc << self.shift).wrapping_add(self.imm);
                    println!("IAddRs idst: {}, isrc: {} {}", *self.idst, *self.isrc, a);
                    *self.idst = (*self.idst).wrapping_add(a)
                }
                InstructionType::IAddM => {
                    *self.idst = (*self.idst).wrapping_add(self.get_u64_from_scratchpad(scratchpad))
                }
                InstructionType::ISubR => {
                    let a = (*self.idst).wrapping_sub(*self.isrc);
                    // println!("idst: {}, isrc: {} {}", *self.idst, *self.isrc, a);
                    *self.idst = (*self.idst).wrapping_sub(*self.isrc);
                }
                InstructionType::ISubM => {
                    *self.idst = (*self.idst).wrapping_sub(self.get_u64_from_scratchpad(scratchpad))
                }
                InstructionType::IMulR | InstructionType::IMulRcp => {
                    println!(
                        "*idst: {}, *isrc: {} isrc {}, imm {}",
                        *self.idst, *self.isrc, self.isrc as u64, self.imm
                    );
                    *self.idst = (*self.idst).wrapping_mul(*self.isrc)
                }
                InstructionType::IMulM => {
                    *self.idst = (*self.idst).wrapping_mul(self.get_u64_from_scratchpad(scratchpad))
                }
                InstructionType::IMulhR => *self.idst = mulh(*self.idst, *self.isrc),
                InstructionType::IMulhM => {
                    *self.idst = mulh(*self.idst, self.get_u64_from_scratchpad(scratchpad))
                }
                InstructionType::ISMulhR => {
                    *self.idst = smulh(*self.idst as i64, *self.isrc as i64) as u64
                } // WIP double check
                InstructionType::ISMulhM => {
                    *self.idst = smulh(
                        *self.idst as i64,
                        self.get_u64_from_scratchpad(scratchpad) as i64,
                    ) as u64
                }
                InstructionType::INegR => *self.idst = (!(*self.idst)).wrapping_add(1),
                InstructionType::IXorR => *self.idst ^= *self.isrc,
                InstructionType::IXorM => *self.idst ^= self.get_u64_from_scratchpad(scratchpad),
                InstructionType::IRorR => {
                    *self.idst = {
                        let val = *self.idst;
                        val.rotate_right((*self.isrc & 63) as u32)
                    }
                }
                InstructionType::IRolR => {
                    *self.idst = {
                        let val = *self.idst;
                        val.rotate_left((*self.isrc & 63) as u32)
                    }
                }
                InstructionType::ISwapR => {
                    let temp = *self.isrc;
                    // never do like this
                    let mut_isrc = self.isrc as *mut u64;
                    *mut_isrc = *self.idst;
                    *self.idst = temp;
                }
                InstructionType::FSwapR => *self.fdst = rx_swap_vec_f128(*self.fdst),
                InstructionType::FAddR => {
                    let a = *self.fdst;
                    *self.fdst = rx_add_vec_f128(*self.fdst, *self.fsrc);
                    println!("FAddR orig fdst {:?} fsrc: {:?} fdst: {:?},  ", a, *self.fsrc, *self.fdst);
                }
                InstructionType::FAddM => {
                    let fsrc = rx_cvt_packed_int_vec_f128(self.get_scratchpad_address(scratchpad));
                    *self.fdst = rx_add_vec_f128(*self.fdst, fsrc);
                }
                InstructionType::FSubR => *self.fdst = rx_sub_vec_f128(*self.fdst, *self.fsrc),
                InstructionType::FSubM => {
                    let fsrc = rx_cvt_packed_int_vec_f128(self.get_scratchpad_address(scratchpad));
                    *self.fdst = rx_sub_vec_f128(*self.fdst, fsrc);
                }
                InstructionType::FScalR => {
                    let mask = rx_set1_vec_f128(0x80F0000000000000);
                    *self.fdst = rx_xor_vec_f128(*self.fdst, mask);
                }
                InstructionType::FMulR => *self.fdst = rx_mul_vec_f128(*self.fdst, *self.fsrc),
                InstructionType::FDivM => {
                    let fsrc = mask_register_exponent_mantissa(
                        config_entropy,
                        rx_cvt_packed_int_vec_f128(self.get_scratchpad_address(scratchpad)),
                    );
                    *self.fdst = rx_div_vec_f128(*self.fdst, fsrc);
                }
                InstructionType::FSqrtR => *self.fdst = rx_sqrt_vec_f128(*self.fdst),
                InstructionType::CBranch => {
                    println!("CBranch idst: {}, imm {}", *self.idst, self.imm);
                    *self.idst = (*self.idst).wrapping_add(self.imm);
                    if (*self.idst & self.mem_mask as u64) == 0 {
                        new_pc = self.target;
                    }
                }
                InstructionType::CFround => {
                    let val = *self.isrc;
                    let mode = (val.rotate_right(self.imm as u32) % 4) as u32;
                    rx_set_rounding_mode(mode);
                }
                InstructionType::IStore => {
                    let scratchpad_addr =
                        ((*self.idst).wrapping_add(self.imm)) & self.mem_mask as u64;
                    let scratchpad_space =
                        &scratchpad[scratchpad_addr as usize] as *const u8 as *mut UnsafeCell<u64>;
                    (*scratchpad_space).get().write(*self.isrc);
                }
                InstructionType::Nop => {}
            }
            new_pc
        }
    }
}

pub(crate) struct BytecodeMachine<'bytecode> {
    // pub bytecode: Vec<InstructionByteCode>,
    pub bytecode: &'bytecode mut BytecodeStorage,
    register_usage: RegistersCount,
}

impl<'bytecode> BytecodeMachine<'bytecode> {
    // pub(crate) fn empty() -> Self {
    //     let bytecode = Vec::new();
    //     let register_usage = [0; REGISTER_COUNT];
    //     Self {
    //         bytecode,
    //         register_usage,
    //     }
    // }

    // pub(crate) fn from_instructions_and_nreg<'instr>(
    //     instructions: Iter<'instr, Instruction>,
    //     nreg: &mut NativeRegisterFile,
    // ) -> Self {
    //     let mut register_usage = [-1i32; REGISTER_COUNT];

    //     let bytecode = instructions
    //         .enumerate()
    //         .map(|(pc, instr)| {
    //             // Guaranteed that pc fits into u8
    //             let pc = pc as i32;
    //             InstructionByteCode::from_instruction(instr, pc, nreg, &mut register_usage)
    //         })
    //         .collect();

    //     Self {
    //         bytecode,
    //         register_usage,
    //     }
    // }

    pub(crate) fn from_components<'instr>(
        instructions: &'instr InstructionsStorage,
        nreg: &mut NativeRegisterFile,
        bytecode: &'bytecode mut BytecodeStorage,
    ) -> Self {
        let mut register_usage = [-1i32; REGISTER_COUNT];
        // let bytecode_int = vec![];

        for pc in 0..RANDOMX_PROGRAM_SIZE {
            let instr = &instructions[pc];
            bytecode[pc].modify_with_instruction(instr, pc as i32, nreg, &mut register_usage);
            // InstructionByteCode::from_instruction(instr, pc as i32, nreg, &mut register_usage);
        }
        // let bytecode = instructions
        //     .enumerate()
        //     .map(|(pc, instr)| {
        //         // Guaranteed that pc fits into u8
        //         let pc = pc as i32;
        //         InstructionByteCode::from_instruction(instr, pc, nreg, &mut register_usage)
        //     })
        //     .collect();

        Self {
            bytecode,
            register_usage,
        }
    }

    pub(crate) fn execute_bytecode(
        &self,
        scratchpad: &[u8],
        config_entropy: &[u64; 2],
        _nreg: &NativeRegisterFile,
    ) {
        let mut pc = 0;
        let mut original_pc = 0; // WIP
        let bytecode_len = self.bytecode.len() as i16;
        // while 0 <= pc && pc < 20 {
        while 0 <= pc && pc < bytecode_len {
            // println!("PC: {}", pc);
            let ibc = &self.bytecode[pc as usize];
            pc = ibc.execute(pc, scratchpad, config_entropy);
            // println!(
            //     "execute PC {:} after bc exec nreg.e[0]:  {:?}",
            //     original_pc, nreg.e[0]
            // );

            original_pc = pc;
        }
    }
}

mod tests {
    use super::*;

    fn setup() -> (NativeRegisterFile, RegistersCount) {
        let nreg = NativeRegisterFile::default();
        let register_usage = [-1i32; REGISTER_COUNT];
        (nreg, register_usage)
    }

    // #[test]
    // fn test_empty_bytecode_machine() {
    //     let machine = BytecodeMachine::empty();
    //     assert!(machine.bytecode.is_empty());
    // }

    // #[test]
    // fn test_iadd_rs() {
    //     let (mut nreg, mut usage) = setup();
    //     // guaranted to fit into u8
    //     let opcode = (CEIL_IADD_RS - 1) as u8;
    //     let instr = Instruction::new(opcode, 2, 3, 0, 1);
    //     let pc = 10;
    //     let result = InstructionByteCode::from_instruction(&instr, pc, &mut nreg, &mut usage);
    //     assert_eq!(result.instr_type, InstructionType::IAddRs);
    // }
}
