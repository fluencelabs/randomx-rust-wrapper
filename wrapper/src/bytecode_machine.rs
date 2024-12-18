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

use std::slice::Iter;

use crate::{
    instruction::{Instruction, NAMES_FREQS}, ironlight::{RANDOMX_JUMP_BITS, RANDOMX_JUMP_OFFSET, RANDOMX_SCRATCHPAD_L1, RANDOMX_SCRATCHPAD_L2, RANDOMX_SCRATCHPAD_L3}, registers::{self, NativeFpuRegister, NativeRegisterFile, REGISTER_COUNT_FLT}
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



const SCRATCHPAD_L1: u32 = RANDOMX_SCRATCHPAD_L1 as u32 / 8;
const SCRATCHPAD_L2: u32 = RANDOMX_SCRATCHPAD_L2 as u32 / 8;
const SCRATCHPAD_L3: u32 = RANDOMX_SCRATCHPAD_L3 as u32 / 8;
const SCRATCHPAD_L1_MASK: u32 = (SCRATCHPAD_L1 - 1) * 8;
const SCRATCHPAD_L2_MASK: u32 = (SCRATCHPAD_L2 - 1) * 8;
const SCRATCHPAD_L3_MASK: u32 = (SCRATCHPAD_L3 - 1) * 8;
const STORE_L3_CONDITION: i32 = 14;
const CONDITION_OFFSET: i32 = RANDOMX_JUMP_OFFSET;
const CONDITION_MASK:u32  = (1 << RANDOMX_JUMP_BITS) - 1;

static ZERO: u64 = 0;

#[derive(Debug, Clone, Copy)]
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

#[repr(C, align(16))]
pub(crate) struct InstructionByteCode {
    idst: *mut u64,
    isrc: *const u64,
    fdst: *mut NativeFpuRegister,
    fsrc: *const NativeFpuRegister,
    imm: u64,
    target: i16,
    shift: u16,
    mem_mask: u32,
    instr_type: InstructionType,
}

impl InstructionByteCode {
    pub fn from_instruction(
        instr: &Instruction,
        pc: u8,
        nreg: &mut NativeRegisterFile,
        register_usage: &mut [u8; REGISTER_COUNT],
    ) -> Self {
        pub fn bc(
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

        let opcode = instr.opcode as i16;

        let mut instr_type = InstructionType::Nop;
        let mut imm: u64 = 0;
        let mut target: i16 = 0;
        let mut shift: u16 = 0;
        let mut mem_mask: u32 = 0;

        let mut idst: *mut u64 = std::ptr::null_mut();
        let mut isrc: *const u64 = std::ptr::null();
        let mut fdst: *mut NativeFpuRegister = std::ptr::null_mut();
        let mut fsrc: *const NativeFpuRegister = std::ptr::null();

            if opcode < CEIL_IADD_RS {
                let dst = instr.dst as usize % REGISTER_COUNT;
                let src = instr.src as usize % REGISTER_COUNT;
                instr_type = InstructionType::IAddRs;
                idst = &mut nreg.r[dst];
                if dst != REGISTER_NEEDS_DISPLACEMENT {
                    isrc = &nreg.r[src];
                    shift = instr.get_mod_shift().into();
                    imm = 0;
                } else {
                    isrc = &nreg.r[src];
                    shift = instr.get_mod_shift().into();
                    imm = instr.get_imm32().into();
                }
                register_usage[dst] = pc as u8;
                return bc(instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask);
            }

            if opcode < CEIL_IADD_M {
                let dst = instr.dst as usize % REGISTER_COUNT;
                let src = instr.src as usize % REGISTER_COUNT;
                instr_type = InstructionType::IAddM;
                idst = &mut nreg.r[dst];
                imm = instr.get_imm32().into();
                if src != dst {
                    isrc = &nreg.r[src];
                    mem_mask = if instr.get_mod_mem() != 0 {
                        SCRATCHPAD_L1_MASK
                    } else {
                        SCRATCHPAD_L2_MASK
                    };
                } else {
                    isrc = &ZERO;
                    mem_mask = SCRATCHPAD_L3_MASK;
                }
                register_usage[dst] = pc;
                return bc(instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask);
            }

            if opcode < CEIL_ISUB_R {
                let dst = instr.dst as usize % REGISTER_COUNT;
                let src = instr.src as usize % REGISTER_COUNT;
                instr_type = InstructionType::ISubR;
                idst = &mut nreg.r[dst];
                if src != dst {
                    isrc = &nreg.r[src];
                } else {
                    imm = instr.get_imm32().into();
                    isrc = &imm;
                }
                register_usage[dst] = pc;
                return bc(instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask);
            }

            if opcode < CEIL_IMUL_R {
                let dst = instr.dst as usize % REGISTER_COUNT;
                let src = instr.src as usize % REGISTER_COUNT;
                instr_type = InstructionType::IMulR;
                idst = &mut nreg.r[dst];
                if src != dst {
                    isrc = &nreg.r[src];
                } else {
                    imm = instr.get_imm32().into();
                    isrc = &imm;
                }
                register_usage[dst] = pc;
                return bc(instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask);
            }
    
            if opcode < CEIL_IMUL_M {
                let dst = instr.dst as usize % REGISTER_COUNT;
                let src = instr.src as usize % REGISTER_COUNT;
                instr_type = InstructionType::IMulM;
                idst = &mut nreg.r[dst];
                imm = instr.get_imm32().into();
                if src != dst {
                    isrc = &nreg.r[src];
                    mem_mask = if instr.get_mod_mem() != 0 {
                        SCRATCHPAD_L1_MASK
                    } else {
                        SCRATCHPAD_L2_MASK
                    };
                } else {
                    isrc = &ZERO;
                    mem_mask = SCRATCHPAD_L3_MASK;
                }
                register_usage[dst] = pc;
                return bc(instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask);
            }
    
            if opcode < CEIL_IMULH_R {
                let dst = instr.dst as usize % REGISTER_COUNT;
                let src = instr.src as usize % REGISTER_COUNT;
                instr_type = InstructionType::IMulhR;
                idst = &mut nreg.r[dst];
                isrc = &nreg.r[src];
                register_usage[dst] = pc;
                return bc(instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask);
            }
    
            if opcode < CEIL_IMULH_M {
                let dst = instr.dst as usize % REGISTER_COUNT;
                let src = instr.src as usize % REGISTER_COUNT;
                instr_type = InstructionType::IMulhM;
                idst = &mut nreg.r[dst];
                imm = instr.get_imm32().into();
                if src != dst {
                    isrc = &nreg.r[src];
                    mem_mask = if instr.get_mod_mem() != 0 {
                        SCRATCHPAD_L1_MASK
                    } else {
                        SCRATCHPAD_L2_MASK
                    };
                } else {
                    isrc = &ZERO;
                    mem_mask = SCRATCHPAD_L3_MASK;
                }
                register_usage[dst] = pc;
                return bc(instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask);
            }
    
            if opcode < CEIL_ISMULH_R {
                let dst = instr.dst as usize % REGISTER_COUNT;
                let src = instr.src as usize % REGISTER_COUNT;
                instr_type = InstructionType::ISMulhR;
                idst = &mut nreg.r[dst];
                isrc = &nreg.r[src];
                register_usage[dst] = pc;
                return bc(instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask);
            }
    
            if opcode < CEIL_ISMULH_M {
                let dst = instr.dst as usize % REGISTER_COUNT;
                let src = instr.src as usize % REGISTER_COUNT;
                instr_type = InstructionType::ISMulhM;
                idst = &mut nreg.r[dst];
                imm = instr.get_imm32().into();
                if src != dst {
                    isrc = &nreg.r[src];
                    mem_mask = if instr.get_mod_mem() != 0 {
                        SCRATCHPAD_L1_MASK
                    } else {
                        SCRATCHPAD_L2_MASK
                    };
                } else {
                    isrc = &ZERO;
                    mem_mask = SCRATCHPAD_L3_MASK;
                }
                register_usage[dst] = pc;
                return bc(instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask);
            }
    
            if opcode < CEIL_IMUL_RCP {
                let divisor = instr.get_imm32() as u32;
                if !(divisor.is_power_of_two() || divisor == 0) {
                    let dst = instr.dst as usize % REGISTER_COUNT;
                    instr_type = InstructionType::IMulR;
                    idst = &mut nreg.r[dst];
                    // imm = randomx_reciprocal(divisor);
                    imm = randomx_reciprocal(divisor);
                    isrc = &imm;
                    register_usage[dst] = pc;
                } else {
                    instr_type = InstructionType::Nop;
                }
                return bc(instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask);
            }
    
            if opcode < CEIL_INEG_R {
                let dst = instr.dst as usize % REGISTER_COUNT;
                instr_type = InstructionType::INegR;
                idst = &mut nreg.r[dst];
                register_usage[dst] = pc;
                return bc(instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask);
            }
    
            if opcode < CEIL_IXOR_R {
                let dst = instr.dst as usize % REGISTER_COUNT;
                let src = instr.src as usize % REGISTER_COUNT;
                instr_type = InstructionType::IXorR;
                idst = &mut nreg.r[dst];
                if src != dst {
                    isrc = &nreg.r[src];
                } else {
                    imm = instr.get_imm32().into();
                    isrc = &imm;
                }
                register_usage[dst] = pc;
                return bc(instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask);
            }
    
            if opcode < CEIL_IXOR_M {
                let dst = instr.dst as usize % REGISTER_COUNT;
                let src = instr.src as usize % REGISTER_COUNT;
                instr_type = InstructionType::IXorM;
                idst = &mut nreg.r[dst];
                imm = instr.get_imm32().into();
                if src != dst {
                    isrc = &nreg.r[src];
                    mem_mask = if instr.get_mod_mem() != 0 {
                        SCRATCHPAD_L1_MASK
                    } else {
                        SCRATCHPAD_L2_MASK
                    };
                } else {
                    isrc = &ZERO;
                    mem_mask = SCRATCHPAD_L3_MASK;
                }
                register_usage[dst] = pc;
                return bc(instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask);
            }
    
            if opcode < CEIL_IROR_R {
                let dst = instr.dst as usize % REGISTER_COUNT;
                let src = instr.src as usize % REGISTER_COUNT;
                instr_type = InstructionType::IRorR;
                idst = &mut nreg.r[dst];
                if src != dst {
                    isrc = &nreg.r[src];
                } else {
                    imm = instr.get_imm32() as u64;
                    isrc = &imm;
                }
                register_usage[dst] = pc;
                return bc(instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask);
            }
    
            if opcode < CEIL_IROL_R {
                let dst = instr.dst as usize % REGISTER_COUNT;
                let src = instr.src as usize % REGISTER_COUNT;
                instr_type = InstructionType::IRolR;
                idst = &mut nreg.r[dst];
                if src != dst {
                    isrc = &nreg.r[src];
                } else {
                    imm = instr.get_imm32() as u64;
                    isrc = &imm;
                }
                register_usage[dst] = pc;
                return bc(instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask);
            }
    
            if opcode < CEIL_ISWAP_R {
                let dst = instr.dst as usize % REGISTER_COUNT;
                let src = instr.src as usize % REGISTER_COUNT;
                if src != dst {
                    idst = &mut nreg.r[dst];
                    isrc = &nreg.r[src];
                    instr_type = InstructionType::ISwapR;
                    register_usage[dst] = pc;
                    register_usage[src] = pc;
                } else {
                    instr_type = InstructionType::Nop;
                }
                return bc(instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask);
            }


//////////////

            if opcode < CEIL_FSWAP_R {
                let dst = instr.dst as usize % REGISTER_COUNT;
                instr_type = InstructionType::FSwapR;
                if dst < REGISTER_COUNT_FLT as usize {
                    fdst = &mut nreg.f[dst];
                } else {
                    fdst = &mut nreg.e[dst - REGISTER_COUNT_FLT as usize];
                }
                return bc(instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask);
            }

            if opcode < CEIL_FADD_R {
                let dst = instr.dst as usize % REGISTER_COUNT_FLT;
                let src = instr.src as usize % REGISTER_COUNT_FLT;
                instr_type = InstructionType::FAddR;
                fdst = &mut nreg.f[dst];
                fsrc = &nreg.a[src];
                return bc(instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask);
            }

            if opcode < CEIL_FADD_M {
                let dst = instr.dst as usize % REGISTER_COUNT_FLT;
                let src = instr.src as usize % REGISTER_COUNT;
                instr_type = InstructionType::FAddM;
                fdst = &mut nreg.f[dst];
                isrc = &nreg.r[src];
                mem_mask = if instr.get_mod_mem() != 0 {
                    SCRATCHPAD_L1_MASK
                } else {
                    SCRATCHPAD_L2_MASK
                };
                imm = instr.get_imm32().into();
                return bc(instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask);
            }

            if opcode < CEIL_FSUB_R {
                let dst = instr.dst as usize % REGISTER_COUNT_FLT;
                let src = instr.src as usize % REGISTER_COUNT_FLT;
                instr_type = InstructionType::FSubR;
                fdst = &mut nreg.f[dst];
                fsrc = &nreg.a[src];
                return bc(instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask);
            }
    
            if opcode < CEIL_FSUB_M {
                let dst = instr.dst as usize % REGISTER_COUNT_FLT;
                let src = instr.src as usize % REGISTER_COUNT;
                instr_type = InstructionType::FSubM;
                fdst = &mut nreg.f[dst];
                isrc = &nreg.r[src];
                mem_mask = if instr.get_mod_mem() != 0 {
                    SCRATCHPAD_L1_MASK
                } else {
                    SCRATCHPAD_L2_MASK
                };
                imm = instr.get_imm32().into();
                return bc(instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask);
            }
    
            if opcode < CEIL_FSCAL_R {
                let dst = instr.dst as usize % REGISTER_COUNT_FLT;
                instr_type = InstructionType::FScalR;
                fdst = &mut nreg.f[dst];
                return bc(instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask);
            }
    
            if opcode < CEIL_FMUL_R {
                let dst = instr.dst as usize % REGISTER_COUNT_FLT;
                let src = instr.src as usize % REGISTER_COUNT_FLT;
                instr_type = InstructionType::FMulR;
                fdst = &mut nreg.e[dst];
                fsrc = &nreg.a[src];
                return bc(instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask);
            }
    
            if opcode < CEIL_FDIV_M {
                let dst = instr.dst as usize % REGISTER_COUNT_FLT;
                let src = instr.src as usize % REGISTER_COUNT;
                instr_type = InstructionType::FDivM;
                fdst = &mut nreg.e[dst];
                isrc = &nreg.r[src];
                mem_mask = if instr.get_mod_mem() != 0 {
                    SCRATCHPAD_L1_MASK
                } else {
                    SCRATCHPAD_L2_MASK
                };
                imm = instr.get_imm32().into();
                return bc(instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask);
            }
    
            if opcode < CEIL_FSQRT_R {
                let dst = instr.dst as usize % REGISTER_COUNT_FLT;
                instr_type = InstructionType::FSqrtR;
                fdst = &mut nreg.e[dst];
                return bc(instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask);
            }
    
            if opcode < CEIL_CBRANCH {
                instr_type = InstructionType::CBranch;
                let creg = instr.dst as usize % REGISTER_COUNT;
                idst = &mut nreg.r[creg];
                target = register_usage[creg] as i16;
                let cond_shift = instr.get_mod_cond() + CONDITION_OFFSET;
                imm = instr.get_imm32() as u64 | (1u64 << cond_shift);
                if CONDITION_OFFSET > 0 || cond_shift > 0 {
                    imm &= !(1u64 << (cond_shift - 1));
                }
                mem_mask = CONDITION_MASK << cond_shift;
                // mark all registers as used
                for j in 0..REGISTER_COUNT {
                    register_usage[j] = pc;
                }
                return bc(instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask);
            }
    
            if opcode < CEIL_CFROUND {
                let src = instr.src as usize % REGISTER_COUNT;
                isrc = &nreg.r[src];
                instr_type = InstructionType::CFround;
                imm = (instr.get_imm32() & 63) as u64;
                return bc(instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask);
            }
    
            if opcode < CEIL_ISTORE {
                let dst = instr.dst as usize % REGISTER_COUNT;
                let src = instr.src as usize % REGISTER_COUNT;
                instr_type = InstructionType::IStore;
                idst = &mut nreg.r[dst];
                isrc = &nreg.r[src];
                imm = instr.get_imm32().into();
                mem_mask = if instr.get_mod_cond() < STORE_L3_CONDITION {
                    if instr.get_mod_mem() != 0 { SCRATCHPAD_L1_MASK } else { SCRATCHPAD_L2_MASK }
                } else {
                    SCRATCHPAD_L3_MASK
                };
                return bc(instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask);
            }
    
            if opcode < CEIL_NOP {
                instr_type = InstructionType::Nop;
                return bc(instr_type, idst, isrc, fdst, fsrc, imm, target, shift, mem_mask);
            }

            unreachable!("UNREACHABLE");
    }
}

pub(crate) struct BytecodeMachine {
    bytecode: Vec<InstructionByteCode>,
    register_usage: [u8; REGISTER_COUNT],
}

impl BytecodeMachine {
    pub(crate) fn empty() -> Self {
        let bytecode = Vec::new();
        let register_usage = [0; REGISTER_COUNT];
        Self {
            bytecode,
            register_usage,
        }
    }

    pub(crate) fn from_instructions_and_nreg<'instr>(
        instructions: Iter<'instr, Instruction>,
        nreg: &mut NativeRegisterFile,
    ) -> Self {
        let mut register_usage = [0; REGISTER_COUNT];

        let bytecode = instructions.enumerate().map(|(pc, instr)| {
            // Guaranteed that pc fits into u8
            let pc = pc as u8;
            InstructionByteCode::from_instruction(instr, pc, nreg, &mut register_usage)
        }).collect();

        let register_usage = [0; REGISTER_COUNT];
        Self {
            bytecode,
            register_usage,
        }
    }
}

mod tests {
    use super::*;

    #[test]
    fn test_empty_bytecode_machine() {
        let machine = BytecodeMachine::empty();
        assert!(machine.bytecode.is_empty());
    }
}
