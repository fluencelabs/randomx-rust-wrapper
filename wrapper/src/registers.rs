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

use std::{
    arch::x86_64::{_mm_load_pd, _mm_setzero_pd, _mm_store_pd},
    ops::BitAndAssign,
};

use crate::bindings::cache::randomx_cache;
use core::arch::x86_64::__m128d;

type IntRegister = u64;
type Addr = u32;
pub type NativeFpuRegister = __m128d;

static REGISTER_COUNT: usize = 8;
static REGISTER_COUNT_FLT: usize = REGISTER_COUNT / 2;
const CACHE_LINE_ALIGN_MASK: Addr = 0xffffffc0;

#[repr(C, align(16))]
#[derive(Debug, Clone, Copy)]
pub struct FpuRegister {
    pub lo: f64,
    pub hi: f64,
}

impl FpuRegister {
    pub fn new(lo: f64, hi: f64) -> Self {
        Self { lo, hi }
    }
}

impl Default for FpuRegister {
    fn default() -> Self {
        Self { lo: 0.0, hi: 0.0 }
    }
}

#[repr(C, align(16))]
#[derive(Debug, Clone, Copy)]
pub struct NativeRegisterFile {
    pub r: [IntRegister; REGISTER_COUNT],
    pub f: [NativeFpuRegister; REGISTER_COUNT_FLT],
    pub e: [NativeFpuRegister; REGISTER_COUNT_FLT],
    pub a: [NativeFpuRegister; REGISTER_COUNT_FLT],
}
impl NativeRegisterFile {
    pub(crate) fn from_fp_registers(a_fpu_regs: &[FpuRegister; REGISTER_COUNT_FLT]) -> Self {
        let zeros: NativeFpuRegister;
        let f: [NativeFpuRegister; REGISTER_COUNT_FLT];
        unsafe {
            zeros = _mm_setzero_pd();
            f = std::array::from_fn(|i| {
                _mm_load_pd(&a_fpu_regs[i] as *const FpuRegister as *const f64)
            });
        }

        Self {
            r: [0; REGISTER_COUNT],
            f,
            e: [zeros; REGISTER_COUNT_FLT],
            a: [zeros; REGISTER_COUNT_FLT],
        }
    }
}

fn store_fpu_register(dst: &mut FpuRegister, src: &NativeFpuRegister) {
    unsafe {
        _mm_store_pd(dst as *mut FpuRegister as *mut f64, *src);
    }
}

pub fn store_fpu_registers_array(
    dst: &mut [FpuRegister; REGISTER_COUNT_FLT],
    src: &[NativeFpuRegister; REGISTER_COUNT_FLT],
) {
    for i in 0..REGISTER_COUNT_FLT {
        store_fpu_register(&mut dst[i], &src[i]);
    }
}

#[repr(C, align(64))]
#[derive(Debug, Clone, Copy)]
pub struct RegisterFile {
    pub r: [IntRegister; REGISTER_COUNT],
    pub f: [FpuRegister; REGISTER_COUNT_FLT],
    pub e: [FpuRegister; REGISTER_COUNT_FLT],
    pub a: [FpuRegister; REGISTER_COUNT_FLT],
}

impl Default for RegisterFile {
    fn default() -> Self {
        Self {
            r: [0; REGISTER_COUNT],
            f: [FpuRegister::default(); REGISTER_COUNT_FLT],
            e: [FpuRegister::default(); REGISTER_COUNT_FLT],
            a: [FpuRegister::default(); REGISTER_COUNT_FLT],
        }
    }
}

impl RegisterFile {
    pub fn initialise_fpu_a(&mut self, entropy: &Vec<f64>) {
        for i in 0..REGISTER_COUNT_FLT {
            self.a[i] = FpuRegister::new(entropy[i], entropy[i + 1]);
        }
    }

    pub(crate) fn store_fpu_f(&mut self, new_f: &[NativeFpuRegister; REGISTER_COUNT_FLT]) {
        store_fpu_registers_array(&mut self.f, new_f);
    }

    pub(crate) fn store_fpu_e(&mut self, new_e: &[NativeFpuRegister; REGISTER_COUNT_FLT]) {
        store_fpu_registers_array(&mut self.e, new_e);
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct MemoryRegisters {
    pub(crate) mx: Addr,
    pub(crate) ma: Addr,
    pub(crate) memory: *mut randomx_cache,
}

impl Default for MemoryRegisters {
    fn default() -> Self {
        Self {
            mx: 0,
            ma: 0,
            memory: std::ptr::null_mut(),
        }
    }
}

impl MemoryRegisters {
    pub fn initialise_mem(&mut self, ma: u64, mx: u64) {
        // WIP check
        self.ma = ma as u32 & CACHE_LINE_ALIGN_MASK;
        self.mx = mx as u32;
    }
}
