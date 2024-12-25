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

 use core::arch::x86_64::{__m128d, __m128i, _mm_loadl_epi64, _mm_cvtepi32_pd};
use std::arch::{asm, x86_64::{_mm_add_pd, _mm_and_pd, _mm_castsi128_pd, _mm_div_pd, _mm_loadu_pd, _mm_mul_pd, _mm_or_pd, _mm_set1_epi64x, _mm_set1_pd, _mm_set_epi64x, _mm_setcsr, _mm_shuffle_pd, _mm_sqrt_pd, _mm_store_pd, _mm_sub_pd, _mm_xor_pd}};

use crate::registers::FpuRegister;

 pub type NativeFpuRegister = __m128d;

const DYNAMIC_MANTISSA_MASK: i64 = 0xffffffffffffff;
const RX_MXCSR_DEFAULT: u32 = 0x9FC0;

#[inline(always)]
pub  fn rx_add_vec_f128(x: NativeFpuRegister, y: NativeFpuRegister) -> NativeFpuRegister {
    unsafe {
        _mm_add_pd(x, y)
    }
}

#[inline(always)]
pub  fn rx_sub_vec_f128(x: NativeFpuRegister, y: NativeFpuRegister) -> NativeFpuRegister {
    unsafe {
        _mm_sub_pd(x, y)
    }
}

#[inline(always)]
pub  fn rx_mul_vec_f128(x: NativeFpuRegister, y: NativeFpuRegister) -> NativeFpuRegister {
    unsafe {
        _mm_mul_pd(x, y)
    }
}

#[inline(always)]
pub  fn rx_div_vec_f128(x: NativeFpuRegister, y: NativeFpuRegister) -> NativeFpuRegister {
    unsafe {
        _mm_div_pd(x, y)
    }
}

#[inline(always)]
pub  fn rx_sqrt_vec_f128(x: NativeFpuRegister) -> NativeFpuRegister {
    unsafe {
        _mm_sqrt_pd(x)
    }
}

#[inline(always)]
pub fn rx_swap_vec_f128(x: NativeFpuRegister) -> NativeFpuRegister {
    unsafe {
        _mm_shuffle_pd(x, x, 1)
    }
}

#[inline(always)]
pub fn rx_xor_vec_f128(x: NativeFpuRegister, y: NativeFpuRegister) -> NativeFpuRegister {
    unsafe {
        _mm_xor_pd(x, y)
    }
}

#[inline(always)]
pub fn rx_store_fpu_as_vec_f128(dst: &mut FpuRegister, src: &NativeFpuRegister) {
    let dst = dst as *mut FpuRegister as *mut f64;
    rx_store_vec_f128(dst, src);
}

#[inline(always)]
pub fn rx_store_vec_f128(dst: *mut f64, src: &NativeFpuRegister) {
    unsafe {
        _mm_store_pd(dst, *src);
    }
}

#[inline(always)]
pub unsafe fn rx_cvt_packed_int_vec_f128(addr: *const core::ffi::c_void) -> NativeFpuRegister {
    let ix: __m128i = _mm_loadl_epi64(addr as *const __m128i);
    _mm_cvtepi32_pd(ix)
}

#[inline(always)]
unsafe fn rx_set_vec_f128( x1: i64, x0: i64) -> NativeFpuRegister {
    _mm_castsi128_pd(_mm_set_epi64x(x1, x0))
}

#[inline(always)]
pub fn rx_set1_vec_f128(x: u64) -> NativeFpuRegister {
    unsafe {
        _mm_castsi128_pd(_mm_set1_epi64x(x as i64))
    }
}

#[inline(always)]
pub unsafe fn mask_register_exponent_mantissa(config_entropy: &[u64;2], x: NativeFpuRegister) -> NativeFpuRegister {
    let xmantissa_mask = rx_set_vec_f128(DYNAMIC_MANTISSA_MASK, DYNAMIC_MANTISSA_MASK);
    let xexponent_mask = _mm_loadu_pd(config_entropy.as_ptr() as *const f64);

    let x = _mm_and_pd(x, xmantissa_mask);
    let x = _mm_or_pd(x, xexponent_mask);
    x
}

#[inline(always)]
pub fn mulh(a: u64, b: u64) -> u64 {
    ((a as u128 * b as u128) >> 64) as u64
}

#[inline(always)]
pub fn smulh(a: i64, b: i64) -> i64 {
    ((a as i128 * b as i128) >> 64) as i64
}

#[inline(always)]
pub fn rx_set_rounding_mode(mode: u32) {
    let val: u32 = RX_MXCSR_DEFAULT | (mode << 13);
    unsafe {
        asm!(
            "ldmxcsr [{0}]",
            in(reg) &val,
            options(nostack, preserves_flags)
        );
        // ldmxcsr(ptr::addr_of!(val) as *const i8);
    }
}