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

pub const RANDOMX_SCRATCHPAD_L1: usize = 16384;
pub const RANDOMX_SCRATCHPAD_L2: usize = 262144;
pub const RANDOMX_SCRATCHPAD_L3: usize = 2097152;
pub const RANDOMX_JUMP_OFFSET: i32 = 8;
pub const RANDOMX_JUMP_BITS: u32 = 8;

pub const SCRATCHPAD_L1: u32 = RANDOMX_SCRATCHPAD_L1 as u32 / 8;
pub const SCRATCHPAD_L2: u32 = RANDOMX_SCRATCHPAD_L2 as u32 / 8;
pub const SCRATCHPAD_L3: u32 = RANDOMX_SCRATCHPAD_L3 as u32 / 8;
pub const SCRATCHPAD_L1_MASK: u32 = (SCRATCHPAD_L1 - 1) * 8;
pub const SCRATCHPAD_L2_MASK: u32 = (SCRATCHPAD_L2 - 1) * 8;
pub const SCRATCHPAD_L3_MASK: u32 = (SCRATCHPAD_L3 - 1) * 8;
pub const SCRATCHPAD_L3_MASK64: i32 = ((SCRATCHPAD_L3 / 8 - 1) * 64) as i32;
pub const STORE_L3_CONDITION: i32 = 14;
pub const CONDITION_OFFSET: i32 = RANDOMX_JUMP_OFFSET;
pub const CONDITION_MASK:u32  = (1 << RANDOMX_JUMP_BITS) - 1;
pub const CACHE_LINE_ALIGN_MASK: u32 = 0xffffffc0;
