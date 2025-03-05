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

#![warn(rust_2018_idioms)]
#![warn(rust_2021_compatibility)]
#![deny(
    dead_code,
    nonstandard_style,
    unused_imports,
    unused_mut,
    unused_variables,
    unused_unsafe,
    unreachable_patterns
)]

#[cfg(test)]
mod tests;
mod stark_primitives;

pub mod alu;
pub mod bytecode_machine;
pub mod randomx_circuit;
pub mod constants;
pub mod instruction;
pub mod intrinsics;
pub mod ironlight;
pub mod program;
pub mod registers;
pub mod utils;

pub type RResult<T> = Result<T, errors::RandomXError>;

pub use ccp_randomx::cache::Cache;
use ccp_randomx::errors;
pub use errors::RandomXError;
pub use errors::VmCreationError;
pub use ccp_randomx::flags::RandomXFlags;
pub use ccp_randomx::result_hash::ResultHash;
pub use ironlight::IronLightVM;

