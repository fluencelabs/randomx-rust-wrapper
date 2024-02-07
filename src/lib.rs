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

pub mod bindings;
pub mod cache;
pub mod dataset;
pub mod errors;
pub mod flags;
pub mod result_hash;
pub mod vm;

pub type RResult<T> = Result<T, errors::RandomXError>;

macro_rules! try_alloc {
    ($alloc:expr, $error:expr) => {{
        let result = unsafe { $alloc };
        if result.is_null() {
            return Err($error)?;
        }

        result
    }};
}

pub(crate) use try_alloc;