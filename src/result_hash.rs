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

pub const RANDOMX_RESULT_SIZE: usize = 32;

type ResultHashSlice = [u8; RANDOMX_RESULT_SIZE];

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ResultHash {
    hash: ResultHashSlice,
}

impl ResultHash {
    pub fn from_slice(hash: ResultHashSlice) -> Self {
        Self { hash }
    }

    pub fn into_slice(self) -> ResultHashSlice {
        self.hash
    }

    pub(crate) fn empty() -> Self {
        Self {
            hash: [0u8; RANDOMX_RESULT_SIZE],
        }
    }

    pub(crate) fn as_raw_mut(&mut self) -> *mut std::ffi::c_void {
        self.hash.as_mut_ptr() as *mut std::ffi::c_void
    }
}

impl AsRef<ResultHashSlice> for ResultHash {
    fn as_ref(&self) -> &ResultHashSlice {
        &self.hash
    }
}
