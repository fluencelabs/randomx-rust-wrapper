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

use hex::FromHex;
use serde::Deserialize;
use serde::Serialize;

pub const RANDOMX_RESULT_SIZE: usize = 32;

type ResultHashInner = [u8; RANDOMX_RESULT_SIZE];

#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
#[repr(transparent)]
pub struct ResultHash(ResultHashInner);

impl ResultHash {
    pub fn from_slice(hash: ResultHashInner) -> Self {
        Self(hash)
    }

    pub fn into_slice(self) -> ResultHashInner {
        self.0
    }

    pub(crate) fn empty() -> Self {
        Self([0u8; RANDOMX_RESULT_SIZE])
    }

    pub(crate) fn as_raw_mut(&mut self) -> *mut std::ffi::c_void {
        self.0.as_mut_ptr() as *mut std::ffi::c_void
    }
}

impl AsRef<ResultHashInner> for ResultHash {
    fn as_ref(&self) -> &ResultHashInner {
        &self.0
    }
}

impl FromHex for ResultHash {
    type Error = <[u8; 32] as FromHex>::Error;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        ResultHashInner::from_hex(hex).map(Self)
    }
}
