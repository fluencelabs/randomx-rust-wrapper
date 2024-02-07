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

use crate::bindings::cache::*;
use crate::errors::RandomXError::CacheAllocationFailed;
use crate::flags::RandomXFlags;
use crate::try_alloc;
use crate::RResult;

pub struct Cache {
    cache: *mut randomx_cache,
}

impl Cache {
    /// Creates RandomX cache with the provided global_nonce.
    pub fn new(flags: RandomXFlags, global_nonce: &[u8]) -> RResult<Self> {
        let cache = try_alloc!(
            randomx_alloc_cache(flags.bits()),
            CacheAllocationFailed { flags }
        );

        let mut cache = Cache { cache };
        cache.reinit(global_nonce);
        Ok(cache)
    }

    /// Initializes the cache memory using the provided global nonce value.
    /// Does nothing if called with the same value again.
    pub fn reinit(&mut self, global_nonce: &[u8]) {
        unsafe {
            randomx_init_cache(
                cache,
                global_nonce.as_ptr() as *const std::ffi::c_void,
                global_nonce.len(),
            )
        };
    }

    pub(crate) fn raw(&self) -> *mut randomx_cache {
        self.cache
    }
}

impl Drop for Cache {
    fn drop(&mut self) {
        unsafe { randomx_release_cache(self.cache) }
    }
}
