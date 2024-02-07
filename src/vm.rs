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

use std::marker::PhantomData;

use crate::bindings::vm::*;
use crate::cache::Cache;
use crate::dataset::Dataset;
use crate::errors::VmCreationError;
use crate::flags::RandomXFlags;
use crate::result_hash::ResultHash;
use crate::try_alloc;
use crate::RResult;

pub struct RandomXVM<'state, T: 'state> {
    vm: *mut randomx_vm,
    // too ensure that state outlives VM
    state: PhantomData<&'state T>,
}

impl RandomXVM<'_, Cache> {
    pub fn light(flags: RandomXFlags, cache: &'_ Cache) -> RResult<Self> {
        if !flags.is_light_mode() {
            return Err(VmCreationError::IncorrectFastModeFlag { flags })?;
        }

        let vm = try_alloc! { randomx_create_vm(flags.bits(), cache.raw(), std::ptr::null_mut()), VmCreationError::AllocationFailed {flags} };

        let vm = RandomXVM {
            vm,
            state: PhantomData,
        };
        Ok(vm)
    }

    /// (from RandomX doc) Reinitializes a virtual machine with a new Cache.
    /// This function should be called anytime the Cache is reinitialized with a new key.
    /// Does nothing if called with a Cache containing the same key value as already set.
    pub fn set_new_cache(&mut self, cache: &'_ Cache) {
        unsafe { randomx_vm_set_cache(self.vm, cache.raw()) }
    }
}

impl RandomXVM<'_, Dataset> {
    pub fn fast(flags: RandomXFlags, dataset: &'_ Dataset) -> RResult<Self> {
        if !flags.is_fast_mode() {
            return Err(VmCreationError::IncorrectLightModeFlag { flags })?;
        }

        let vm = try_alloc! { randomx_create_vm(flags.bits(), std::ptr::null_mut(), dataset.raw()), VmCreationError::AllocationFailed {flags} };

        let vm = RandomXVM {
            vm,
            state: PhantomData,
        };

        Ok(vm)
    }

    /// Reinitializes a virtual machine with a new Dataset.
    pub fn set_new_dataset(&mut self, dataset: &'_ Dataset) {
        unsafe { randomx_vm_set_dataset(self.vm, dataset.raw()) }
    }
}

impl<T> Drop for RandomXVM<'_, T> {
    fn drop(&mut self) {
        unsafe { randomx_destroy_vm(self.vm) }
    }
}

impl<T> RandomXVM<'_, T> {
    pub fn calculate_hash(&self, local_nonce: &[u8]) -> ResultHash {
        let mut hash = ResultHash::empty();

        unsafe {
            randomx_calculate_hash(
                self.vm,
                local_nonce.as_ptr() as *const std::ffi::c_void,
                local_nonce.len(),
                hash.as_raw_mut(),
            )
        };

        hash
    }

    pub fn calculuate_hash_first(&self, local_nonce: &[u8]) {
        unsafe {
            randomx_calculate_hash_first(
                self.vm,
                local_nonce.as_ptr() as *const std::ffi::c_void,
                local_nonce.len(),
            )
        };
    }

    pub fn calculuate_hash_next(&self, local_nonce: &[u8]) -> ResultHash {
        let mut hash = ResultHash::empty();

        unsafe {
            randomx_calculate_hash_next(
                self.vm,
                local_nonce.as_ptr() as *const std::ffi::c_void,
                local_nonce.len(),
                hash.as_raw_mut(),
            )
        };

        hash
    }

    pub fn calculuate_hash_last(&self) -> ResultHash {
        let mut hash = ResultHash::empty();

        unsafe { randomx_calculate_hash_last(self.vm, hash.as_raw_mut()) };

        hash
    }
}
