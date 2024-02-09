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

use crate::bindings::dataset::*;
use crate::cache::Cache;
use crate::errors::RandomXError::DatasetAllocationError;
use crate::flags::RandomXFlags;
use crate::try_alloc;
use crate::RResult;

pub struct Dataset {
    dataset: *mut randomx_dataset,
}

impl Dataset {
    /// Create a new database with provided global nonce and flags.
    /// Only RANDOMX_FLAG_LARGE_PAGES is supported (can be set or unset),
    /// it forces memory allocation in large pages.
    pub fn new(global_nonce: &[u8], flags: RandomXFlags) -> RResult<Self> {
        let cache = Cache::new(global_nonce, flags)?;
        Self::from_cache(&cache, flags.contains(RandomXFlags::LARGE_PAGES))
    }

    /// Creates a new database with the provided cache,
    /// large_pages_enabled forces it to allocate memory in large pages.
    pub fn from_cache(cache: &Cache, large_pages_enabled: bool) -> RResult<Self> {
        let flags = if large_pages_enabled {
            RandomXFlags::LARGE_PAGES
        } else {
            RandomXFlags::default()
        };

        let dataset =
            try_alloc! { randomx_alloc_dataset(flags.bits()), DatasetAllocationError { flags } };

        let mut dataset = Self { dataset };
        dataset.reinit(cache);
        Ok(dataset)
    }

    /// Initializes dataset with the provided cache.
    pub(crate) fn reinit(&mut self, cache: &Cache) {
        let elements_count = unsafe { randomx_dataset_item_count() };
        unsafe { randomx_init_dataset(self.dataset, cache.raw(), 0, elements_count) };
    }

    pub(crate) fn raw(&self) -> *mut randomx_dataset {
        self.dataset
    }
}

impl Drop for Dataset {
    fn drop(&mut self) {
        unsafe { randomx_release_dataset(self.dataset) }
    }
}
