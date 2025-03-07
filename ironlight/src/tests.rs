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

use tracing_forest::util::LevelFilter;
use tracing_forest::ForestLayer;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Registry;

use crate::ironlight::aes_1rx4_hash;
use crate::ironlight::HashWithGroth16Proof;
use crate::Cache;
use crate::RandomXFlags;
use crate::IronLightVM;
use crate::ResultHash;

fn run_ironlight_randomx(global_nonce: &[u8], local_nonce: &[u8], flags: RandomXFlags) -> ResultHash {
    let cache = Cache::new(&global_nonce, flags).unwrap();
    let mut vm = IronLightVM::new(cache, flags).unwrap();
    vm.hash(&local_nonce)
}

fn run_prove_light(global_nonce: &[u8], local_nonce: &[u8], flags: RandomXFlags) -> HashWithGroth16Proof {
    let cache = Cache::new(&global_nonce, flags).unwrap();
    let mut vm = IronLightVM::new(cache, flags).unwrap();
    vm.prove_light(&local_nonce)
}

#[test]
fn ironlight_mode_works() {
    let global_nonce = vec![1, 2, 3, 4, 5, 6, 7];
    let local_nonce = vec![2, 3, 4, 5, 6, 7];
    let flags = RandomXFlags::DEFAULT | RandomXFlags::FLAG_IRONLIGHT;
    println!("Flags: {:?}", flags);

    let actual_result = run_ironlight_randomx(&global_nonce, &local_nonce, flags);
    let hex_string: String = actual_result
        .into_slice()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    println!("Result: {}", hex_string);
    let expected_result = ResultHash::from_slice([
        133, 95, 150, 177, 51, 99, 179, 126, 55, 33, 61, 139, 120, 240, 233, 99, 78, 17, 195, 171,
        72, 165, 63, 121, 251, 194, 167, 44, 123, 31, 135, 219,
    ]);
    let hex_string: String = expected_result
        .into_slice()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    println!("Expected result: {}", hex_string);


    assert_eq!(actual_result, expected_result);
}


#[test]
fn prove_light_works() {
    use tracing_subscriber::prelude::__tracing_subscriber_SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let global_nonce = vec![1, 2, 3, 4, 5, 6, 7];
    let local_nonce = vec![2, 3, 4, 5, 6, 7];
    let flags = RandomXFlags::DEFAULT | RandomXFlags::FLAG_IRONLIGHT;

    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    Registry::default()
        .with(env_filter)
        .with(ForestLayer::default())
        .init();

    let HashWithGroth16Proof {hash, proof} = run_prove_light(&global_nonce, &local_nonce, flags);
    let hex_string: String = hash
        .into_slice()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    println!("Groth16 proof: {}", hex::encode(proof));
    println!("Result: {}", hex_string);
    let expected_result = ResultHash::from_slice([
        133, 95, 150, 177, 51, 99, 179, 126, 55, 33, 61, 139, 120, 240, 233, 99, 78, 17, 195, 171,
        72, 165, 63, 121, 251, 194, 167, 44, 123, 31, 135, 219,
    ]);
    let hex_string: String = expected_result
        .into_slice()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    println!("Expected result: {}", hex_string);

    // assert_eq!(actual_result, expected_result);
}

#[test]
fn tshoot_aes() {
    println!("Input:");

    let input = [42u8; 512];
    let mut hash = [0u8; 512];

    println!("Input: {:?}", input);
    aes_1rx4_hash(&input, input.len(), &mut hash);
    let hex_string: String = hash
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    println!("Result: {}", hex_string);
}