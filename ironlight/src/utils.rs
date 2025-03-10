
use hashbrown::HashMap;
use p3_baby_bear::BabyBear;
use p3_field::{extension::BinomialExtensionField, AbstractField, ExtensionField};
use p3_uni_stark::OpenedValues;
use sp1_prover::SP1CoreProofData;
use sp1_stark::{baby_bear_poseidon2::BabyBearPoseidon2, AirOpenedValues, ChipOpenedValues, ShardCommitment, ShardOpenedValues, ShardProof, StarkVerifyingKey};

use crate::stark_primitives::{P3Proof, BIN_OP_ROW_SIZE};


pub(crate) fn _dummy_vk() -> StarkVerifyingKey<BabyBearPoseidon2> {
  let chips = vec![
      ("Byte".to_string(), 16),
      ("MemoryProgram".to_string(), 14),
      ("Program".to_string(), 14),
      ("AddSub".to_string(), 4),
      ("CPU".to_string(), 4),
      ("MemoryLocal".to_string(), 4),
  ];

  let chip_ordering = chips
      .iter()
      .enumerate()
      .map(|(i, (name, _))| (name.to_owned(), i))
      .collect::<HashMap<_, _>>();

  StarkVerifyingKey {
      commit: [BabyBear::zero(); sp1_stark::DIGEST_SIZE].into(),
      pc_start: BabyBear::zero(),
      chip_information: vec![],
      chip_ordering: chip_ordering,
  }
}

fn convert_opened_values_<F: p3_field::Field, EF: ExtensionField<F>>(
  p3_opended_values: &OpenedValues<EF>,
  log_degree: usize,
) -> ChipOpenedValues<EF> {
  // dummy values for pre and perm
  // let preprocessed_width = chip.preprocessed_width();
  // pre, main, perm must be unused
  let preprocessed = AirOpenedValues {
      local: vec![EF::zero(); BIN_OP_ROW_SIZE],
      next: vec![EF::zero(); BIN_OP_ROW_SIZE],
  };
  let permutation = AirOpenedValues {
      local: vec![EF::zero(); BIN_OP_ROW_SIZE * EF::D],
      next: vec![EF::zero(); BIN_OP_ROW_SIZE * EF::D],
  };

  let OpenedValues {
      trace_local,
      trace_next,
      quotient_chunks,
  } = p3_opended_values;
  // Put everything into main b/c main opnening values are handed over to
  // pcs::verify
  let main = AirOpenedValues {
      local: trace_local.clone(),
      next: trace_next.clone(),
  };

  let quotient = quotient_chunks.clone();

  ChipOpenedValues {
      preprocessed,
      main,
      permutation,
      quotient,
      global_cumulative_sum: EF::zero(),
      local_cumulative_sum: EF::zero(),
      log_degree,
  }
}

pub(crate) fn p3_proof_to_shardproof(
  p3_proof: P3Proof,
) -> ShardProof<sp1_stark::baby_bear_poseidon2::BabyBearPoseidon2> {
  let P3Proof {
      commitments,
      opened_values,
      opening_proof,
      degree_bits,
  } = p3_proof;

  let chip_opened_values = convert_opened_values_::<BabyBear, BinomialExtensionField<BabyBear, 4>>(
      &opened_values,
      degree_bits,
  );
  let shard_proof = ShardProof {
      commitment: ShardCommitment {
          global_main_commit: [BabyBear::zero(); sp1_stark::DIGEST_SIZE].into(),
          local_main_commit: commitments.trace,
          // local_main_commit: commitments.trace,
          permutation_commit: [BabyBear::zero(); sp1_stark::DIGEST_SIZE].into(),
          quotient_commit: commitments.quotient_chunks,
      },
      opened_values: ShardOpenedValues {
          chips: vec![chip_opened_values],
      },
      opening_proof,
      chip_ordering: HashMap::new(),
      public_values: vec![],
  };

  shard_proof
}

pub(crate) fn _get_sp1_core_proofdata(
  p3_proof: P3Proof,
) -> SP1CoreProofData {
  let shard_proof = p3_proof_to_shardproof(p3_proof);
  let shard_proofs = vec![shard_proof];
  SP1CoreProofData(shard_proofs)
}