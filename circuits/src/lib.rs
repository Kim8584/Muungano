use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::halo2curves::ff::Field;
use halo2_base::poseidon::hasher::spec::OptimizedPoseidonSpec;
use halo2_base::poseidon::hasher::PoseidonHasher;
use halo2_base::gates::flex_gate::threads::SinglePhaseCoreManager;
use halo2_base::gates::{GateInstructions, RangeChip, RangeInstructions};
use halo2_base::utils::testing::base_test;
use halo2_base::AssignedValue;

pub const POSEIDON_T: usize = 3;
pub const POSEIDON_RATE: usize = 2;
pub const POSEIDON_R_F: usize = 8;
pub const POSEIDON_R_P: usize = 57;

pub const DEFAULT_K: u32 = 14;
pub const DEFAULT_LOOKUP_BITS: usize = 13;

pub fn poseidon_spec() -> OptimizedPoseidonSpec<Fr, POSEIDON_T, POSEIDON_RATE> {
    OptimizedPoseidonSpec::<Fr, POSEIDON_T, POSEIDON_RATE>::new::<
        POSEIDON_R_F,
        POSEIDON_R_P,
        0,
    >()
}

#[derive(Clone, Debug)]
pub struct MuunganoPublicInputs {
    pub public_root_1: Fr,
    pub public_root_2: Fr,
    pub public_threshold: Fr,
    pub public_quote_id: Fr,
}

#[derive(Clone, Debug)]
pub struct MuunganoPrivateWitness {
    pub private_score_1: Fr,
    pub private_salt_1: Fr,
    pub private_path_1: [Fr; 4],
    pub private_index_1: Fr,
    
    pub private_score_2: Fr,
    pub private_salt_2: Fr,
    pub private_path_2: [Fr; 4],
    pub private_index_2: Fr,

    pub private_identity: Fr,
}

pub fn hash_fix_len(values: &[Fr]) -> Fr {
    base_test().k(12).lookup_bits(11).run(|ctx, range| {
        let mut hasher = PoseidonHasher::<Fr, POSEIDON_T, POSEIDON_RATE>::new(poseidon_spec());
        hasher.initialize_consts(ctx, range.gate());
        let assigned: Vec<_> = values.iter().map(|value| ctx.load_witness(*value)).collect();
        *hasher
            .hash_fix_len_array(ctx, range.gate(), &assigned)
            .value()
    })
}

pub fn native_leaf_hash(identity: Fr, score: Fr, salt: Fr) -> Fr {
    hash_fix_len(&[identity, score, salt])
}

pub fn native_node_hash(left: Fr, right: Fr) -> Fr {
    hash_fix_len(&[left, right])
}

pub fn native_compute_root(leaf: Fr, path: &[Fr; 4], index: usize) -> Fr {
    let mut current = leaf;
    for i in 0..4 {
        let bit = (index >> i) & 1;
        let (left, right) = if bit == 0 {
            (current, path[i])
        } else {
            (path[i], current)
        };
        current = native_node_hash(left, right);
    }
    current
}

pub fn assign_muungano_circuit(
    pool: &mut SinglePhaseCoreManager<Fr>,
    range: &RangeChip<Fr>,
    public: MuunganoPublicInputs,
    private: MuunganoPrivateWitness,
    assigned_instances: &mut Vec<AssignedValue<Fr>>,
) {
    let ctx = pool.main();
    let gate = range.gate();

    // 1. Initialize Poseidon Hasher
    let mut hasher = PoseidonHasher::<Fr, POSEIDON_T, POSEIDON_RATE>::new(poseidon_spec());
    hasher.initialize_consts(ctx, gate);

    // 2. Load private witnesses
    let score_1 = ctx.load_witness(private.private_score_1);
    let salt_1 = ctx.load_witness(private.private_salt_1);
    let index_1 = ctx.load_witness(private.private_index_1);

    let score_2 = ctx.load_witness(private.private_score_2);
    let salt_2 = ctx.load_witness(private.private_salt_2);
    let index_2 = ctx.load_witness(private.private_index_2);

    let identity = ctx.load_witness(private.private_identity);

    // 3. Decompose indices into direction bits
    let direction_bits_1 = range.gate.num_to_bits(ctx, index_1, 4);
    let direction_bits_2 = range.gate.num_to_bits(ctx, index_2, 4);

    // 4. Verification for Tree 1 (e.g. Mobile Money)
    let leaf_hash_1 = hasher.hash_fix_len_array(ctx, gate, &[identity, score_1, salt_1]);
    let mut current_1 = leaf_hash_1;
    for i in 0..4 {
        let sibling = ctx.load_witness(private.private_path_1[i]);
        let bit = direction_bits_1[i];
        let left = gate.select(ctx, sibling, current_1, bit);
        let right = gate.select(ctx, current_1, sibling, bit);
        current_1 = hasher.hash_fix_len_array(ctx, gate, &[left, right]);
    }
    let public_root_1_assigned = ctx.load_constant(public.public_root_1);
    let root_1_diff = gate.sub(ctx, current_1, public_root_1_assigned);
    gate.assert_is_const(ctx, &root_1_diff, &Fr::ZERO);

    // 5. Verification for Tree 2 (e.g. Bank)
    let leaf_hash_2 = hasher.hash_fix_len_array(ctx, gate, &[identity, score_2, salt_2]);
    let mut current_2 = leaf_hash_2;
    for i in 0..4 {
        let sibling = ctx.load_witness(private.private_path_2[i]);
        let bit = direction_bits_2[i];
        let left = gate.select(ctx, sibling, current_2, bit);
        let right = gate.select(ctx, current_2, sibling, bit);
        current_2 = hasher.hash_fix_len_array(ctx, gate, &[left, right]);
    }
    let public_root_2_assigned = ctx.load_constant(public.public_root_2);
    let root_2_diff = gate.sub(ctx, current_2, public_root_2_assigned);
    gate.assert_is_const(ctx, &root_2_diff, &Fr::ZERO);

    // 6. Score Aggregation and UltraPLONK Range Check: score_1 + score_2 >= threshold
    range.range_check(ctx, score_1, 32);
    range.range_check(ctx, score_2, 32);
    let score_total = gate.add(ctx, score_1, score_2);

    let public_threshold_assigned = ctx.load_constant(public.public_threshold);
    range.range_check(ctx, public_threshold_assigned, 32);

    let one = ctx.load_constant(Fr::ONE);
    let score_total_plus_1 = gate.add(ctx, score_total, one);
    // score_total + 1 can be up to 33 bits, so comparison uses 34 bits to avoid overflow
    range.check_less_than(ctx, public_threshold_assigned, score_total_plus_1, 34);

    // 7. Context & Replay Protection: Quote ID/Lock H
    let public_quote_id_assigned = ctx.load_constant(public.public_quote_id);

    // 8. Expose inputs publicly as instances
    assigned_instances.push(public_root_1_assigned);
    assigned_instances.push(public_root_2_assigned);
    assigned_instances.push(public_threshold_assigned);
    assigned_instances.push(public_quote_id_assigned);
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_base::gates::circuit::builder::RangeCircuitBuilder;
    use halo2_base::halo2_proofs::dev::MockProver;

    #[test]
    fn test_muungano_success() {
        let identity = Fr::from(12345u64);
        
        // Mobile Money Ledger parameters
        let score_1 = Fr::from(400u64);
        let salt_1 = Fr::from(9999u64);
        let leaf_1 = native_leaf_hash(identity, score_1, salt_1);
        let path_1 = [
            Fr::from(11u64),
            Fr::from(22u64),
            Fr::from(33u64),
            Fr::from(44u64),
        ];
        let index_1 = 5;
        let root_1 = native_compute_root(leaf_1, &path_1, index_1);

        // Bank Ledger parameters
        let score_2 = Fr::from(350u64); // total = 400 + 350 = 750 >= 700 threshold
        let salt_2 = Fr::from(8888u64);
        let leaf_2 = native_leaf_hash(identity, score_2, salt_2);
        let path_2 = [
            Fr::from(55u64),
            Fr::from(66u64),
            Fr::from(77u64),
            Fr::from(88u64),
        ];
        let index_2 = 10;
        let root_2 = native_compute_root(leaf_2, &path_2, index_2);

        let threshold = Fr::from(700u64);
        let quote_id = Fr::from(987654321u64);

        let public = MuunganoPublicInputs {
            public_root_1: root_1,
            public_root_2: root_2,
            public_threshold: threshold,
            public_quote_id: quote_id,
        };

        let private = MuunganoPrivateWitness {
            private_score_1: score_1,
            private_salt_1: salt_1,
            private_path_1: path_1,
            private_index_1: Fr::from(index_1 as u64),
            
            private_score_2: score_2,
            private_salt_2: salt_2,
            private_path_2: path_2,
            private_index_2: Fr::from(index_2 as u64),

            private_identity: identity,
        };

        let mut builder = RangeCircuitBuilder::default()
            .use_k(DEFAULT_K as usize)
            .use_lookup_bits(DEFAULT_LOOKUP_BITS);
        builder.set_instance_columns(1);

        let range = RangeChip::new(DEFAULT_LOOKUP_BITS, builder.lookup_manager().clone());
        let mut assigned_instances = Vec::new();
        assign_muungano_circuit(builder.pool(0), &range, public, private, &mut assigned_instances);
        builder.assigned_instances[0] = assigned_instances;

        builder.calculate_params(Some(9));

        let public_inputs = vec![vec![root_1, root_2, threshold, quote_id]];

        let prover = MockProver::run(DEFAULT_K, &builder, public_inputs).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_muungano_fail_low_score() {
        let identity = Fr::from(12345u64);
        
        let score_1 = Fr::from(300u64);
        let salt_1 = Fr::from(9999u64);
        let leaf_1 = native_leaf_hash(identity, score_1, salt_1);
        let path_1 = [
            Fr::from(11u64),
            Fr::from(22u64),
            Fr::from(33u64),
            Fr::from(44u64),
        ];
        let index_1 = 5;
        let root_1 = native_compute_root(leaf_1, &path_1, index_1);

        let score_2 = Fr::from(350u64); // total = 300 + 350 = 650 < 700 threshold
        let salt_2 = Fr::from(8888u64);
        let leaf_2 = native_leaf_hash(identity, score_2, salt_2);
        let path_2 = [
            Fr::from(55u64),
            Fr::from(66u64),
            Fr::from(77u64),
            Fr::from(88u64),
        ];
        let index_2 = 10;
        let root_2 = native_compute_root(leaf_2, &path_2, index_2);

        let threshold = Fr::from(700u64);
        let quote_id = Fr::from(987654321u64);

        let public = MuunganoPublicInputs {
            public_root_1: root_1,
            public_root_2: root_2,
            public_threshold: threshold,
            public_quote_id: quote_id,
        };

        let private = MuunganoPrivateWitness {
            private_score_1: score_1,
            private_salt_1: salt_1,
            private_path_1: path_1,
            private_index_1: Fr::from(index_1 as u64),
            
            private_score_2: score_2,
            private_salt_2: salt_2,
            private_path_2: path_2,
            private_index_2: Fr::from(index_2 as u64),

            private_identity: identity,
        };

        let mut builder = RangeCircuitBuilder::default()
            .use_k(DEFAULT_K as usize)
            .use_lookup_bits(DEFAULT_LOOKUP_BITS);
        builder.set_instance_columns(1);

        let range = RangeChip::new(DEFAULT_LOOKUP_BITS, builder.lookup_manager().clone());
        let mut assigned_instances = Vec::new();
        assign_muungano_circuit(builder.pool(0), &range, public, private, &mut assigned_instances);
        builder.assigned_instances[0] = assigned_instances;

        builder.calculate_params(Some(9));

        let public_inputs = vec![vec![root_1, root_2, threshold, quote_id]];
        let prover = MockProver::run(DEFAULT_K, &builder, public_inputs).unwrap();
        assert!(prover.verify().is_err());
    }
}
