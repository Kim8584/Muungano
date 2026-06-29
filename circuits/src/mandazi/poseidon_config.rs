use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::poseidon::hasher::spec::OptimizedPoseidonSpec;

pub const POSEIDON_T: usize = 3;
pub const POSEIDON_RATE: usize = 2;
pub const POSEIDON_R_F: usize = 8;
pub const POSEIDON_R_P: usize = 57;

pub fn poseidon_spec() -> OptimizedPoseidonSpec<Fr, POSEIDON_T, POSEIDON_RATE> {
    OptimizedPoseidonSpec::<Fr, POSEIDON_T, POSEIDON_RATE>::new::<
        POSEIDON_R_F,
        POSEIDON_R_P,
        0,
    >()
}
