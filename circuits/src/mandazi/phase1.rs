//! Mandazi phase 1: ephemeral commitment, ECDH keystream, and leaf hash binding.
//!
//! Public inputs:
//! - buyer public key `PK`
//! - ephemeral point `C = r * G`
//! - registry leaf digest `H = Poseidon(message)`
//! - ciphertext `Cipher = message + Poseidon(S)` where `S = r * PK`
//!
//! Private witnesses:
//! - ephemeral scalar `r`
//! - message (same cell used for hashing and encryption)
//!
//! Uses Grumpkin as the embedded curve over BN254 `Fr` (Axiom/halo2-ecc native lane).
//! Baby Jubjub uses the same base field and will replace Grumpkin in a follow-up.

use crate::mandazi::native::grumpkin_scalar_to_fr;
use crate::mandazi::poseidon_config::{poseidon_spec, POSEIDON_RATE, POSEIDON_T};
use halo2_base::halo2_proofs::halo2curves::ff::Field;
use halo2_base::gates::flex_gate::threads::SinglePhaseCoreManager;
use halo2_base::gates::{GateInstructions, RangeChip, RangeInstructions};
use halo2_base::halo2_proofs::halo2curves::bn256::{Fq as GrumpkinScalar, Fr};
use halo2_base::halo2_proofs::halo2curves::grumpkin::G1Affine;
use halo2_base::poseidon::hasher::PoseidonHasher;
use halo2_base::{AssignedValue, Context};
use halo2_ecc::ecc::EccChip;
use halo2_ecc::fields::fp::FpChip;

pub const DEFAULT_K: u32 = 20;
pub const DEFAULT_LOOKUP_BITS: usize = 19;
pub const LIMB_BITS: usize = 88;
pub const NUM_LIMBS: usize = 3;
pub const SCALAR_MAX_BITS: usize = 254;
pub const SCALAR_WINDOW_BITS: usize = 4;

type CoordChip<'a> = FpChip<'a, Fr, Fr>;

#[derive(Clone, Debug)]
pub struct Phase1PublicInputs {
    pub buyer_pk: G1Affine,
    pub ephemeral_point: G1Affine,
    pub leaf_hash: Fr,
    pub ciphertext: Fr,
}

#[derive(Clone, Debug)]
pub struct Phase1PrivateWitness {
    pub ephemeral_scalar: GrumpkinScalar,
    pub message: Fr,
}

pub fn assign_phase1_circuit(
    pool: &mut SinglePhaseCoreManager<Fr>,
    range: &RangeChip<Fr>,
    public: Phase1PublicInputs,
    private: Phase1PrivateWitness,
) {
    let ctx = pool.main();
    let gate = range.gate();
    let fp_chip = CoordChip::new(range, LIMB_BITS, NUM_LIMBS);
    let ecc_chip = EccChip::new(&fp_chip);

    let mut hasher = PoseidonHasher::<Fr, POSEIDON_T, POSEIDON_RATE>::new(poseidon_spec());
    hasher.initialize_consts(ctx, gate);

    let r_assigned = assign_ephemeral_scalar(ctx, private.ephemeral_scalar);

    let c_public = ecc_chip.assign_constant_point(ctx, public.ephemeral_point);
    let c_computed = ecc_chip.fixed_base_scalar_mult::<G1Affine>(
        ctx,
        &G1Affine::generator(),
        r_assigned.clone(),
        SCALAR_MAX_BITS,
        SCALAR_WINDOW_BITS,
    );
    ecc_chip.assert_equal(ctx, c_computed, c_public);

    let pk_public = ecc_chip.assign_constant_point(ctx, public.buyer_pk);
    let shared_computed = ecc_chip.scalar_mult::<G1Affine>(
        ctx,
        pk_public,
        r_assigned,
        SCALAR_MAX_BITS,
        SCALAR_WINDOW_BITS,
    );

    let keystream = hasher.hash_fix_len_array(
        ctx,
        gate,
        &[
            *shared_computed.x.native(),
            *shared_computed.y.native(),
        ],
    );

    // Cell binding: one witness cell for the registry leaf used in hash and cipher.
    let message = ctx.load_witness(private.message);
    let computed_leaf_hash = hasher.hash_fix_len_array(ctx, gate, &[message]);
    let public_leaf = ctx.load_constant(public.leaf_hash);
    let leaf_diff = gate.sub(ctx, computed_leaf_hash, public_leaf);
    gate.assert_is_const(ctx, &leaf_diff, &Fr::ZERO);

    let expected_ciphertext = gate.add(ctx, message, keystream);
    let public_cipher = ctx.load_constant(public.ciphertext);
    let cipher_diff = gate.sub(ctx, expected_ciphertext, public_cipher);
    gate.assert_is_const(ctx, &cipher_diff, &Fr::ZERO);
}

fn assign_ephemeral_scalar(ctx: &mut Context<Fr>, scalar: GrumpkinScalar) -> Vec<AssignedValue<Fr>> {
    vec![ctx.load_witness(grumpkin_scalar_to_fr(scalar))]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mandazi::native::{
        buyer_derives_shared_secret, decrypt_field, generate_phase1_seller_material,
        keystream_from_shared_point,
    };
    use halo2_base::gates::circuit::builder::RangeCircuitBuilder;
    use halo2_base::utils::testing::base_test;
    use halo2_base::halo2_proofs::halo2curves::ff::Field;
    use halo2_base::halo2_proofs::halo2curves::group::Curve;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn phase1_native_roundtrip() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let buyer_sk = GrumpkinScalar::random(&mut rng);
        let buyer_pk = (G1Affine::generator() * buyer_sk).to_affine();
        let message = Fr::from(424242u64);

        let material = generate_phase1_seller_material(buyer_pk, message, &mut rng);
        let buyer_shared = buyer_derives_shared_secret(buyer_sk, material.ephemeral_point);
        assert_eq!(buyer_shared, material.shared_secret);

        let buyer_keystream = keystream_from_shared_point(buyer_shared);
        assert_eq!(buyer_keystream, material.keystream);
        assert_eq!(decrypt_field(material.ciphertext, buyer_keystream), message);
    }

    #[test]
    fn phase1_circuit_satisfies_constraints() {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let buyer_sk = GrumpkinScalar::random(&mut rng);
        let buyer_pk = (G1Affine::generator() * buyer_sk).to_affine();
        let message = Fr::from(1337u64);

        let material = generate_phase1_seller_material(buyer_pk, message, &mut rng);
        let public = Phase1PublicInputs {
            buyer_pk,
            ephemeral_point: material.ephemeral_point,
            leaf_hash: material.leaf_hash,
            ciphertext: material.ciphertext,
        };
        let private = Phase1PrivateWitness {
            ephemeral_scalar: material.ephemeral_scalar,
            message: material.message,
        };

        base_test()
            .k(DEFAULT_K)
            .lookup_bits(DEFAULT_LOOKUP_BITS)
            .run_builder(|pool, range| {
                assign_phase1_circuit(pool, range, public, private);
            });
    }

    #[test]
    fn phase1_rejects_wrong_ciphertext() {
        let mut rng = ChaCha20Rng::seed_from_u64(9);
        let buyer_sk = GrumpkinScalar::random(&mut rng);
        let buyer_pk = (G1Affine::generator() * buyer_sk).to_affine();
        let message = Fr::from(99u64);

        let material = generate_phase1_seller_material(buyer_pk, message, &mut rng);
        let public = Phase1PublicInputs {
            buyer_pk,
            ephemeral_point: material.ephemeral_point,
            leaf_hash: material.leaf_hash,
            ciphertext: material.ciphertext + Fr::ONE,
        };
        let private = Phase1PrivateWitness {
            ephemeral_scalar: material.ephemeral_scalar,
            message: material.message,
        };

        let mut builder = RangeCircuitBuilder::default()
            .use_k(DEFAULT_K as usize)
            .use_lookup_bits(DEFAULT_LOOKUP_BITS);
        let range = RangeChip::new(DEFAULT_LOOKUP_BITS, builder.lookup_manager().clone());
        assign_phase1_circuit(builder.pool(0), &range, public, private);
        builder.calculate_params(Some(9));

        use halo2_base::halo2_proofs::dev::MockProver;
        assert!(
            MockProver::run(DEFAULT_K, &builder, vec![])
                .unwrap()
                .verify()
                .is_err()
        );
    }
}
