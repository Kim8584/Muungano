//! Off-circuit helpers for Mandazi phase-1 witness generation and buyer-side checks.

use crate::mandazi::poseidon_config::{POSEIDON_RATE, POSEIDON_T};
use halo2_base::gates::RangeInstructions;
use halo2_base::halo2_proofs::halo2curves::bn256::{Fq as GrumpkinScalar, Fr};
use halo2_base::halo2_proofs::halo2curves::ff::Field;
use halo2_base::halo2_proofs::halo2curves::grumpkin::G1Affine;
use halo2_base::halo2_proofs::halo2curves::group::Curve;
use halo2_base::poseidon::hasher::PoseidonHasher;
use halo2_base::utils::{biguint_to_fe, fe_to_biguint, testing::base_test};
use rand_core::RngCore;

pub fn grumpkin_scalar_to_fr(scalar: GrumpkinScalar) -> Fr {
    biguint_to_fe(&fe_to_biguint(&scalar))
}

pub fn encrypt_field(message: Fr, keystream: Fr) -> Fr {
    message + keystream
}

pub fn decrypt_field(ciphertext: Fr, keystream: Fr) -> Fr {
    ciphertext - keystream
}

/// Native Poseidon fix-length hash matching in-circuit `hash_fix_len_array`.
pub fn hash_fix_len(values: &[Fr]) -> Fr {
    base_test().k(12).lookup_bits(11).run(|ctx, range| {
        let mut hasher = PoseidonHasher::<Fr, POSEIDON_T, POSEIDON_RATE>::new(
            crate::mandazi::poseidon_config::poseidon_spec(),
        );
        hasher.initialize_consts(ctx, range.gate());
        let assigned: Vec<_> = values.iter().map(|value| ctx.load_witness(*value)).collect();
        *hasher
            .hash_fix_len_array(ctx, range.gate(), &assigned)
            .value()
    })
}

pub fn leaf_hash(message: Fr) -> Fr {
    hash_fix_len(&[message])
}

pub fn keystream_from_shared_point(shared: G1Affine) -> Fr {
    hash_fix_len(&[shared.x, shared.y])
}

/// Seller-side session material for phase 1.
#[derive(Clone, Debug)]
pub struct Phase1SellerMaterial {
    pub ephemeral_scalar: GrumpkinScalar,
    pub ephemeral_point: G1Affine,
    pub shared_secret: G1Affine,
    pub message: Fr,
    pub leaf_hash: Fr,
    pub keystream: Fr,
    pub ciphertext: Fr,
}

pub fn generate_phase1_seller_material(
    buyer_pk: G1Affine,
    message: Fr,
    rng: &mut impl RngCore,
) -> Phase1SellerMaterial {
    let ephemeral_scalar = GrumpkinScalar::random(rng);
    let ephemeral_point = (G1Affine::generator() * ephemeral_scalar).to_affine();
    let shared_secret = (buyer_pk * ephemeral_scalar).to_affine();
    let leaf_hash = leaf_hash(message);
    let keystream = keystream_from_shared_point(shared_secret);
    let ciphertext = encrypt_field(message, keystream);

    Phase1SellerMaterial {
        ephemeral_scalar,
        ephemeral_point,
        shared_secret,
        message,
        leaf_hash,
        keystream,
        ciphertext,
    }
}

/// Buyer-side decryption check: `sk_buyer * C == r * PK`.
pub fn buyer_derives_shared_secret(
    buyer_sk: GrumpkinScalar,
    ephemeral_point: G1Affine,
) -> G1Affine {
    (ephemeral_point * buyer_sk).to_affine()
}
