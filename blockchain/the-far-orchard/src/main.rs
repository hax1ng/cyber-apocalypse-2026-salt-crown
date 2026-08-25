//! FarOrchard validator — for the Merkle vow registry.
//!
//! Modes:
//!   (default)   Read PROOF from stdin, verify, output OK/FAIL
//!   --generate-tree  Generate random Merkle tree, output public data
mod circuit;
mod merkle;

use circuit::{FarOrchardCircuit, MERKLE_DEPTH};
use ff::{Field, PrimeField};
use group::{Curve, Group};
use halo2_proofs::{
    plonk::{keygen_vk, verify_proof, SingleVerifier},
    poly::commitment::Params,
    transcript::{Blake2bRead, Challenge255},
};
use pasta_curves::{arithmetic::CurveAffine, pallas, vesta};
use rand::rngs::OsRng;
use rand::RngCore;
use std::io::Read;

const K_PARAM: u32 = 13;
const NUM_LEAVES: usize = 8;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() > 1 && args[1] == "--generate-tree" {
        generate_tree();
        return;
    }

    // Default: verify proof from stdin
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).unwrap();

    let proof_hex = get_field(&input, "PROOF").expect("missing PROOF");
    let (proof_bytes, merkle_root, nullifier_x) =
        merkle::deserialize_proof(&proof_hex).expect("failed to deserialize proof");

    eprintln!("Building verifying key...");
    let params: Params<vesta::Affine> = Params::new(K_PARAM);
    let empty_circuit = FarOrchardCircuit::default();
    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk failed");

    eprintln!("Verifying proof...");
    let strategy = SingleVerifier::new(&params);
    let public_inputs: [[pallas::Base; 2]; 1] = [[merkle_root, nullifier_x]];
    let instances: [&[&[pallas::Base]]; 1] = [&[&public_inputs[0]]];

    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof_bytes[..]);
    let result = verify_proof(&params, &vk, strategy, &instances, &mut transcript);

    if result.is_ok() {
        eprintln!("Proof verified successfully!");
        eprintln!("  merkle_root: {}", merkle::field_to_hex(&merkle_root));
        eprintln!("  nullifier_x: {}", merkle::field_to_hex(&nullifier_x));
        println!("OK");
        println!("MERKLE_ROOT={}", merkle::field_to_hex(&merkle_root));
        println!("NULLIFIER={}", merkle::field_to_hex(&nullifier_x));
    } else {
        eprintln!("Proof verification failed: {:?}", result);
        println!("FAIL");
    }
}

/// Generate a random Merkle tree and output public data.
///
/// Generates NUM_LEAVES random 256-bit secret keys
fn generate_tree() {
    let mut rng = OsRng;
    let mut leaves = Vec::with_capacity(NUM_LEAVES);

    for _ in 0..NUM_LEAVES {
        // Generate random 256-bit secret key that is a valid field element
        let mut sk_bytes = [0u8; 32];
        loop {
            rng.fill_bytes(&mut sk_bytes);
            let sk_opt: Option<pallas::Base> = pallas::Base::from_repr(sk_bytes).into();
            if let Some(sk) = sk_opt {
                if !sk.is_zero_vartime() {
                    let scalar = pallas::Scalar::from_repr(sk.to_repr()).unwrap();
                    let pk_point = pallas::Point::generator() * scalar;
                    let pk_x = *pk_point.to_affine().coordinates().unwrap().x();
                    leaves.push(pk_x);
                    break;
                }
            }
        }
    }

    // Build Merkle tree
    let tree = merkle::MerkleTree::new(leaves.clone(), MERKLE_DEPTH);

    // Output public data
    println!("MERKLE_ROOT={}", merkle::field_to_hex(&tree.root));
    for (i, &pk_x) in leaves.iter().enumerate() {
        println!("LEAF={},{}", i, merkle::field_to_hex(&pk_x));
    }

    eprintln!(
        "Generated {} leaves, merkle root = {}",
        NUM_LEAVES,
        merkle::field_to_hex(&tree.root)
    );
}

fn get_field(input: &str, name: &str) -> Option<String> {
    for line in input.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix(&format!("{}=", name)) {
            return Some(rest.trim().to_string());
        }
    }
    None
}
