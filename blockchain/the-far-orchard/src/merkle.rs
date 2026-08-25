//! Off-circuit Merkle tree and serialization helpers.

use group::ff::PrimeField;
use group::{Curve, Group};
use halo2_gadgets::sinsemilla::primitives::HashDomain;
use halo2_gadgets::sinsemilla::HashDomains;
use pasta_curves::{arithmetic::CurveAffine, pallas};

use crate::circuit::{FarOrchardHashDomains, K};

/// Sinsemilla hash for Merkle tree (off-circuit).
///
/// Mirrors the on-circuit `MerkleChip::hash_layer`: the message is
/// `l (K bits) || left (255 bits) || right (255 bits)`, hashed under the
/// `FarOrchardHashDomains` Q constant.
pub fn merkle_crh(layer: usize, left: pallas::Base, right: pallas::Base) -> pallas::Base {
    // Q is a trait method taking &self; call it on an instance.
    let q = FarOrchardHashDomains.Q();

    // l = layer index, as K bits little-endian.
    let l_bits: [bool; K] = {
        let mut bits = [false; K];
        let l_val = layer as u64;
        for i in 0..K {
            bits[i] = (l_val >> i) & 1 == 1;
        }
        bits
    };

    let left_bits = field_to_bits(&left, 255);
    let right_bits = field_to_bits(&right, 255);

    // Build message: l || left || right (as an iterator of bools).
    let message = l_bits
        .iter()
        .chain(left_bits.iter())
        .chain(right_bits.iter())
        .copied();

    let domain = HashDomain::from_Q(pallas::Point::from(q));
    let point = domain.hash_to_point(message).unwrap();
    *point.to_affine().coordinates().unwrap().x()
}

fn field_to_bits(val: &pallas::Base, num_bits: usize) -> Vec<bool> {
    let repr = val.to_repr();
    (0..num_bits)
        .map(|i| ((repr[i / 8] >> (i % 8)) & 1) == 1)
        .collect()
}

/// Build a Merkle tree from leaf values.
pub struct MerkleTree {
    pub depth: usize,
    pub leaves: Vec<pallas::Base>,
    pub nodes: Vec<Vec<pallas::Base>>, // nodes[layer][index], layer 0 = root
    pub root: pallas::Base,
}

impl MerkleTree {
    pub fn new(leaves: Vec<pallas::Base>, depth: usize) -> Self {
        let n = 1usize << depth;
        let mut padded = leaves.clone();
        padded.resize(n, pallas::Base::zero());

        let mut nodes = vec![vec![]; depth + 1];
        nodes[depth] = padded.clone();

        // Build from bottom (leaves) to top (root).
        for l in 0..depth {
            let layer = depth - 1 - l;
            let prev = &nodes[layer + 1];
            let mut cur = Vec::with_capacity(prev.len() / 2);
            for i in (0..prev.len()).step_by(2) {
                cur.push(merkle_crh(l, prev[i], prev[i + 1]));
            }
            nodes[layer] = cur;
        }

        let root = nodes[0][0];
        Self {
            depth,
            leaves: padded,
            nodes,
            root,
        }
    }

    /// Get Merkle path (siblings) for leaf at position `pos`.
    /// Returns siblings ordered from leaf to root.
    pub fn path(&self, pos: usize) -> Vec<pallas::Base> {
        let mut siblings = Vec::with_capacity(self.depth);
        let mut idx = pos;
        for layer in (0..self.depth).rev() {
            let sibling = if idx % 2 == 0 {
                self.nodes[layer + 1][idx + 1]
            } else {
                self.nodes[layer + 1][idx - 1]
            };
            siblings.push(sibling);
            idx /= 2;
        }
        siblings
    }
}

/// Derive public key from secret key (off-circuit).
pub fn derive_pk(sk: pallas::Base) -> pallas::Affine {
    let g = pallas::Point::generator();
    let scalar = pallas::Scalar::from_repr(sk.to_repr()).unwrap();
    (g * scalar).to_affine()
}

/// Derive nullifier from secret key (off-circuit).
pub fn derive_nullifier(sk: pallas::Base) -> pallas::Base {
    let g = pallas::Point::generator();
    let scalar = pallas::Scalar::from_repr(sk.to_repr()).unwrap();
    let point = g * scalar;
    *point.to_affine().coordinates().unwrap().x()
}

/// Serialize a pallas::Base to hex.
pub fn field_to_hex(val: &pallas::Base) -> String {
    hex::encode(val.to_repr())
}

/// Deserialize a pallas::Base from hex.
pub fn hex_to_field(hex_str: &str) -> Result<pallas::Base, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("hex decode: {}", e))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "expected 32 bytes".to_string())?;
    Option::from(pallas::Base::from_repr(arr)).ok_or_else(|| "invalid field element".to_string())
}

/// Serialize proof + public inputs to a compact hex format.
pub fn serialize_proof(
    proof: &[u8],
    merkle_root: &pallas::Base,
    nullifier_x: &pallas::Base,
) -> String {
    let mut buf = Vec::new();
    buf.extend_from_slice(&merkle_root.to_repr());
    buf.extend_from_slice(&nullifier_x.to_repr());
    buf.extend_from_slice(&(proof.len() as u32).to_le_bytes());
    buf.extend_from_slice(proof);
    hex::encode(&buf)
}

/// Deserialize proof + public inputs from hex.
pub fn deserialize_proof(hex_str: &str) -> Result<(Vec<u8>, pallas::Base, pallas::Base), String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("hex decode: {}", e))?;
    if bytes.len() < 68 {
        return Err("too short".into());
    }
    let root_arr: [u8; 32] = bytes[0..32].try_into().unwrap();
    let nf_arr: [u8; 32] = bytes[32..64].try_into().unwrap();
    let proof_len = u32::from_le_bytes(bytes[64..68].try_into().unwrap()) as usize;
    if bytes.len() < 68 + proof_len {
        return Err("truncated proof".into());
    }
    let proof = bytes[68..68 + proof_len].to_vec();
    let root = Option::from(pallas::Base::from_repr(root_arr)).ok_or("invalid root")?;
    let nf = Option::from(pallas::Base::from_repr(nf_arr)).ok_or("invalid nullifier")?;
    Ok((proof, root, nf))
}
