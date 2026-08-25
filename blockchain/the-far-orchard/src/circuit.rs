use group::ff::PrimeField;
use group::{Curve, Group};
use halo2_gadgets::{
    ecc::{
        chip::{
            find_zs_and_us, BaseFieldElem, EccChip, EccConfig, FixedPoint, FullScalar, ShortScalar,
            H, NUM_WINDOWS, NUM_WINDOWS_SHORT,
        },
        FixedPointBaseField, FixedPoints, NonIdentityPoint, ScalarVar,
    },
    sinsemilla::{
        chip::SinsemillaChip,
        merkle::{chip::MerkleChip, MerklePath},
        CommitDomains, HashDomains,
    },
    utilities::lookup_range_check::{LookupRangeCheck, PallasLookupRangeCheckConfig},
};
use halo2_proofs::{
    circuit::{Chip, Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Constraints, Error, Instance},
    poly::Rotation,
};
use lazy_static::lazy_static;
use pasta_curves::pallas;

pub const K: usize = 10;
pub const C: usize = 253;
pub const MERKLE_DEPTH: usize = 8;
pub const MAX_WORDS: usize = C;

// ─── Fixed Bases ───────────────────────────────────────────────────────────

lazy_static! {
    static ref PALLAS_GENERATOR: pallas::Affine = pallas::Point::generator().to_affine();
    static ref ZS_AND_US: Vec<(u64, [pallas::Base; H])> =
        find_zs_and_us(*PALLAS_GENERATOR, NUM_WINDOWS).unwrap();
    static ref ZS_AND_US_SHORT: Vec<(u64, [pallas::Base; H])> =
        find_zs_and_us(*PALLAS_GENERATOR, NUM_WINDOWS_SHORT).unwrap();
}

fn to_u8_arrays(data: &[(u64, [pallas::Base; H])]) -> Vec<[[u8; 32]; H]> {
    data.iter()
        .map(|(_, us)| {
            [
                us[0].to_repr(),
                us[1].to_repr(),
                us[2].to_repr(),
                us[3].to_repr(),
                us[4].to_repr(),
                us[5].to_repr(),
                us[6].to_repr(),
                us[7].to_repr(),
            ]
        })
        .collect()
}

/// Fixed bases for the FarOrchard circuit.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FarOrchardFixedBases;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FarOrchardFullScalar;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FarOrchardBaseField;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FarOrchardShortScalar;

impl FixedPoints<pallas::Affine> for FarOrchardFixedBases {
    type FullScalar = FarOrchardFullScalar;
    type Base = FarOrchardBaseField;
    type ShortScalar = FarOrchardShortScalar;
}

impl FixedPoint<pallas::Affine> for FarOrchardFullScalar {
    type FixedScalarKind = FullScalar;
    fn generator(&self) -> pallas::Affine {
        *PALLAS_GENERATOR
    }
    fn u(&self) -> Vec<[[u8; 32]; H]> {
        to_u8_arrays(&ZS_AND_US)
    }
    fn z(&self) -> Vec<u64> {
        ZS_AND_US.iter().map(|(z, _)| *z).collect()
    }
}

impl FixedPoint<pallas::Affine> for FarOrchardBaseField {
    type FixedScalarKind = BaseFieldElem;
    fn generator(&self) -> pallas::Affine {
        *PALLAS_GENERATOR
    }
    fn u(&self) -> Vec<[[u8; 32]; H]> {
        to_u8_arrays(&ZS_AND_US)
    }
    fn z(&self) -> Vec<u64> {
        ZS_AND_US.iter().map(|(z, _)| *z).collect()
    }
}

impl FixedPoint<pallas::Affine> for FarOrchardShortScalar {
    type FixedScalarKind = ShortScalar;
    fn generator(&self) -> pallas::Affine {
        *PALLAS_GENERATOR
    }
    fn u(&self) -> Vec<[[u8; 32]; H]> {
        to_u8_arrays(&ZS_AND_US_SHORT)
    }
    fn z(&self) -> Vec<u64> {
        ZS_AND_US_SHORT.iter().map(|(z, _)| *z).collect()
    }
}

// ─── Sinsemilla Domains ────────────────────────────────────────────────────

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FarOrchardHashDomains;

impl HashDomains<pallas::Affine> for FarOrchardHashDomains {
    #[allow(non_snake_case)]
    fn Q(&self) -> pallas::Affine {
        *PALLAS_GENERATOR
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FarOrchardCommitDomains;

impl CommitDomains<pallas::Affine, FarOrchardFixedBases, FarOrchardHashDomains>
    for FarOrchardCommitDomains
{
    fn r(&self) -> FarOrchardFullScalar {
        FarOrchardFullScalar
    }
    fn hash_domain(&self) -> FarOrchardHashDomains {
        FarOrchardHashDomains
    }
}

// ─── Circuit Config ────────────────────────────────────────────────────────

type SinsemillaConfig = <SinsemillaChip<
    FarOrchardHashDomains,
    FarOrchardCommitDomains,
    FarOrchardFixedBases,
> as Chip<pallas::Base>>::Config;

type MerkleConfigType =
    <MerkleChip<FarOrchardHashDomains, FarOrchardCommitDomains, FarOrchardFixedBases> as Chip<
        pallas::Base,
    >>::Config;

#[derive(Clone, Debug)]
pub struct FarOrchardConfig {
    pub advices: [Column<Advice>; 10],
    pub primary: Column<Instance>,
    ecc_config: EccConfig<FarOrchardFixedBases>,
    sinsemilla_config: SinsemillaConfig,
    merkle_config: MerkleConfigType,
    q_nullifier: halo2_proofs::plonk::Selector,
}

impl FarOrchardConfig {
    pub fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self {
        let advices = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];

        let primary = meta.instance_column();
        meta.enable_equality(primary);

        for advice in advices.iter() {
            meta.enable_equality(*advice);
        }

        let table_idx = meta.lookup_table_column();
        let lookup = (
            table_idx,
            meta.lookup_table_column(),
            meta.lookup_table_column(),
        );

        let lagrange_coeffs = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];
        meta.enable_constant(lagrange_coeffs[0]);

        let range_check = PallasLookupRangeCheckConfig::configure(meta, advices[9], table_idx);

        let ecc_config =
            EccChip::<FarOrchardFixedBases>::configure(meta, advices, lagrange_coeffs, range_check);

        let sinsemilla_config = SinsemillaChip::configure(
            meta,
            advices[..5].try_into().unwrap(),
            advices[6],
            lagrange_coeffs[1],
            lookup,
            range_check,
            false,
        );
        let merkle_config = MerkleChip::configure(meta, sinsemilla_config.clone());

        let q_nullifier = meta.selector();
        meta.create_gate("nullifier public input", |meta| {
            let q_nullifier = meta.query_selector(q_nullifier);
            let nf_x = meta.query_advice(advices[0], Rotation::cur());
            let expected_nf_x = meta.query_advice(advices[1], Rotation::cur());
            Constraints::with_selector(q_nullifier, [("nf_x check", nf_x - expected_nf_x)])
        });

        FarOrchardConfig {
            advices,
            primary,
            ecc_config,
            sinsemilla_config,
            merkle_config,
            q_nullifier,
        }
    }

    pub fn ecc_chip(&self) -> EccChip<FarOrchardFixedBases> {
        EccChip::construct(
            self.ecc_config.clone(),
            halo2_gadgets::ecc::chip::CircuitVersion::InsecureUnanchoredBase,
        )
    }

    pub fn merkle_chip(
        &self,
    ) -> MerkleChip<FarOrchardHashDomains, FarOrchardCommitDomains, FarOrchardFixedBases> {
        MerkleChip::construct(self.merkle_config.clone())
    }
}

// ─── Circuit ───────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct FarOrchardCircuit {
    pub sk: Value<pallas::Base>,
    pub g_d: Value<pallas::Affine>,
    pub merkle_path: Value<[pallas::Base; MERKLE_DEPTH]>,
    pub merkle_pos: Value<u32>,
    /// Solver-only switch used to reproduce the deployed validator's
    /// equality-cycle ordering while auditing its public leaf binding.
    pub leaf_constraint_mode: u8,
}

impl Default for FarOrchardCircuit {
    fn default() -> Self {
        Self {
            sk: Value::unknown(),
            g_d: Value::unknown(),
            merkle_path: Value::unknown(),
            merkle_pos: Value::unknown(),
            // The released standalone validator has only two public inputs.
            leaf_constraint_mode: u8::MAX,
        }
    }
}

impl Circuit<pallas::Base> for FarOrchardCircuit {
    type Config = FarOrchardConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        FarOrchardConfig::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), Error> {
        SinsemillaChip::<FarOrchardHashDomains, FarOrchardCommitDomains, FarOrchardFixedBases>::load(
            config.sinsemilla_config.clone(),
            &mut layouter,
        )?;

        let ecc_chip = config.ecc_chip();
        let merkle_chip = config.merkle_chip();

        let g_d = NonIdentityPoint::new(
            ecc_chip.clone(),
            layouter.namespace(|| "witness g_d"),
            self.g_d,
        )?;

        let sk_cell = layouter.assign_region(
            || "witness sk",
            |mut region| region.assign_advice(|| "sk", config.advices[0], 0, || self.sk),
        )?;

        let sk_scalar = ScalarVar::from_base(
            ecc_chip.clone(),
            layouter.namespace(|| "sk as ScalarVar"),
            &sk_cell,
        )?;
        let (pk, _) = g_d.mul(layouter.namespace(|| "pk = [sk] * g_d"), sk_scalar)?;
        let nullifier = {
            let nullifier_base = FixedPointBaseField::from_inner(ecc_chip, FarOrchardBaseField);
            nullifier_base.mul(
                layouter.namespace(|| "nullifier = [sk] * NullifierK"),
                sk_cell.clone(),
            )?
        };

        let nf_x = nullifier.extract_p();
        layouter.assign_region(
            || "nullifier check",
            |mut region| {
                config.q_nullifier.enable(&mut region, 0)?;
                nf_x.inner()
                    .copy_advice(|| "nf_x", &mut region, config.advices[0], 0)?;
                region.assign_advice_from_instance(
                    || "expected nf_x",
                    config.primary,
                    1,
                    config.advices[1],
                    0,
                )?;
                Ok(())
            },
        )?;

        let leaf = pk.extract_p().inner().clone();
        if self.leaf_constraint_mode == 0 {
            layouter.constrain_instance(leaf.cell(), config.primary, 2)?;
        }

        let merkle_inputs = MerklePath::<
            pallas::Affine,
            MerkleChip<FarOrchardHashDomains, FarOrchardCommitDomains, FarOrchardFixedBases>,
            MERKLE_DEPTH,
            K,
            MAX_WORDS,
            1,
        >::construct(
            [merkle_chip],
            FarOrchardHashDomains,
            self.merkle_pos,
            self.merkle_path,
        );

        let calculated_root = merkle_inputs
            .calculate_root(
                layouter.namespace(|| "Merkle path verification"),
                leaf.clone(),
            )?;

        if self.leaf_constraint_mode == 1 {
            layouter.constrain_instance(leaf.cell(), config.primary, 2)?;
        }
        layouter.constrain_instance(calculated_root.cell(), config.primary, 0)?;
        if self.leaf_constraint_mode == 2 {
            layouter.constrain_instance(leaf.cell(), config.primary, 2)?;
        }

        Ok(())
    }
}
