use bulletproofs_gadgets::gadget_poseidon::{allocate_statics_for_prover, allocate_statics_for_verifier, PoseidonParams};
use bulletproofs_gadgets::gadget_vsmt_2::{VanillaSparseMerkleTree, TreeDepth, vanilla_merkle_merkle_tree_verif_gadget};
use bulletproofs_gadgets::r1cs_utils::{AllocatedScalar, AllocatedQuantity};
use bulletproofs_gadgets::scalar_utils::get_bits;
use curve25519_dalek::ristretto::{CompressedRistretto};
use bulletproofs_gadgets::gadget_bound_check::bound_check_gadget;
use std::time::{Duration, Instant};
use bulletproofs::{BulletproofGens, PedersenGens};
use bulletproofs::r1cs::*;
use merlin::Transcript;
use bulletproofs_gadgets::*;
use curve25519_dalek::scalar::Scalar;
use crate::utils::{scalarize, gen_random_scalar, b64_decode};
pub struct Share;

//lower and upper bound to ensure enough time is given for access
const LOWER: u64 = 1;
const UPPER: u64 = 365;

fn count_bits(number: u64) -> usize {
    let used_bits = 64 - number.leading_zeros();
    return used_bits as usize
}

impl Share {
    pub fn prove(pc_gens: &PedersenGens, bp_gens: &BulletproofGens, expiry_ts: u64, v: &str, pk_user: &str, sk_owner: &str, hash_sig: &str, hash: &str, constants: &Vec<Scalar>, com_own_idx: u32, tree: &VanillaSparseMerkleTree, p_params: &PoseidonParams) -> Result<([CompressedRistretto; 4], [Vec<CompressedRistretto>; 3], R1CSProof), R1CSError> {

        let runtime = Instant::now();
        let mut ts = Duration::new(0,0);

        let mut transcript = Transcript::new(b"Share Circuit");
        let mut prover = Prover::new(&pc_gens, &mut transcript);

        //check if expiry_ts is within range [1 - LOWER,365 - UPPER)
        let a = expiry_ts - LOWER;
        let b = UPPER - expiry_ts;
        let mut range_coms = vec![];
        let (com_ts, var_ts) = prover.commit(expiry_ts.into(), gen_random_scalar());
        let quantity_ts = AllocatedQuantity{variable: var_ts, assignment: Some(expiry_ts)};
        range_coms.push(com_ts);
        let (com_a, var_a) = prover.commit(a.into(), gen_random_scalar());
        let quantity_a = AllocatedQuantity{variable: var_a, assignment: Some(a)};
        range_coms.push(com_a);
        let (com_b, var_b) = prover.commit(b.into(), gen_random_scalar());
        let quantity_b = AllocatedQuantity{variable: var_b, assignment: Some(b)};
        range_coms.push(com_b);
        assert!(bound_check_gadget(&mut prover, quantity_ts, quantity_a, quantity_b, UPPER, LOWER, count_bits(UPPER)).is_ok());
        
        //commitment for hiding v and expiry_ts
        let mut com_input = "".to_string();
        com_input.push_str(v);
        com_input.push_str(pk_user);
        com_input.push_str(&expiry_ts.to_string());
        let (com_shr, _) = prover.commit(scalarize(&com_input), gen_random_scalar()); 

        //proof that PRF is computed correctly, hash
        let (com_l_h, var_l_h) = prover.commit(scalarize(&sk_owner), gen_random_scalar());
        let (com_r_h, var_r_h) = prover.commit(scalarize(&hash_sig), gen_random_scalar());
        let left_alloc_h = AllocatedScalar{variable: var_l_h, assignment: Some(scalarize(&sk_owner))};
        let right_alloc_h = AllocatedScalar{variable: var_r_h, assignment: Some(scalarize(&hash_sig))};
        assert!(gadget_mimc::mimc_gadget(&mut prover, left_alloc_h, right_alloc_h, 322, &constants, &b64_decode(hash)).is_ok());

        //proof that cm_own is well formed - IS THIS NEEDED? Isnt the next proof enough?
        //TODO
        
        //proof that cm_own is in the merkle tree rt_own
        let com_own_idx = Scalar::from(com_own_idx);
        let mut merkle_proof_vec = Vec::<Scalar>::new();
        let mut merkle_proof = Some(merkle_proof_vec);
        tree.get(com_own_idx, &mut merkle_proof);
        merkle_proof_vec = merkle_proof.unwrap();
        let (com_leaf, var_leaf) = prover.commit(com_own_idx, gen_random_scalar());
        let leaf_alloc = AllocatedScalar{variable: var_leaf, assignment: Some(com_own_idx)};

        let mut leaf_index_comms = vec![];
        let mut leaf_index_vars = vec![];
        let mut leaf_index_allocs = vec![];
        for b in get_bits(&com_own_idx, TreeDepth).iter().take(tree.depth){
            let val = Scalar::from(*b as u8);
            let (com, var) = prover.commit(val.clone(), gen_random_scalar());
            leaf_index_comms.push(com);
            leaf_index_vars.push(var);
            leaf_index_allocs.push(AllocatedScalar{variable: var, assignment: Some(val)});
        }
        //tree.get(com_own_idx, &mut merkle_proof);
        //merkle_proof_vec = merkle_proof.unwrap();
        let mut proof_comms = vec![];
        let mut proof_vars = vec![];
        let mut proof_allocs = vec![];
        for p in merkle_proof_vec.iter().rev(){
            let (com, var) = prover.commit(*p, gen_random_scalar());
            proof_comms.push(com);
            proof_vars.push(var);
            proof_allocs.push(AllocatedScalar{variable: var, assignment: Some(*p)});
        }

        let statics = allocate_statics_for_prover(&mut prover, 4);
        assert!(vanilla_merkle_merkle_tree_verif_gadget(&mut prover, tree.depth, &tree.root, leaf_alloc, leaf_index_allocs, proof_allocs, statics, &p_params).is_ok());
        

        let n_cons = prover.num_constraints();
        let n_mults = prover.num_multipliers();
        let proof = prover.prove(&bp_gens).unwrap();
        ts += runtime.elapsed();
        println!("[SHARE] Prove time: {:?}", ts);
        println!("[SHARE] Number of constraints: {}", n_cons);
        println!("[SHARE] Number of multipliers: {}", n_mults);

        // let mut dumb = CompressedRistretto([0;32]);

        let coms_flat = [com_shr, com_l_h, com_r_h, com_leaf];
        // let coms_flat = [dumb, dumb, dumb, dumb, dumb, com_leaf];
        let coms_vec = [range_coms, leaf_index_comms, proof_comms];
        Ok((coms_flat, coms_vec, proof))
    }

    pub fn verify(pc_gens: &PedersenGens, bp_gens: &BulletproofGens, coms_flat: &[CompressedRistretto], coms_vec: &[Vec<CompressedRistretto>], proof: R1CSProof, constants: &Vec<Scalar>,  hash: &str, tree: &VanillaSparseMerkleTree, p_params: &PoseidonParams) -> Result<bool, R1CSError> {    
        let runtime = Instant::now();
        let mut ts = Duration::new(0,0);

        let mut transcript = Transcript::new(b"Share Circuit");
        let mut verifier = Verifier::new(&mut transcript);

        //Verify expiry_ts range
        let var_ts = verifier.commit(coms_vec[0][0]);
        let quantity_ts = AllocatedQuantity{variable: var_ts, assignment: None};  
        let var_a = verifier.commit(coms_vec[0][1]);
        let quantity_a = AllocatedQuantity{variable: var_a, assignment: None};
        let var_b = verifier.commit(coms_vec[0][2]);
        let quantity_b = AllocatedQuantity{variable: var_b, assignment: None};
        assert!(bound_check_gadget(&mut verifier, quantity_ts, quantity_a, quantity_b, UPPER, LOWER, count_bits(UPPER)).is_ok());

        //Verify cm_shr
        let _ = verifier.commit(coms_flat[0]);
        //Verify hash
        let var_l_h = verifier.commit(coms_flat[1]);
        let var_r_h = verifier.commit(coms_flat[2]);
        let left_alloc_h = AllocatedScalar{variable: var_l_h, assignment: None};
        let right_alloc_h= AllocatedScalar{variable: var_r_h, assignment: None};
        assert!(gadget_mimc::mimc_gadget(&mut verifier, left_alloc_h, right_alloc_h, 322, &constants, &b64_decode(hash)).is_ok());
        
        //Verify cm_own in rt_own
        let var_leaf = verifier.commit(coms_flat[3]);
        let leaf_alloc = AllocatedScalar{variable: var_leaf, assignment: None};
        let mut leaf_index_allocs = vec![];
        for l in coms_vec[1].clone(){
            let var = verifier.commit(l);
            leaf_index_allocs.push(AllocatedScalar{variable: var, assignment: None});
        }
        let mut proof_allocs = vec![];
        for p in coms_vec[2].clone(){
            let var = verifier.commit(p);
            proof_allocs.push(AllocatedScalar{variable: var, assignment: None});
        }
        let statics = allocate_statics_for_verifier(&mut verifier, 4, &pc_gens);
        assert!(vanilla_merkle_merkle_tree_verif_gadget(&mut verifier, tree.depth, &tree.root, leaf_alloc, leaf_index_allocs, proof_allocs, statics, &p_params).is_ok());
        assert!(verifier.verify(&proof, &pc_gens, &bp_gens).is_ok());
        
        ts += runtime.elapsed();
        println!("[SHARE] Verify time: {:?}", ts);
        Ok(true)
    }
}
