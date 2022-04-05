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
pub struct Access;

//lower and upper bound to ensure enough time is given for access
const LOWER: u64 = 0;
const UPPER: u64 = 364;

fn count_bits(number: u64) -> usize {
    let used_bits = 64 - number.leading_zeros();
    return used_bits as usize
}

impl Access {
    pub fn prove(pc_gens: &PedersenGens, bp_gens: &BulletproofGens, expiry_ts: u64, curr_ts: u64, v: &str, pk_server: &str, sk_user: &str, hash_sig: &str, hash: &str, constants: &Vec<Scalar>, com_shr_idx: u32, tree: &VanillaSparseMerkleTree, p_params: &PoseidonParams) -> Result<([CompressedRistretto; 4], [Vec<CompressedRistretto>; 3], R1CSProof), R1CSError> {

        let runtime = Instant::now();
        let mut ts = Duration::new(0,0);

        let mut transcript = Transcript::new(b"Access Circuit");
        let mut prover = Prover::new(&pc_gens, &mut transcript);

        let time_left = expiry_ts - curr_ts;

        //check if time_left is within range [0 - LOWER,364 - UPPER)
        let a = time_left - LOWER;
        let b = UPPER - time_left;
        let mut range_coms = vec![];
        let (com_ts, var_ts) = prover.commit(time_left.into(), gen_random_scalar());
        let quantity_ts = AllocatedQuantity{variable: var_ts, assignment: Some(time_left)};
        range_coms.push(com_ts);
        let (com_a, var_a) = prover.commit(a.into(), gen_random_scalar());
        let quantity_a = AllocatedQuantity{variable: var_a, assignment: Some(a)};
        range_coms.push(com_a);
        let (com_b, var_b) = prover.commit(b.into(), gen_random_scalar());
        let quantity_b = AllocatedQuantity{variable: var_b, assignment: Some(b)};
        range_coms.push(com_b);
        assert!(bound_check_gadget(&mut prover, quantity_ts, quantity_a, quantity_b, UPPER, LOWER, count_bits(UPPER)).is_ok());
        
        //commitment for hiding v
        let mut com_input = "".to_string();
        com_input.push_str(v);
        com_input.push_str(pk_server);
        let (com_acc, _) = prover.commit(scalarize(&com_input), gen_random_scalar()); 

        //proof that PRF is computed correctly, hash
        let (com_l_h, var_l_h) = prover.commit(scalarize(&sk_user), gen_random_scalar());
        let (com_r_h, var_r_h) = prover.commit(scalarize(&hash_sig), gen_random_scalar());
        let left_alloc_h = AllocatedScalar{variable: var_l_h, assignment: Some(scalarize(&sk_user))};
        let right_alloc_h = AllocatedScalar{variable: var_r_h, assignment: Some(scalarize(&hash_sig))};
        assert!(gadget_mimc::mimc_gadget(&mut prover, left_alloc_h, right_alloc_h, 322, &constants, &b64_decode(hash)).is_ok());

        //proof that cm_shr is well formed - IS THIS NEEDED? Isnt the next proof enough?
        //TODO
        
        //proof that cm_shr is in the merkle tree rt_shr
        let com_shr_idx = Scalar::from(com_shr_idx);
        let mut merkle_proof_vec = Vec::<Scalar>::new();
        let mut merkle_proof = Some(merkle_proof_vec);
        tree.get(com_shr_idx, &mut merkle_proof);
        merkle_proof_vec = merkle_proof.unwrap();
        let (com_leaf, var_leaf) = prover.commit(com_shr_idx, gen_random_scalar());
        let leaf_alloc = AllocatedScalar{variable: var_leaf, assignment: Some(com_shr_idx)};

        let mut leaf_index_comms = vec![];
        let mut leaf_index_vars = vec![];
        let mut leaf_index_allocs = vec![];
        for b in get_bits(&com_shr_idx, TreeDepth).iter().take(tree.depth){
            let val = Scalar::from(*b as u8);
            let (com, var) = prover.commit(val.clone(), gen_random_scalar());
            leaf_index_comms.push(com);
            leaf_index_vars.push(var);
            leaf_index_allocs.push(AllocatedScalar{variable: var, assignment: Some(val)});
        }
        //tree.get(com_shr_idx, &mut merkle_proof);
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
        println!("[ACCESS] Prove time: {:?}", ts);
        println!("[ACCESS] Number of constraints: {}", n_cons);
        println!("[ACCESS] Number of multipliers: {}", n_mults);

        // let mut dumb = CompressedRistretto([0;32]);

        let coms_flat = [com_acc, com_l_h, com_r_h, com_leaf];
        // let coms_flat = [dumb, dumb, dumb, dumb, dumb, com_leaf];
        let coms_vec = [range_coms, leaf_index_comms, proof_comms];
        Ok((coms_flat, coms_vec, proof))
    }

    pub fn verify(pc_gens: &PedersenGens, bp_gens: &BulletproofGens, coms_flat: &[CompressedRistretto], coms_vec: &[Vec<CompressedRistretto>], proof: R1CSProof, constants: &Vec<Scalar>,  hash: &str, tree: &VanillaSparseMerkleTree, p_params: &PoseidonParams) -> Result<bool, R1CSError> {    
        let runtime = Instant::now();
        let mut ts = Duration::new(0,0);

        let mut transcript = Transcript::new(b"Access Circuit");
        let mut verifier = Verifier::new(&mut transcript);

        //Verify time_left range
        let var_ts = verifier.commit(coms_vec[0][0]);
        let quantity_ts = AllocatedQuantity{variable: var_ts, assignment: None};  
        let var_a = verifier.commit(coms_vec[0][1]);
        let quantity_a = AllocatedQuantity{variable: var_a, assignment: None};
        let var_b = verifier.commit(coms_vec[0][2]);
        let quantity_b = AllocatedQuantity{variable: var_b, assignment: None};
        assert!(bound_check_gadget(&mut verifier, quantity_ts, quantity_a, quantity_b, UPPER, LOWER, count_bits(UPPER)).is_ok());

        //Verify cm_acc
        let _ = verifier.commit(coms_flat[0]);
        //Verify hash
        let var_l_h = verifier.commit(coms_flat[1]);
        let var_r_h = verifier.commit(coms_flat[2]);
        let left_alloc_h = AllocatedScalar{variable: var_l_h, assignment: None};
        let right_alloc_h= AllocatedScalar{variable: var_r_h, assignment: None};
        assert!(gadget_mimc::mimc_gadget(&mut verifier, left_alloc_h, right_alloc_h, 322, &constants, &b64_decode(hash)).is_ok());
        
        //Verify cm_shr in rt_shr
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
        println!("[ACCESS] Verify time: {:?}", ts);
        Ok(true)
    }
}
