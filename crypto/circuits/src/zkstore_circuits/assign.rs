use bulletproofs_gadgets::gadget_poseidon::{allocate_statics_for_prover, allocate_statics_for_verifier, PoseidonParams};
use bulletproofs_gadgets::gadget_vsmt_2::{VanillaSparseMerkleTree, TreeDepth, vanilla_merkle_merkle_tree_verif_gadget};
use bulletproofs_gadgets::r1cs_utils::AllocatedScalar;
use bulletproofs_gadgets::scalar_utils::get_bits;
use curve25519_dalek::ristretto::{CompressedRistretto};
use std::time::{Duration, Instant};
use bulletproofs::{BulletproofGens, PedersenGens};
use bulletproofs::r1cs::*;
use merlin::Transcript;
use bulletproofs_gadgets::*;
use curve25519_dalek::scalar::Scalar;
use crate::utils::{scalarize, gen_random_scalar, b64_decode};
pub struct Assign;

impl Assign {
    pub fn prove(pc_gens: &PedersenGens, bp_gens: &BulletproofGens, v: &str, pk_owner: &str, sk_server: &str, p: &str, hash_sig: &str, sn: &str, hash: &str, constants: &Vec<Scalar>, com_str_idx: u32, tree: &VanillaSparseMerkleTree, p_params: &PoseidonParams) -> Result<([CompressedRistretto; 6], [Vec<CompressedRistretto>; 2], R1CSProof), R1CSError> {

        let runtime = Instant::now();
        let mut ts = Duration::new(0,0);

        let mut transcript = Transcript::new(b"Assign Circuit");
        let mut prover = Prover::new(&pc_gens, &mut transcript);

        //commitment for hiding v
        let mut com_input = "".to_string();
        com_input.push_str(v);
        com_input.push_str(pk_owner);
        let (com_own, _) = prover.commit(scalarize(&com_input), gen_random_scalar());

        //proof that PRF is computed correctly, serial number
        let (com_l_sn, var_l_sn) = prover.commit(scalarize(&sk_server), gen_random_scalar());
        let (com_r_sn, var_r_sn) = prover.commit(scalarize(&p), gen_random_scalar());
        let left_alloc_sn = AllocatedScalar{variable: var_l_sn, assignment: Some(scalarize(&sk_server))};
        let right_alloc_sn = AllocatedScalar{variable: var_r_sn, assignment: Some(scalarize(&p))};
        assert!(gadget_mimc::mimc_gadget(&mut prover, left_alloc_sn, right_alloc_sn, 322, &constants, &b64_decode(sn)).is_ok());

        //proof that PRF is computed correctly, hash
        let (com_l_h, var_l_h) = prover.commit(scalarize(&sk_server), gen_random_scalar());
        let (com_r_h, var_r_h) = prover.commit(scalarize(&hash_sig), gen_random_scalar());
        let left_alloc_h = AllocatedScalar{variable: var_l_h, assignment: Some(scalarize(&sk_server))};
        let right_alloc_h = AllocatedScalar{variable: var_r_h, assignment: Some(scalarize(&hash_sig))};
        assert!(gadget_mimc::mimc_gadget(&mut prover, left_alloc_h, right_alloc_h, 322, &constants, &b64_decode(hash)).is_ok());

        //proof that cm_str is well formed - IS THIS NEEDED? Isnt the next proof enough?
        //TODO
        
        //proof that cm_str is in the merkle tree rt_str
        let com_str_idx = Scalar::from(com_str_idx);
        let mut merkle_proof_vec = Vec::<Scalar>::new();
        let mut merkle_proof = Some(merkle_proof_vec);
        tree.get(com_str_idx, &mut merkle_proof);
        merkle_proof_vec = merkle_proof.unwrap();
        let (com_leaf, var_leaf) = prover.commit(com_str_idx, gen_random_scalar());
        let leaf_alloc = AllocatedScalar{variable: var_leaf, assignment: Some(com_str_idx)};

        let mut leaf_index_comms = vec![];
        let mut leaf_index_vars = vec![];
        let mut leaf_index_allocs = vec![];
        for b in get_bits(&com_str_idx, TreeDepth).iter().take(tree.depth){
            let val = Scalar::from(*b as u8);
            let (com, var) = prover.commit(val.clone(), gen_random_scalar());
            leaf_index_comms.push(com);
            leaf_index_vars.push(var);
            leaf_index_allocs.push(AllocatedScalar{variable: var, assignment: Some(val)});
        }
        //tree.get(com_str_idx, &mut merkle_proof);
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
        println!("[ASSIGN] Prove time: {:?}", ts);
        println!("[ASSIGN] Number of constraints: {}", n_cons);
        println!("[ASSIGN] Number of multipliers: {}", n_mults);

        // let mut dumb = CompressedRistretto([0;32]);

        let coms_flat = [com_own, com_l_sn, com_r_sn, com_l_h, com_r_h, com_leaf];
        // let coms_flat = [dumb, dumb, dumb, dumb, dumb, com_leaf];
        let coms_vec = [leaf_index_comms, proof_comms];
        Ok((coms_flat, coms_vec, proof))
    }

    pub fn verify(pc_gens: &PedersenGens, bp_gens: &BulletproofGens, coms_flat: &[CompressedRistretto], coms_vec: &[Vec<CompressedRistretto>], proof: R1CSProof, constants: &Vec<Scalar>, sn: &str, hash: &str, tree: &VanillaSparseMerkleTree, p_params: &PoseidonParams) -> Result<bool, R1CSError> {    
        let runtime = Instant::now();
        let mut ts = Duration::new(0,0);

        let mut transcript = Transcript::new(b"Assign Circuit");
        let mut verifier = Verifier::new(&mut transcript);
        //Verify cm_own
        let _ = verifier.commit(coms_flat[0]);
        //Verify sn
        let var_l_sn = verifier.commit(coms_flat[1]);
        let var_r_sn = verifier.commit(coms_flat[2]);
        let left_alloc_sn = AllocatedScalar{variable: var_l_sn, assignment: None};
        let right_alloc_sn = AllocatedScalar{variable: var_r_sn, assignment: None};
        assert!(gadget_mimc::mimc_gadget(&mut verifier, left_alloc_sn, right_alloc_sn, 322, &constants, &b64_decode(sn)).is_ok());
        //Verify hash
        let var_l_h = verifier.commit(coms_flat[3]);
        let var_r_h = verifier.commit(coms_flat[4]);
        let left_alloc_h = AllocatedScalar{variable: var_l_h, assignment: None};
        let right_alloc_h= AllocatedScalar{variable: var_r_h, assignment: None};
        assert!(gadget_mimc::mimc_gadget(&mut verifier, left_alloc_h, right_alloc_h, 322, &constants, &b64_decode(hash)).is_ok());
        
        //Verify cm_str in rt_str
        let var_leaf = verifier.commit(coms_flat[5]);
        let leaf_alloc = AllocatedScalar{variable: var_leaf, assignment: None};
        let mut leaf_index_allocs = vec![];
        for l in coms_vec[0].clone(){
            let var = verifier.commit(l);
            leaf_index_allocs.push(AllocatedScalar{variable: var, assignment: None});
        }
        let mut proof_allocs = vec![];
        for p in coms_vec[1].clone(){
            let var = verifier.commit(p);
            proof_allocs.push(AllocatedScalar{variable: var, assignment: None});
        }
        let statics = allocate_statics_for_verifier(&mut verifier, 4, &pc_gens);
        assert!(vanilla_merkle_merkle_tree_verif_gadget(&mut verifier, tree.depth, &tree.root, leaf_alloc, leaf_index_allocs, proof_allocs, statics, &p_params).is_ok());
        assert!(verifier.verify(&proof, &pc_gens, &bp_gens).is_ok());
        
        ts += runtime.elapsed();
        println!("[ASSIGN] Verify time: {:?}", ts);
        Ok(true)
    }
}
