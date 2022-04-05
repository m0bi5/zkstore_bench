use bulletproofs_gadgets::r1cs_utils::AllocatedScalar;
use curve25519_dalek::ristretto::CompressedRistretto;
use std::time::{Duration, Instant};
use bulletproofs::{BulletproofGens, PedersenGens};
use bulletproofs::r1cs::*;
use merlin::Transcript;
use bulletproofs_gadgets::*;
use curve25519_dalek::scalar::Scalar;
use crate::utils::{scalarize, gen_random_scalar, b64_decode};
pub struct Store;

impl Store {
    pub fn prove(pc_gens: &PedersenGens, bp_gens: &BulletproofGens, v: &str, p: &str, sk_owner: &str, pk_server: &str, hash: &str, hash_sig: &str, constants: &Vec<Scalar>) -> Result<([CompressedRistretto; 3], R1CSProof), R1CSError> {
        let runtime = Instant::now();
        let mut ts = Duration::new(0,0);

        let mut transcript = Transcript::new(b"Store Circuit");
        let mut prover = Prover::new(&pc_gens, &mut transcript);
        let mut com_input = "".to_string();
        com_input.push_str(v);
        com_input.push_str(pk_server);
        com_input.push_str(p);
        //commitment for hiding v
        let (com, _) = prover.commit(scalarize(&com_input), gen_random_scalar());
        //proof that PRF is computed correctly
        let (com_l, var_l) = prover.commit(scalarize(&sk_owner), gen_random_scalar());
        let (com_r, var_r) = prover.commit(scalarize(&hash_sig), gen_random_scalar());
        let left_alloc = AllocatedScalar{variable: var_l, assignment: Some(scalarize(&sk_owner))};
        let right_alloc = AllocatedScalar{variable: var_r, assignment: Some(scalarize(&hash_sig))};
        assert!(gadget_mimc::mimc_gadget(&mut prover, left_alloc, right_alloc, 322, &constants, &b64_decode(hash)).is_ok());

        let n_cons = prover.num_constraints();
        let n_mults = prover.num_multipliers();
        let proof = prover.prove(&bp_gens).unwrap();
        
        ts += runtime.elapsed();
        println!("[STORE] Prove time: {:?}", ts);
        println!("[STORE] Number of constraints: {}", n_cons);
        println!("[STORE] Number of multipliers: {}", n_mults);

        let coms = [com, com_l, com_r];
        Ok((coms, proof))
    }
    pub fn verify(pc_gens: &PedersenGens, bp_gens: &BulletproofGens, coms: &[CompressedRistretto], proof: R1CSProof, constants: &Vec<Scalar>, hash: &str) -> Result<bool, R1CSError> {
        let runtime = Instant::now();
        let mut ts = Duration::new(0,0);

        let mut transcript = Transcript::new(b"Store Circuit");
        let mut verifier = Verifier::new(&mut transcript);

        //Verify that commitments are well formed
        let _ = verifier.commit(coms[0]);
        let var_l = verifier.commit(coms[1]);
        let var_r = verifier.commit(coms[2]);
        //Verify that PRF is computed correctly
        let left_alloc = AllocatedScalar{variable: var_l, assignment: None};
        let right_alloc = AllocatedScalar{variable: var_r, assignment: None};
        assert!(gadget_mimc::mimc_gadget(&mut verifier, left_alloc, right_alloc, 322, &constants, &b64_decode(hash)).is_ok());
        //Verify that proof is correct
        assert!(verifier.verify(&proof, &pc_gens, &bp_gens).is_ok());
        
        ts += runtime.elapsed();
        println!("[STORE] Verify time: {:?}", ts);
        
        Ok(true)
    }
}
