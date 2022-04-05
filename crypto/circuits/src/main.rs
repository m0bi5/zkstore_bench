mod zkstore_circuits;
mod utils;

use bulletproofs_gadgets::gadget_mimc;
use bulletproofs_gadgets::gadget_vsmt_2::*;
use bulletproofs_gadgets::gadget_poseidon::*;
use bulletproofs::{BulletproofGens, PedersenGens};
//use accumulator_membership::protocols::membership::prove;
use curve25519_dalek::scalar::Scalar;   
use rug::Integer;

use std::mem;

use crate::zkstore_circuits::{store::Store as Store, assign::Assign as Assign, share::Share as Share, access::Access as Access};
use crate::utils::{scalarize,gen_random_scalar, b64_encode};

fn main(){
    /*
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(2048, 1);
    let hash_sig = "asdadsd";
    let sk_owner = "ghjkgbdb";
    let constants = (0..322).map(|_| gen_random_scalar()).collect::<Vec<_>>();
    let hash_scalar = gadget_mimc::mimc(&scalarize(&sk_owner), &scalarize(&hash_sig), &constants);
    let hash_as_string = b64_encode(&hash_scalar);
    let hash = hash_as_string.as_str();
    
    let r = gen_random_scalar();
    let p_as_string = b64_encode(&r);
    let p = p_as_string.as_str();

    let (coms, proof) = Store::prove(&pc_gens, &bp_gens, "aafafds", p, sk_owner, "dksfhsjdg", &hash, hash_sig, &constants).unwrap();
    let _ = Store::verify(&pc_gens, &bp_gens, &coms, proof, &constants, hash).unwrap();
    prove(&Integer::from(1))*/
}