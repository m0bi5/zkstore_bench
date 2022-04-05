#![ allow( dead_code, unused_imports, non_upper_case_globals ) ]

use pyo3::prelude::*;
use pyo3::wrap_pyfunction;
mod zkstore_circuits;
mod utils;

use base64::{encode,decode};
use serde::{Serialize, Deserialize};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, ristretto::CompressedRistretto};
use crate::zkstore_circuits::{store::Store as Store, assign::Assign as Assign, share::Share as Share, access::Access as Access};
use bulletproofs::{BulletproofGens, PedersenGens};
use std::{fs::File, io::{BufReader}};
use bulletproofs_gadgets::gadget_vsmt_2::*;
use bulletproofs_gadgets::gadget_poseidon::*;
use std::collections::HashMap;
use bulletproofs::r1cs::*;
use crate::utils::{from_vsmt, into_vsmt, ristretto_vec_to_string_vec, string_vec_to_ristretto_vec};

pub fn read_scalar_vec_from_str(vec: Vec<String>) -> Vec<Scalar>{
    let mut vec_scalar = vec![];
    for i in vec{
        vec_scalar.push(serde_json::from_str(&i).unwrap());
    }
    vec_scalar
}

#[pyfunction]
fn store_prove(v: String, p: String, sk_owner: String, pk_server: String, hash: String, hash_sig: String, filename: Vec<String>) -> PyResult<(Vec<String>, String)> {
    let constants = read_scalar_vec_from_str(filename);
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(65536, 1);
    let (coms, proof) = Store::prove(&pc_gens, &bp_gens, &v, &p, &sk_owner, &pk_server, &hash, &hash_sig, &constants).unwrap();  
    let coms_v = ristretto_vec_to_string_vec(&coms.to_vec());
    let proof_s = encode(&proof.to_bytes());
    Ok((coms_v, proof_s))
}

#[pyfunction]
fn store_verify(coms: Vec<String>, proof: String, hash: String, filename: Vec<String>) -> PyResult<bool> {
    let constants = read_scalar_vec_from_str(filename);
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(65536, 1);
    let coms_v = string_vec_to_ristretto_vec(&coms.to_vec());
    let proof = R1CSProof::from_bytes(&decode(proof).unwrap()).unwrap();
    Ok(Store::verify(&pc_gens, &bp_gens, &coms_v, proof, &constants, &hash).unwrap()) 
}

#[pyfunction]
fn store_verify2(coms: Vec<String>, proof: String, hash: String, filename: Vec<String>) -> PyResult<bool> {
    let constants = read_scalar_vec_from_str(filename);
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(65536, 1);
    Ok(false) 
}

#[pyfunction]
fn assign_prove(v: String, p: String, sk_server: String, pk_owner: String, hash: String, hash_sig: String, sn: String, updated_cm_idx: u32, root: String, empty_tree_hashes: Vec<String>, db: HashMap<String, (String, String)>, filename: Vec<String>) -> PyResult<(Vec<String>, Vec<Vec<String>>, String)> {
    let width = 6;
    let (full_b, full_e) = (4, 4);
    let partial_rounds = 140;
    let p_params = PoseidonParams::new(width, full_b, full_e, partial_rounds);
    let constants = read_scalar_vec_from_str(filename);
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(65536, 1);
    let vsmt = into_vsmt(root, empty_tree_hashes, db, &p_params);
    let (coms_flat, coms_vec, proof) = Assign::prove(&pc_gens, &bp_gens, &v, &pk_owner, &sk_server, &p, &hash_sig, &sn, &hash, &constants, updated_cm_idx, &vsmt, &p_params).unwrap();  
    let coms_flat_v = ristretto_vec_to_string_vec(&coms_flat.to_vec());
    let mut coms_vec_v = vec![];
    for i in coms_vec{
        coms_vec_v.push(ristretto_vec_to_string_vec(&i));
    }
    let proof_s = encode(&proof.to_bytes());
    Ok((coms_flat_v, coms_vec_v, proof_s))
}

#[pyfunction]
fn assign_verify(coms_flat: Vec<String>, coms_vec: Vec<Vec<String>>, proof: String, sn: String, hash: String, root: String, empty_tree_hashes: Vec<String>, db: HashMap<String, (String, String)>, filename: Vec<String>) -> PyResult<bool> {
    let width = 6;
    let (full_b, full_e) = (4, 4);
    let partial_rounds = 140;
    let p_params = PoseidonParams::new(width, full_b, full_e, partial_rounds);
    let constants = read_scalar_vec_from_str(filename);
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(65536, 1);
    let vsmt = into_vsmt(root, empty_tree_hashes, db, &p_params);
    let coms_flat_v = string_vec_to_ristretto_vec(&coms_flat.to_vec());
    let mut coms_vec_v = vec![];
    for i in coms_vec{
        coms_vec_v.push(string_vec_to_ristretto_vec(&i));
    }
    let proof = R1CSProof::from_bytes(&decode(proof).unwrap()).unwrap();
    Ok(Assign::verify(&pc_gens, &bp_gens, &coms_flat_v, &coms_vec_v, proof, &constants, &sn, &hash , &vsmt, &p_params).unwrap())
}

#[pyfunction]
fn share_prove(v: String, sk_owner: String, pk_user: String, hash: String, hash_sig: String, expiry_ts: u64, updated_cm_idx: u32, root: String, empty_tree_hashes: Vec<String>, db: HashMap<String, (String, String)>, filename: Vec<String>) -> PyResult<(Vec<String>, Vec<Vec<String>>, String)> {
    let width = 6;
    let (full_b, full_e) = (4, 4);
    let partial_rounds = 140;
    let p_params = PoseidonParams::new(width, full_b, full_e, partial_rounds);
    let constants = read_scalar_vec_from_str(filename);
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(65536, 1);

    let vsmt = into_vsmt(root, empty_tree_hashes, db, &p_params);

    let (coms_flat, coms_vec, proof) = Share::prove(&pc_gens, &bp_gens, expiry_ts, &v, &pk_user, &sk_owner, &hash_sig, &hash, &constants, updated_cm_idx, &vsmt, &p_params).unwrap();
    let coms_flat_v = ristretto_vec_to_string_vec(&coms_flat.to_vec());
    let mut coms_vec_v = vec![];
    for i in coms_vec{
        coms_vec_v.push(ristretto_vec_to_string_vec(&i));
    }
    let proof_s = encode(&proof.to_bytes());
    Ok((coms_flat_v, coms_vec_v, proof_s))
}

#[pyfunction]
fn share_verify(coms_flat: Vec<String>, coms_vec: Vec<Vec<String>>, proof: String, hash: String, root: String, empty_tree_hashes: Vec<String>, db: HashMap<String, (String, String)>, filename: Vec<String>) -> PyResult<bool>{
    let width = 6;
    let (full_b, full_e) = (4, 4);
    let partial_rounds = 140;
    let p_params = PoseidonParams::new(width, full_b, full_e, partial_rounds);
    let constants = read_scalar_vec_from_str(filename);
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(65536, 1);
    let vsmt = into_vsmt(root, empty_tree_hashes, db, &p_params);
    let coms_flat = string_vec_to_ristretto_vec(&coms_flat);
    let mut coms_vec_v = vec![];
    for i in coms_vec{
        coms_vec_v.push(string_vec_to_ristretto_vec(&i));
    }
    let proof = R1CSProof::from_bytes(&decode(proof).unwrap()).unwrap();
    Ok(Share::verify(&pc_gens, &bp_gens, &coms_flat, &coms_vec_v, proof, &constants, &hash, &vsmt, &p_params).unwrap())
}

#[pyfunction]
fn access_prove(v: String, sk_user: String, pk_server: String, hash: String, hash_sig: String, current_ts: u64, expiry_ts: u64, updated_cm_idx: u32, root: String, empty_tree_hashes: Vec<String>, db: HashMap<String, (String, String)>, filename: Vec<String>) -> PyResult<(Vec<String>, Vec<Vec<String>>, String)>{
    let width = 6;
    let (full_b, full_e) = (4, 4);
    let partial_rounds = 140;
    let p_params = PoseidonParams::new(width, full_b, full_e, partial_rounds);
    let constants = read_scalar_vec_from_str(filename);
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(65536, 1);
    let vsmt = into_vsmt(root, empty_tree_hashes, db, &p_params);
    let (coms_flat, coms_vec, proof) = Access::prove(&pc_gens, &bp_gens, expiry_ts, current_ts, &v, &pk_server, &sk_user, &hash_sig, &hash, &constants, updated_cm_idx, &vsmt, &p_params).unwrap();
    let coms_flat_v = ristretto_vec_to_string_vec(&coms_flat.to_vec());
    let mut coms_vec_v = vec![];
    for i in coms_vec{
        coms_vec_v.push(ristretto_vec_to_string_vec(&i));
    }
    let proof_s = encode(&proof.to_bytes());
    Ok((coms_flat_v, coms_vec_v, proof_s))
}
#[pyfunction]
fn access_verify(coms_flat: Vec<String>, coms_vec: Vec<Vec<String>>, proof: String, hash: String, root: String, empty_tree_hashes: Vec<String>, db: HashMap<String, (String, String)>, filename: Vec<String>) -> PyResult<bool>{
    let width = 6;
    let (full_b, full_e) = (4, 4);
    let partial_rounds = 140;
    let p_params = PoseidonParams::new(width, full_b, full_e, partial_rounds);
    let constants = read_scalar_vec_from_str(filename);
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(65536, 1);
    let vsmt = into_vsmt(root, empty_tree_hashes, db, &p_params);
    let coms_flat = string_vec_to_ristretto_vec(&coms_flat);
    let mut coms_vec_v = vec![];
    for i in coms_vec{
        coms_vec_v.push(string_vec_to_ristretto_vec(&i));
    }
    let proof = R1CSProof::from_bytes(&decode(proof).unwrap()).unwrap();
    Ok(Access::verify(&pc_gens, &bp_gens, &coms_flat, &coms_vec_v, proof, &constants, &hash, &vsmt, &p_params).unwrap())
}

#[pymodule]
fn rust_circuits(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(store_prove, m)?)?;
    m.add_function(wrap_pyfunction!(store_verify, m)?)?;
    m.add_function(wrap_pyfunction!(store_verify2, m)?)?;
    m.add_function(wrap_pyfunction!(assign_prove, m)?)?;
    m.add_function(wrap_pyfunction!(assign_verify, m)?)?;
    m.add_function(wrap_pyfunction!(share_prove, m)?)?;
    m.add_function(wrap_pyfunction!(share_verify, m)?)?;
    m.add_function(wrap_pyfunction!(access_prove, m)?)?;
    m.add_function(wrap_pyfunction!(access_verify, m)?)?;
    Ok(())
}