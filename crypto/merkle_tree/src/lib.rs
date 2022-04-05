use pyo3::prelude::*;
use pyo3::wrap_pyfunction;
use curve25519_dalek::scalar::Scalar;
use base64::{encode,decode};
use bulletproofs_gadgets::gadget_vsmt_2::*;
use bulletproofs_gadgets::gadget_poseidon::*;
use std::collections::HashMap;
use std::convert::TryInto;

fn vec_2_fixed<T>(v: Vec<T>) -> [T; 32] {
    let boxed_slice = v.into_boxed_slice();
    let boxed_array: Box<[T; 32]> = match boxed_slice.try_into() {
        Ok(ba) => ba,
        Err(o) => panic!("Expected a Vec of length {} but it was {}", 32, o.len()),
    };
    *boxed_array
}

// type ScalarBytes = [u8; 32];
// type DBVal = (Scalar, Scalar);

pub const TREE_DEPTH: usize = 64;

pub fn b64_encode(s: &Scalar) -> String{
    encode(s.to_bytes())
}
pub fn b64_encode2(s: &[u8]) -> String{
    encode(s)
}
pub fn b64_decode2(s: &String) -> [u8; 32]{
    vec_2_fixed(decode(&s).unwrap())
}
pub fn clone_into_array<A, T>(slice: &[T]) -> A
    where A: Sized + Default + AsMut<[T]>,
          T: Clone
{
    let mut a = Default::default();
    <A as AsMut<[T]>>::as_mut(&mut a).clone_from_slice(slice);
    a
}
pub fn b64_decode(s: &str) -> Scalar{
    let result = decode(s).unwrap();
    //decoding 64 to 32?! - watchout!!!
    Scalar::from_bytes_mod_order(clone_into_array(&result[..]))
}

pub fn from_vsmt(tree: &VanillaSparseMerkleTree) -> (String, Vec<String>, HashMap<String, (String, String)>){
    let root = b64_encode(&tree.root);
    let empty_tree_hashes = tree.empty_tree_hashes.iter().map(|x| b64_encode(x)).collect();
    let db = tree.db.iter().map(|(k, v)| (b64_encode2(k), (b64_encode(&v.0), b64_encode(&v.1)))).collect();
    (root, empty_tree_hashes, db)
}

#[pyfunction]
fn update(idx: u32, val: u32, root: String, tree_hashes: Vec<String>, db: HashMap<String, (String, String)>) -> PyResult<(String, Vec<String>, HashMap<String, (String, String)>)> {
    let width = 6;
    let (full_b, full_e) = (4, 4);
    let partial_rounds = 140;
    let params = PoseidonParams::new(width, full_b, full_e, partial_rounds);
    let hash_params = &params;
    let mut vsmt = VanillaSparseMerkleTree {
        depth: TREE_DEPTH,
        root: b64_decode(&root),
        empty_tree_hashes: tree_hashes.iter().map(|x| b64_decode(x)).collect(),
        db: db.iter().map(|(k, v)| (b64_decode2(k), (b64_decode(&v.0), b64_decode(&v.1)))).collect(),
        hash_params: hash_params
    } ;
    vsmt.update(Scalar::from(idx), Scalar::from(val));
    Ok(from_vsmt(&vsmt))
}

#[pyfunction]
fn new() -> PyResult<(String, Vec<String>, HashMap<String, (String, String)>)> {    
    let width = 6;
    let (full_b, full_e) = (4, 4);
    let partial_rounds = 140;
    let params = PoseidonParams::new(width, full_b, full_e, partial_rounds);
    let depth = TREE_DEPTH;
    let hash_params = &params;
    let mut db = HashMap::new();
    let mut empty_tree_hashes: Vec<Scalar> = vec![];
    empty_tree_hashes.push(Scalar::zero());
    for i in 1..=depth {
        let prev = empty_tree_hashes[i-1];
        let new = Poseidon_hash_2(prev.clone(), prev.clone(), hash_params, &SboxType::Inverse);
        let key = new.to_bytes();

        db.insert(key, (prev, prev));
        empty_tree_hashes.push(new);
    }

    let root = empty_tree_hashes[depth].clone();

    let vsmt = VanillaSparseMerkleTree {
        depth,
        empty_tree_hashes,
        db,
        hash_params,
        root
    };
    Ok(from_vsmt(&vsmt))
}

#[pymodule]
fn rust_merkle_tree(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(update, m)?)?;
    m.add_function(wrap_pyfunction!(new, m)?)?;
    Ok(())
}