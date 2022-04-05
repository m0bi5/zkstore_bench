use base64::{encode, decode};
use rand::thread_rng;
use curve25519_dalek::{scalar::Scalar, ristretto::CompressedRistretto};
use sha3::{Digest, Sha3_256};
use bulletproofs_gadgets::gadget_vsmt_2::*;
use bulletproofs_gadgets::gadget_poseidon::*;
use std::collections::HashMap;
use std::convert::TryInto;
use std::convert::AsMut;

pub fn clone_into_array<A, T>(slice: &[T]) -> A
    where A: Sized + Default + AsMut<[T]>,
          T: Clone
{
    let mut a = Default::default();
    <A as AsMut<[T]>>::as_mut(&mut a).clone_from_slice(slice);
    a
}

pub fn ristretto_vec_to_string_vec(scalar_vec: &Vec<CompressedRistretto>) -> Vec<String> {
    let mut string_vec = Vec::new();
    for i in scalar_vec {
        string_vec.push(encode(&i.to_bytes()));
    }
    string_vec
}

pub fn string_vec_to_ristretto_vec(string_vec: &Vec<String>) -> Vec<CompressedRistretto> {
    let mut scalar_vec = Vec::new();
    for i in string_vec {
        let mut bytes = [0u8;32];
        bytes.copy_from_slice(&decode(&i).unwrap());
        let scalar = CompressedRistretto::from_slice(&bytes);
        scalar_vec.push(scalar);
    }
    scalar_vec
}

pub fn scalarize(s: &str) -> Scalar{
    let mut hasher = Sha3_256::new();
    hasher.update(s.as_bytes());
    let result = hasher.finalize();
    Scalar::from_bytes_mod_order(clone_into_array(&result[..]))
}

pub fn b64_encode(s: &Scalar) -> String{
    encode(s.to_bytes())
}

pub fn b64_decode(s: &str) -> Scalar{
    let result = decode(s).unwrap();
    Scalar::from_bytes_mod_order(clone_into_array(&result[..]))
}

pub fn gen_random_scalar() -> Scalar{
    let mut rng = thread_rng();
    Scalar::random(&mut rng)
}



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

pub fn b64_encode2(s: &[u8]) -> String{
    encode(s)
}
pub fn b64_decode2(s: &String) -> [u8; 32]{
    vec_2_fixed(decode(&s).unwrap())
}

pub fn from_vsmt(tree: &VanillaSparseMerkleTree) -> (String, Vec<String>, HashMap<String, (String, String)>){
    let root = b64_encode(&tree.root);
    let empty_tree_hashes = tree.empty_tree_hashes.iter().map(|x| b64_encode(x)).collect();
    let db = tree.db.iter().map(|(k, v)| (b64_encode2(k), (b64_encode(&v.0), b64_encode(&v.1)))).collect();
    (root, empty_tree_hashes, db)
}

pub fn into_vsmt(root: String, empty_tree_hashes: Vec<String>, db: HashMap<String, (String, String)>, hash_params: &PoseidonParams) -> VanillaSparseMerkleTree{
    let depth = TREE_DEPTH;
    let root = b64_decode(&root);
    let empty_tree_hashes = empty_tree_hashes.iter().map(|x| b64_decode(x)).collect();
    let db = db.iter().map(|(k, v)| (b64_decode2(k), (b64_decode(&v.0), b64_decode(&v.1)))).collect();
    VanillaSparseMerkleTree{
        depth,
        empty_tree_hashes, 
        db,
        hash_params,
        root
    }
}

