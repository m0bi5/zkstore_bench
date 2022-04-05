use pyo3::prelude::*;
use pyo3::wrap_pyfunction;
use curve25519_dalek::scalar::Scalar;
use std::{fs::File, io::{BufReader}};
use base64::encode;
use sha3::{Digest, Sha3_256};

pub fn mimc(
    xl: &Scalar,
    xr: &Scalar,
    constants: &[Scalar]
) -> Scalar
{
    assert_eq!(constants.len(), 322);

    let mut xl = xl.clone();
    let mut xr = xr.clone();

    for i in 0..322 {
        let tmp1 = xl + constants[i];
        let mut tmp2 = (tmp1 * tmp1) * tmp1;
        tmp2 += xr;
        xr = xl;
        xl = tmp2;
    }

    xl
}

pub fn clone_into_array<A, T>(slice: &[T]) -> A
    where A: Sized + Default + AsMut<[T]>,
          T: Clone
{
    let mut a = Default::default();
    <A as AsMut<[T]>>::as_mut(&mut a).clone_from_slice(slice);
    a
}

pub fn b64_encode(s: &Scalar) -> String{
    encode(s.to_bytes())
}

pub fn read_scalar_vec_from_str(vec: Vec<String>) -> Vec<Scalar>{
    let mut vec_scalar = vec![];
    for i in vec{
        vec_scalar.push(serde_json::from_str(&i).unwrap());
    }
    vec_scalar
}

pub fn scalarize(s: &str) -> Scalar{
    let mut hasher = Sha3_256::new();
    hasher.update(s.as_bytes());
    let result = hasher.finalize();
    Scalar::from_bytes_mod_order(clone_into_array(&result[..]))
}

#[pyfunction]
fn prf(in1: String, in2: String, mimc_constants: Vec<String>) -> PyResult<String> {
    let mimc2 = read_scalar_vec_from_str(mimc_constants);
    Ok(b64_encode(&mimc(&scalarize(&in1), &scalarize(&in2), &mimc2)))
}

#[pymodule]
fn rust_mimc(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(prf, m)?)?;
    Ok(())
}