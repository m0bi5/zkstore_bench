use pyo3::prelude::*;
use pyo3::wrap_pyfunction;
use rand::{rngs::OsRng};
use schnorrkel::{Keypair, Signature, signing_context, PublicKey, SecretKey};
use base64::{encode, decode};

//32 bytes, 64rust bytes
#[pyfunction]
fn key_gen(_lambda: u8) -> PyResult<(String, String)> {
    let keypair: Keypair = Keypair::generate_with(OsRng);
    let sk = encode(keypair.secret.to_bytes().to_vec());
    let pk = encode(keypair.public.to_bytes().to_vec());
    Ok((pk, sk))
}

//64 bytes
#[pyfunction]
fn sig(sk: String, pk: String, m: String) -> PyResult<String> {
    let context = signing_context(b"ZKSTORE_SIGNATURE");
    let sk = decode(sk).unwrap();
    let pk = decode(pk).unwrap();
    let m = decode(m).unwrap();
    let sk = SecretKey::from_bytes(&sk).unwrap();
    let pk = PublicKey::from_bytes(&pk).unwrap();
    let sigma = sk.sign(context.bytes(&m), &pk).to_bytes().to_vec();
    Ok(encode(sigma))
}

#[pyfunction]
fn vrfy(pk: String, sigma: String, m: String) -> PyResult<bool> {
    let context = signing_context(b"ZKSTORE_SIGNATURE");
    let pk = decode(pk).unwrap();
    let sigma = decode(sigma).unwrap();
    let m = decode(m).unwrap();
    let pk = PublicKey::from_bytes(&pk).unwrap();
    let sigma = Signature::from_bytes(&sigma).unwrap();
    Ok(pk.verify(context.bytes(&m), &sigma).is_ok())
}

#[pymodule]
fn rust_schnorr(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(key_gen, m)?)?;
    m.add_function(wrap_pyfunction!(sig, m)?)?;
    m.add_function(wrap_pyfunction!(vrfy, m)?)?;
    Ok(())
}