use pyo3::prelude::*;
use pyo3::wrap_pyfunction;
use ecies::{encrypt, decrypt, utils::generate_keypair};
use base64::{encode, decode};

#[pyfunction]
fn key_gen(_lambda: u8) -> PyResult<(String, String)> {
    let (sk, pk) = generate_keypair();
    let (sk, pk) = (&sk.serialize(), &pk.serialize());
    let pk_s = encode(pk.to_vec());
    let sk_s = encode(sk.to_vec());

    Ok((pk_s, sk_s))
}

#[pyfunction]
fn enc(pk: String, m: String) -> PyResult<String> {
    let c = &encrypt(&decode(pk).unwrap(), &decode(m).unwrap()).unwrap();
    Ok(encode(&c.to_vec()))
}

#[pyfunction]
fn dec(sk: String, c: String) -> PyResult<String> {
    let m = &decrypt(&decode(sk).unwrap(), &decode(c).unwrap()).unwrap();
    Ok(encode(m.to_vec()))
}

#[pymodule]
fn rust_ecies(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(key_gen, m)?)?;
    m.add_function(wrap_pyfunction!(enc, m)?)?;
    m.add_function(wrap_pyfunction!(dec, m)?)?;
    Ok(())
}