use pyo3::prelude::*;
use rayon::prelude::*;
use ed25519_dalek::Keypair;
use rand::rngs::OsRng;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

#[pyfunction]
fn search_batch_rust(batch_size: usize) -> Vec<(String, Vec<u8>)> {
    let chunk_size = 5000;
    let chunks = (0..batch_size).collect::<Vec<_>>()
        .chunks(chunk_size)
        .map(|_| chunk_size)
        .collect::<Vec<_>>();

    let results = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let found_count = Arc::new(AtomicUsize::new(0));
    
    chunks.par_iter()
        .for_each(|&size| {
            let mut local_results = Vec::new();
            let mut csprng = OsRng;
            
            for _ in 0..size {
                let keypair = Keypair::generate(&mut csprng);
                let pubkey = bs58::encode(&keypair.public.to_bytes()).into_string();
                
                if pubkey.ends_with("moon") {
                    let secret_key = keypair.secret.to_bytes().to_vec();
                    local_results.push((pubkey, secret_key));
                    found_count.fetch_add(1, Ordering::Relaxed);
                    
                    if found_count.load(Ordering::Relaxed) >= 10 {
                        break;
                    }
                }
            }
            
            if !local_results.is_empty() {
                results.lock().extend(local_results);
            }
        });
    
    Arc::try_unwrap(results)
        .unwrap()
        .into_inner()
}

#[pymodule]
fn vanity_search(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(search_batch_rust, m)?)?;
    Ok(())
} 