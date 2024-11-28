use rayon::prelude::*;
use ed25519_dalek::Keypair;
use rand::rngs::OsRng;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;
use std::io::{self, Write};
use reqwest::Client;
use serde_json::json;
use tokio::sync::mpsc;

const BATCH_PER_THREAD: usize = 10_000;
const TARGET1: &[u8] = b"martin";
const TARGET2: &[u8] = b"helio";
const API_ENDPOINT: &str = "fake";
const BEARER_TOKEN: &str = "fake";
const BATCH_SIZE: usize = 2;

#[inline(always)]
fn check_suffix(bytes: &[u8]) -> bool {
    if bytes.len() < TARGET1.len() { return false; }
    bytes[..TARGET1.len()] == *TARGET1 || 
    bytes[..TARGET2.len()] == *TARGET2
}

#[tokio::main]
async fn main() {
    println!("Starting Solana vanity address generator (Pure Rust)");
    println!("Looking for addresses ending with 'moon'");
    
    let start_time = Instant::now();
    let num_threads = rayon::current_num_threads();
    let results = Arc::new(parking_lot::Mutex::new(Vec::<(String, String)>::with_capacity(10)));
    let found_count = Arc::new(AtomicUsize::new(0));
    let attempts_count = Arc::new(AtomicUsize::new(0));
    let last_success_check = Arc::new(parking_lot::Mutex::new(Instant::now()));
    let last_success_count = Arc::new(AtomicUsize::new(0));
    let client = Client::new();
    
    let (tx, mut rx) = mpsc::channel(100);
    
    // Spawn API handler task
    let api_handle = tokio::spawn(async move {
        let mut batch = Vec::with_capacity(BATCH_SIZE);
        let client = Client::new();
        
        while let Some(key) = rx.recv().await {
            batch.push(key);
            
            if batch.len() >= BATCH_SIZE {
                let payload = json!({
                    "mintAddresses": &batch,
                    "blockchainSymbol": "SOL"
                });

                println!("Request payload: {}", serde_json::to_string_pretty(&payload).unwrap());

                let res = client.post(API_ENDPOINT)
                    .header("Authorization", format!("Bearer {}", BEARER_TOKEN))
                    .json(&payload)
                    .send()
                    .await;
                
                match res {
                    Ok(response) => {
                        let status = response.status();
                        let body = response.text().await.unwrap_or_else(|e| format!("Failed to get response body: {}", e));
                        println!("Response status: {}", status);
                        println!("Response body: {}", body);
                    }
                    Err(e) => eprintln!("Failed to send addresses: {}", e),
                }
                
                batch.clear();
            }
        }
    });

    ctrlc::set_handler(move || {
        println!("\nStopping...");
        std::process::exit(0);
    }).expect("Error setting Ctrl-C handler");

    let tx = Arc::new(parking_lot::Mutex::new(tx));

    (0..num_threads).into_par_iter().for_each(|_| {
        let mut local_results = Vec::with_capacity(2);
        let mut csprng = OsRng;
        let mut pubkey_bytes = [0u8; 32];
        let tx = tx.clone();
        
        loop {
            for _ in 0..BATCH_PER_THREAD {
                let keypair = Keypair::generate(&mut csprng);
                pubkey_bytes.copy_from_slice(&keypair.public.to_bytes());
                
                let pubkey_str = bs58::encode(&pubkey_bytes).into_string();
                if !check_suffix(pubkey_str.as_bytes()) { continue; }
                
                let secret_key = bs58::encode(&keypair.secret.to_bytes()).into_string();
                println!("\nFound matching address!");
                println!("Public key: {}", pubkey_str);
                println!("Private key: {}", secret_key);
                
                let mut phantom_bytes = Vec::with_capacity(64);
                phantom_bytes.extend_from_slice(&keypair.secret.to_bytes());
                phantom_bytes.extend_from_slice(&keypair.public.to_bytes());
                
                let phantom_key = bs58::encode(&phantom_bytes).into_string();
                println!("Phantom private key: {}", phantom_key);
                
                local_results.push((pubkey_str, secret_key.clone()));
                found_count.fetch_add(1, Ordering::Relaxed);

                if let Err(e) = tx.lock().try_send(phantom_key) {
                    eprintln!("Failed to send key to API handler: {}", e);
                }
            }

            attempts_count.fetch_add(BATCH_PER_THREAD, Ordering::Relaxed);
            let total_attempts = attempts_count.load(Ordering::Relaxed);
            
            if total_attempts % 500_000 == 0 {
                let elapsed = start_time.elapsed().as_secs_f64();
                print!("\rTried {} addresses... ({:.0}/sec)", 
                    total_attempts, total_attempts as f64 / elapsed);
                io::stdout().flush().unwrap();

                let mut last_check = last_success_check.lock();
                if last_check.elapsed().as_secs() >= 300 {
                    let current_found = found_count.load(Ordering::Relaxed);
                    let success_since_last = current_found - last_success_count.load(Ordering::Relaxed);
                    println!("\nLast 5 minutes: {} successful keypairs ({:.2} per minute)", 
                        success_since_last, success_since_last as f64 / 5.0);
                    
                    last_success_count.store(current_found, Ordering::Relaxed);
                    *last_check = Instant::now();
                }
            }
        }
    });

    let total_attempts = attempts_count.load(Ordering::Relaxed);
    let elapsed = start_time.elapsed().as_secs_f64();
    println!("\n\nFinished!");
    println!("Total attempts: {}", total_attempts);
    println!("Average speed: {:.0} addresses/sec", total_attempts as f64 / elapsed);
    
    drop(tx);
    api_handle.await.unwrap();
} 