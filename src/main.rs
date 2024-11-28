use rayon::prelude::*;
use ed25519_dalek::Keypair;
use rand::rngs::OsRng;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;
use std::io::{self, Write};

const BATCH_PER_THREAD: usize = 10_000;
const TARGET: &[u8] = b"moon";

#[inline(always)]
fn check_suffix(bytes: &[u8]) -> bool {
    if bytes.len() < TARGET.len() { return false; }
    bytes[bytes.len() - TARGET.len()..] == *TARGET
}

fn main() {
    println!("Starting Solana vanity address generator (Pure Rust)");
    println!("Looking for addresses ending with 'moon'");
    
    let start_time = Instant::now();
    let num_threads = rayon::current_num_threads();
    let results = Arc::new(parking_lot::Mutex::new(Vec::with_capacity(10)));
    let found_count = Arc::new(AtomicUsize::new(0));
    let attempts_count = Arc::new(AtomicUsize::new(0));
    
    ctrlc::set_handler(move || {
        println!("\nStopping...");
        std::process::exit(0);
    }).expect("Error setting Ctrl-C handler");

    (0..num_threads).into_par_iter().for_each(|_| {
        let mut local_results = Vec::with_capacity(2);
        let mut csprng = OsRng;
        let mut pubkey_bytes = [0u8; 32];
        let mut local_attempts = 0;
        
        'outer: loop {
            for _ in 0..BATCH_PER_THREAD {
                let keypair = Keypair::generate(&mut csprng);
                pubkey_bytes.copy_from_slice(&keypair.public.to_bytes());
                local_attempts += 1;
                
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
                
                local_results.push((pubkey_str, secret_key));
                
                if found_count.fetch_add(1, Ordering::Relaxed) >= 9 {
                    attempts_count.fetch_add(local_attempts, Ordering::Relaxed);
                    break 'outer;
                }
            }
            
            if found_count.load(Ordering::Relaxed) >= 9 {
                attempts_count.fetch_add(local_attempts, Ordering::Relaxed);
                break;
            }

            attempts_count.fetch_add(BATCH_PER_THREAD, Ordering::Relaxed);
            let total_attempts = attempts_count.load(Ordering::Relaxed);
            
            if total_attempts % 500_000 == 0 {
                let elapsed = start_time.elapsed().as_secs_f64();
                print!("\rTried {} addresses... ({:.0}/sec)", 
                    total_attempts, total_attempts as f64 / elapsed);
                io::stdout().flush().unwrap();
            }
        }
        
        if !local_results.is_empty() {
            results.lock().extend(local_results);
        }
    });

    let total_attempts = attempts_count.load(Ordering::Relaxed);
    let elapsed = start_time.elapsed().as_secs_f64();
    println!("\n\nFinished!");
    println!("Total attempts: {}", total_attempts);
    println!("Average speed: {:.0} addresses/sec", total_attempts as f64 / elapsed);
} 