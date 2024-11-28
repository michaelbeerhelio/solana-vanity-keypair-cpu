import time
from vanity_search import search_batch_rust
from based58 import b58encode, b58decode
import multiprocessing

def main():
    print("Starting Solana vanity address generator (CPU-optimized)")
    print("Looking for addresses ending with 'moon'")
    print(f"Using {multiprocessing.cpu_count()} CPU cores")
    
    cpu_count = multiprocessing.cpu_count()
    batch_size = 500_000 // cpu_count
    attempts = 0
    start_time = time.time()
    
    try:
        while True:
            results = search_batch_rust(batch_size)
            attempts += batch_size
            
            for pub_key, priv_key_bytes in results:
                pub_key_bytes = b58decode(pub_key)
                phantom_key = bytes(priv_key_bytes) + pub_key_bytes  # Convert list to bytes before concatenating
                secret_key = b58encode(phantom_key).decode('ascii')
                print(f"\nFound matching address in batch of {attempts:,} attempts!")
                print(f"Public key: {pub_key}")
                print(f"Private key (Phantom format): {secret_key}")

            if attempts % 1_000_000 == 0:
                print(f"Tried {attempts:,} addresses... ({attempts/(time.time() - start_time):.0f}/sec)")

    except KeyboardInterrupt:
        print(f"\nStopped after {attempts:,} attempts")
        print(f"Average speed: {attempts/(time.time() - start_time):.0f} addresses/sec")

if __name__ == "__main__":
    main()