# BTCKEY Brute Force. Brute force the private key of Bitcoin (BTC) Public address.
# This is ofcourse pointless to run. But I knooooow you thought about it because you are here. 

import secrets
import hashlib
import ecdsa
import base58
import time
import multiprocessing
import sys

def generate_private_key():
    """Generates a random 256-bit private key."""
    private_key = secrets.token_bytes(32)
    return private_key

def derive_public_key(private_key):
    """Derives the public key from the private key using ECDSA."""
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    public_key = vk.to_string()
    # Ensure the y-coordinate is even
    compressed_public_key = b'\x02' + bytes.fromhex(public_key.hex())[:32]
    return compressed_public_key

def generate_bitcoin_address(public_key):
    """Generates a Bitcoin address from the public key."""
    public_key_hash = hashlib.new('ripemd160', hashlib.sha256(public_key).digest()).digest()
    # Add version byte (0x00 for mainnet)
    address_version = b'\x00' + public_key_hash
    checksum = hashlib.sha256(hashlib.sha256(address_version).digest()).digest()[:4]
    address_final = address_version + checksum
    bitcoin_address = base58.b58encode(address_final).decode()
    return bitcoin_address

def brute_force_task(bitcoin_address, task_id, attempts_per_process, result_queue):
    """Worker function for the multiprocessing pool."""
    attempts = 0
    start_time = time.time()
    while attempts < attempts_per_process:
        attempts += 1
        private_key = generate_private_key()
        public_key = derive_public_key(private_key)
        address = generate_bitcoin_address(public_key)
        if address == bitcoin_address:
          end_time = time.time()
          result =  {"status": "found", "attempts":attempts, "time": end_time-start_time, "private_key": private_key.hex(), "public_key": public_key.hex(), "address": address, "task_id": task_id}
          result_queue.put(result)
          return result # Return if found
        if attempts % 10000 == 0:
           elapsed_time = time.time() - start_time
           print (f"Task ID: {task_id}. Attempting {attempts}... Time elapsed: {elapsed_time:.2f} seconds")
    result = {"status": "not found", "attempts":attempts, "time": time.time()-start_time, "task_id": task_id}
    result_queue.put(result)
    return result # Return not found

def attempt_brute_force_multithreaded(bitcoin_address, num_processes, attempts_per_process):
    """Attempts to find the private key using multiple processes."""
    start_time = time.time()
    processes = []
    result_queue = multiprocessing.Queue()
    for i in range(num_processes):
        process = multiprocessing.Process(target=brute_force_task, args=(bitcoin_address, i, attempts_per_process, result_queue))
        processes.append(process)
        process.start()

    for process in processes:
      process.join() #wait for them to finish

    results = []
    while not result_queue.empty():
        results.append(result_queue.get())

    end_time = time.time()
    total_time = end_time - start_time
    print (f"Total Time: {total_time:.2f} seconds")
    for result in results:
      if result["status"] == "found":
        print(f"Private Key Found by Task ID: {result['task_id']} after {result['attempts']} attempts!")
        print(f"Time taken: {result['time']:.2f} seconds")
        print(f"Private Key (Hex): {result['private_key']}")
        print(f"Public Key (Hex): {result['public_key']}")
        print (f"Bitcoin Address (Base58): {result['address']}")
        return result['private_key'] #exit if one is found
    return None

# Target Bitcoin address

if len(sys.argv) != 2:  # Ensure exactly one argument is provided
   print("Usage: python run.py <bitcoin_address>")
   sys.exit(1)
bitcoin_address = sys.argv[1]  # Get the user input from the command line
donation_address = "16CowvxvLSR4BPEP9KJZiR622UU7hGEce5"
num_processes = 8  # Number of CPU cores to use
attempts_per_process = 1000000 #number of attempts per process

print(f"Beginning multi-threaded brute force on address: {bitcoin_address}...")
# Attempt to derive the private key
private_key = attempt_brute_force_multithreaded(bitcoin_address, num_processes, attempts_per_process)
if private_key:
   print (f"Target address private key {private_key}")
else:
  print ("Private key not found.")
