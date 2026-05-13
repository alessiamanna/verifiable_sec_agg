import numpy as np
import hashlib
from pylfsr import LFSR
from pypuf.simulation import XORArbiterPUF

CHAIN_LEN = 100
PUF_SIZE = 128
MAX_NUM_CLIENTS = 4

def pypuf_to_binary(bits):
    return np.array([1 if b == 1 else 0 for b in bits], dtype=np.uint8)

def binary_to_pypuf(bits):
    return np.array([1 if b == 1 else -1 for b in bits], dtype=np.int8)

def bits_to_int(bits):
    return int("".join(str(int(b)) for b in bits), 2)

def derive_next_challenge(resp_bits):
    digest = hashlib.sha256(bytes(resp_bits)).digest()
    bits = np.array([int(b) for byte in digest[:16] for b in f"{byte:08b}"], dtype=np.uint8)
    return bits

def lfsr_expand_and_eval(puf, challenge_bits):
    fpoly = [128, 126, 101, 99]
    lfsr = LFSR(fpoly=fpoly, initstate=challenge_bits)
    real_challenges = []
    for _ in range(PUF_SIZE):
        bits = lfsr.runKCycle(128) 
        real_challenges.append(binary_to_pypuf(bits))
    real_challenges = np.array(real_challenges) 
    resp_pm1 = puf.eval(real_challenges)
    return pypuf_to_binary(resp_pm1)

def generate_cpp_array_ta(name, puf, seed_val):
    challenge_bits = np.array([int(b) for b in f"{seed_val:0128b}"], dtype=np.uint8)
    
    c_str = f"const UInt128 {name}[MAX_NUM_CLIENTS][CHAIN_LEN] = {{\n"
    for _ in range(MAX_NUM_CLIENTS):
        c_str += "    {\n"
        for _ in range(CHAIN_LEN):
            resp_bits = lfsr_expand_and_eval(puf, challenge_bits)
            val_int = bits_to_int(resp_bits)
            
            w0 = val_int & 0xFFFFFFFF
            w1 = (val_int >> 32) & 0xFFFFFFFF
            w2 = (val_int >> 64) & 0xFFFFFFFF
            w3 = (val_int >> 96) & 0xFFFFFFFF
            
            c_str += f"        UInt128{{0x{w0:08X}, 0x{w1:08X}, 0x{w2:08X}, 0x{w3:08X}}},\n"
            challenge_bits = derive_next_challenge(resp_bits)
        c_str += "    },\n"
    c_str += "};\n"
    return c_str

def generate_cpp_array_srv(name, puf, seed_val):
    challenge_bits = np.array([int(b) for b in f"{seed_val:0128b}"], dtype=np.uint8)
    
    c_str = f"const UInt128 {name}[CHAIN_LEN] = {{\n"
    for _ in range(CHAIN_LEN):
        resp_bits = lfsr_expand_and_eval(puf, challenge_bits)
        val_int = bits_to_int(resp_bits)
        
        w0 = val_int & 0xFFFFFFFF
        w1 = (val_int >> 32) & 0xFFFFFFFF
        w2 = (val_int >> 64) & 0xFFFFFFFF
        w3 = (val_int >> 96) & 0xFFFFFFFF
        
        c_str += f"    UInt128{{0x{w0:08X}, 0x{w1:08X}, 0x{w2:08X}, 0x{w3:08X}}},\n"
        challenge_bits = derive_next_challenge(resp_bits)
    c_str += "};\n"
    return c_str

if __name__ == "__main__":
    puf_ta = XORArbiterPUF(n=128, k=6, seed=123)
    puf_srv = XORArbiterPUF(n=128, k=6, seed=456)

    header = f"""#ifndef PUF_DATA_H
#define PUF_DATA_H

#include "common.h"

// --- DEFINITIONS ---
#define CHAIN_LEN 100
#define MAX_NUM_CLIENTS 4
#define PUF_SIZE_BYTE 16

// ---------------- TRUSTED AUTHORITY CHAIN ----------------
{generate_cpp_array_ta("PUF_CHAIN_TA", puf_ta, seed_val=0xCAFEBABE)}

// ---------------- SERVER CHAIN ----------------
{generate_cpp_array_srv("PUF_CHAIN_SRV", puf_srv, seed_val=0xDEADBEEF)}

#endif
"""
    with open("src/puf_data.h", "w") as f:
        f.write(header)
    
    print("Done.")
