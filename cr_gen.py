import numpy as np
import hashlib
from pylfsr import LFSR
from pypuf.simulation import XORArbiterPUF

# length of the chain
CHAIN_LEN = 100

# size of the puf challenge/response
PUF_SIZE = 128

# converts pypuf bits to binary
def pypuf_to_binary(bits):
    return np.array([1 if b == 1 else 0 for b in bits], dtype=np.uint8)

# converts binary bits to pypuf format
def binary_to_pypuf(bits):
    return np.array([1 if b == 1 else -1 for b in bits], dtype=np.int8)

def bits_to_int(bits):
    return int("".join(str(int(b)) for b in bits), 2)

def derive_next_challenge(resp_bits):
    digest = hashlib.sha256(bytes(resp_bits)).digest()
    bits = np.array([int(b) for byte in digest[:16] for b in f"{byte:08b}"], dtype=np.uint8)
    return bits

#lfsr to expand the challenge and evaluate the puf
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

def generate_c_array(name, puf, seed_val):
    challenge_bits = np.array([int(b) for b in f"{seed_val:0128b}"], dtype=np.uint8)
    
    # convert to _BitInt(128); we'll get an array. C23 needed; supported in CLANG or GCC > 14
    c_str = f"const unsigned _BitInt(128) {name}[{CHAIN_LEN}] = {{\n"
    
    for _ in range(CHAIN_LEN):
        resp_bits = lfsr_expand_and_eval(puf, challenge_bits)
        val_int = bits_to_int(resp_bits)
        c_str += f"    0x{val_int:032X}uwb,\n"
        
        challenge_bits = derive_next_challenge(resp_bits)
        
    c_str += "};\n"
    return c_str

if __name__ == "__main__":
    puf_ta = XORArbiterPUF(n=128, k=6, seed=123)
    puf_srv = XORArbiterPUF(n=128, k=6, seed=456)

    header = f"""#ifndef PUF_DATA_H
#define PUF_DATA_H

#define CHAIN_LEN {CHAIN_LEN}
#define PUF_SIZE_BYTE 16

// ---------------- TRUSTED AUTHORITY CHAIN ----------------
{generate_c_array("PUF_CHAIN_TA", puf_ta, seed_val=0xCAFEBABE)}

// ---------------- SERVER CHAIN ----------------
{generate_c_array("PUF_CHAIN_SRV", puf_srv, seed_val=0xDEADBEEF)}

#endif
"""
    with open("src/puf_data.h", "w") as f:
        f.write(header)
    
    print("Done.")