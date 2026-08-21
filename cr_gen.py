#!/usr/bin/env python3
"""
Challenge-Response (CR) Pair & Hash Chain Generator for HeVerSa Protocol.

Generates:
  - PUF_CHAIN_TA: Trusted Authority challenge-response chains per client
  - PUF_CHAIN_SRV: Aggregation Server challenge-response chain

"""

import sys
import os
import argparse
import hashlib
import random
from typing import List, Tuple

class PureLFSR:
    """128-bit Fibonacci LFSR with polynomial taps [128, 126, 101, 99]."""
    def __init__(self, init_state: int):
        self.state = init_state if init_state != 0 else 1

    def step(self) -> int:
        fb = ((self.state >> 127) ^ (self.state >> 125) ^ (self.state >> 100) ^ (self.state >> 98)) & 1
        self.state = ((self.state << 1) | fb) & ((1 << 128) - 1)
        return fb

    def run_k_cycles(self, k: int) -> int:
        for _ in range(k):
            self.step()
        return self.state


class PureArbiterPUF:
    """Additive linear delay model for a single Arbiter PUF."""
    def __init__(self, n: int = 128, seed: int = 123):
        self.n = n
        rng = random.Random(seed)
        self.weights = [rng.gauss(0.0, 1.0) for _ in range(n + 1)]

    def eval_bits(self, challenge_int: int) -> int:
        total_delay = self.weights[0]
        prod = 1
        for i in range(self.n):
            bit = (challenge_int >> (self.n - 1 - i)) & 1
            c_val = 1 if bit == 0 else -1
            prod *= c_val
            total_delay += self.weights[i + 1] * prod
        return 1 if total_delay > 0 else 0


class PureXORArbiterPUF:
    """k-XOR Arbiter PUF."""
    def __init__(self, n: int = 128, k: int = 6, seed: int = 123):
        self.n = n
        self.k = k
        self.arbiters = [PureArbiterPUF(n=n, seed=seed + i * 10007) for i in range(k)]

    def eval_response(self, challenge_int: int) -> int:
        res = 0
        for arb in self.arbiters:
            res ^= arb.eval_bits(challenge_int)
        return res


def get_puf_evaluator(n: int, k: int, seed: int, force_pure: bool = False):
    """Returns a callable that evaluates 128 challenge cycles to produce a 128-bit response."""
    if not force_pure:
        try:
            import numpy as np
            from pylfsr import LFSR
            from pypuf.simulation import XORArbiterPUF

            puf = XORArbiterPUF(n=n, k=k, seed=seed)

            def eval_pypuf(challenge_int: int) -> int:
                chal_bits = np.array([(challenge_int >> (127 - i)) & 1 for i in range(128)], dtype=np.uint8)
                fpoly = [128, 126, 101, 99]
                lfsr = LFSR(fpoly=fpoly, initstate=chal_bits)
                real_chals = []
                for _ in range(n):
                    bits = lfsr.runKCycle(128)
                    real_chals.append(np.array([1 if b == 1 else -1 for b in bits], dtype=np.int8))
                resp_pm1 = puf.eval(np.array(real_chals))
                resp_bits = [1 if b == 1 else 0 for b in resp_pm1]
                val = 0
                for b in resp_bits:
                    val = (val << 1) | b
                return val

            return eval_pypuf
        except ImportError:
            pass

    puf_pure = PureXORArbiterPUF(n=n, k=k, seed=seed)

    def eval_pure(challenge_int: int) -> int:
        lfsr = PureLFSR(challenge_int)
        resp_val = 0
        for _ in range(n):
            c_int = lfsr.run_k_cycles(128)
            bit = puf_pure.eval_response(c_int)
            resp_val = (resp_val << 1) | bit
        return resp_val

    return eval_pure


def derive_next_challenge(resp_int: int) -> int:
    """Derives the next 128-bit challenge from the SHA-256 hash of the response."""
    resp_bytes = resp_int.to_bytes(16, byteorder='big')
    digest = hashlib.sha256(resp_bytes).digest()
    return int.from_bytes(digest[:16], byteorder='big')


def format_uint128(val_int: int) -> str:
    """Formats a 128-bit integer into a C++ UInt128 initializer."""
    w0 = val_int & 0xFFFFFFFF
    w1 = (val_int >> 32) & 0xFFFFFFFF
    w2 = (val_int >> 64) & 0xFFFFFFFF
    w3 = (val_int >> 96) & 0xFFFFFFFF
    return f"UInt128{{0x{w0:08X}, 0x{w1:08X}, 0x{w2:08X}, 0x{w3:08X}}}"


def generate_ta_chain(eval_fn, num_clients: int, chain_len: int, base_seed: int) -> str:
    """Generates C++ array for the TA PUF chains."""
    lines = [f"const UInt128 PUF_CHAIN_TA[MAX_NUM_CLIENTS][CHAIN_LEN] = {{"]
    for c in range(num_clients):
        lines.append(f"    // Client {c}")
        lines.append("    {")
        challenge = (base_seed ^ (c * 0x5DEECE66D)) & ((1 << 128) - 1)
        if challenge == 0:
            challenge = 1
        for _ in range(chain_len):
            resp = eval_fn(challenge)
            lines.append(f"        {format_uint128(resp)},")
            challenge = derive_next_challenge(resp)
        lines.append("    },")
    lines.append("};")
    return "\n".join(lines)


def generate_srv_chain(eval_fn, chain_len: int, seed_val: int) -> str:
    """Generates C++ array for the Server PUF chain."""
    lines = ["const UInt128 PUF_CHAIN_SRV[CHAIN_LEN] = {"]
    challenge = seed_val if seed_val != 0 else 1
    for _ in range(chain_len):
        resp = eval_fn(challenge)
        lines.append(f"    {format_uint128(resp)},")
        challenge = derive_next_challenge(resp)
    lines.append("};")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Generate C++ Challenge-Response header (puf_data.h) for the HeVerSa Protocol."
    )
    parser.add_argument("-N", "--num-clients", type=int, default=10, help="Number of clients (default: 10)")
    parser.add_argument("-L", "--chain-len", type=int, default=100, help="Chain length per client (default: 100)")
    parser.add_argument("-S", "--puf-size", type=int, default=128, help="PUF response size in bits (default: 128)")
    parser.add_argument("-k", "--k-xor", type=int, default=6, help="Number of XOR Arbiter stages (default: 6)")
    parser.add_argument("--seed-ta", type=lambda x: int(x, 0), default=0xCAFEBABE, help="Seed for TA chain (default: 0xCAFEBABE)")
    parser.add_argument("--seed-srv", type=lambda x: int(x, 0), default=0xDEADBEEF, help="Seed for Server chain (default: 0xDEADBEEF)")
    parser.add_argument("-o", "--output", type=str, default="src/puf_data.h", help="Output header path (default: src/puf_data.h)")
    parser.add_argument("--pure", action="store_true", help="Force built-in pure Python PUF simulator")

    args = parser.parse_args()

    print(f"[CR_GEN] Generating PUF Data: Clients={args.num_clients}, ChainLen={args.chain_len}, PUF_Size={args.puf_size} bits")

    eval_ta = get_puf_evaluator(n=args.puf_size, k=args.k_xor, seed=123, force_pure=args.pure)
    eval_srv = get_puf_evaluator(n=args.puf_size, k=args.k_xor, seed=456, force_pure=args.pure)

    ta_code = generate_ta_chain(eval_ta, args.num_clients, args.chain_len, args.seed_ta)
    srv_code = generate_srv_chain(eval_srv, args.chain_len, args.seed_srv)

    header_content = f"""#ifndef PUF_DATA_H
#define PUF_DATA_H

#include "common.h"

// --- DEFINITIONS ---
#ifndef CHAIN_LEN
#define CHAIN_LEN {args.chain_len}
#endif

#ifndef PUF_SIZE_BYTE
#define PUF_SIZE_BYTE {args.puf_size // 8}
#endif

// ---------------- TRUSTED AUTHORITY CHAIN ----------------
{ta_code}

// ---------------- SERVER CHAIN ----------------
{srv_code}

#endif // PUF_DATA_H
"""

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(header_content)

    print(f"[CR_GEN] Successfully generated: {args.output}")


if __name__ == "__main__":
    main()