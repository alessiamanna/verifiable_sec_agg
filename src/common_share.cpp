#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "common.h"
#include "puf_data.h"
#include "puf_utils.h"
#include "sss/sss.h"
#include "common_share.h"
#include "crypto_utils.h"

protocol_key_t get_shared_key(node_id_t node_helper, node_id_t node_target) {
    return UInt128::from_uint32(node_helper) ^ 
           UInt128::from_uint32(node_target) ^ 
           UInt128::from_uint32(0xCAFEBABE);
}


void compute_share_h(puf_resp_t puf_link, protocol_key_t key, uint8_t* out_share, size_t out_len) {
    memset(out_share, 0, out_len);
    hmac_t seed_hash;
    calc_hmac_sha256((uint8_t*)&puf_link, sizeof(puf_resp_t), (uint8_t*)&key, sizeof(protocol_key_t), seed_hash);
   
    size_t copied = 0;
    while (copied < out_len) {
        size_t to_copy = (out_len - copied > SHA256_DIGEST) ? SHA256_DIGEST : (out_len - copied);
        memcpy(out_share + copied, seed_hash, to_copy);
        copied += to_copy;

        if (copied < out_len) {
            hmac_t next_hash;
            calc_hmac_sha256(seed_hash, SHA256_DIGEST, (uint8_t*)&key, sizeof(protocol_key_t), next_hash);
            memcpy(seed_hash, next_hash, SHA256_DIGEST);
        }
    }
}

// sposta in utility
void print_hex_debug(const char* label, uint8_t* data, size_t len, uint32_t key) {
    printf("\n[DEBUG HMAC] %s\n", label);
    printf("   KEY (L4): 0x%X\n", key);
    printf("   LEN:      %zu bytes\n", len);
    printf("   DATA:     ");
    for(size_t i = 0; i < len; i++) {
        printf("%02X ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n             ");
    }
    printf("\n");
}