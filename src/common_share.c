#include <stdio.h>
#include <string.h>

#include "common.h"
#include "puf_data.h"
#include "puf_utils.h"
#include "sss/sss.h"
#include "common_share.h"

protocol_key_t get_shared_key(node_id_t helper_node, node_id_t target_node){
    return (protocol_key_t)helper_node ^ (protocol_key_t)target_node ^ 0xCAFEBABE;
}

void compute_share_h(puf_resp_t puf_link, protocol_key_t key, uint8_t* out_share) {
    memset(out_share, 0, sss_SHARE_LEN);

    private_key_t seed_hash = calc_hmac_sign(&puf_link, sizeof(puf_resp_t), (private_key_t)key);

    uint64_t current_val = (uint64_t)seed_hash; 

    //mi serve espandere a 113byte
    for(int i = 0; i < sss_SHARE_LEN; i++) {
        current_val = current_val * 6364136223846793005ULL + 1442695040888963407ULL;
        out_share[i] = (uint8_t)(current_val >> 56);
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