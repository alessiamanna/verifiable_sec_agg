#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <string.h>
#include "crypto_utils.h"


void calc_hmac_sha256(const uint8_t* data, size_t data_len, const uint8_t* key, size_t key_len, hmac_t out_mac) {
    unsigned int mac_len = SHA256_DIGEST;
 
    HMAC(EVP_sha256(), 
         key, key_len, 
         data, data_len, 
         out_mac, &mac_len);
}

bool verify_hmac(uint8_t *hmac1, uint8_t *hmac2){
    return memcmp(hmac1, hmac2, SHA256_DIGEST) == 0;
}

void sign_payload(payload_t p1, payload_t p2, puf_resp_t key, uint8_t *out_mac){
    uint8_t hash_buff[sizeof(payload_t) * 2];
    memcpy(hash_buff, &p1, sizeof(payload_t));
    memcpy(hash_buff + sizeof(payload_t), &p2, sizeof(payload_t));

    calc_hmac_sha256(hash_buff, sizeof(hash_buff), (uint8_t*)&key, sizeof(puf_resp_t), out_mac);
}

void sign_node_set(node_set_t *set, puf_resp_t key, uint8_t *out_mac){
   calc_hmac_sha256((uint8_t*)set, sizeof(node_set_t), (uint8_t*)&key, sizeof(puf_resp_t), out_mac);
}

void sign_shares_list(share_item_t* items, size_t count, puf_resp_t key, hmac_t out_mac) {
    size_t payload_size = count * sizeof(share_item_t);
    calc_hmac_sha256((uint8_t*)items, payload_size, (uint8_t*)&key, sizeof(puf_resp_t), out_mac);
}