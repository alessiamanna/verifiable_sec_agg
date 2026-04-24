#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <string.h>
#include "crypto_utils.h"
#include "common.h"


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


void sign_payload(update_t* p1, update_t* p2, puf_resp_t key, uint8_t *out_mac){
    size_t single_array_size = sizeof(update_t) * UPDATE_LEN;  
    size_t total_size = single_array_size * 2;                  
    
    uint8_t hash_buff[sizeof(update_t) * UPDATE_LEN * 2];      
    
    memcpy(hash_buff, p1, single_array_size);                  
    memcpy(hash_buff + single_array_size, p2, single_array_size);
    
    calc_hmac_sha256(hash_buff, total_size, (uint8_t*)&key, sizeof(puf_resp_t), out_mac);
}

void sign_node_set(node_set_t *set, puf_resp_t key, uint8_t *out_mac){
   calc_hmac_sha256((uint8_t*)set, sizeof(node_set_t), (uint8_t*)&key, sizeof(puf_resp_t), out_mac);
}

void sign_shares_list(share_item_t* items, size_t count, puf_resp_t key, hmac_t out_mac) {
    size_t payload_size = count * sizeof(share_item_t);
    calc_hmac_sha256((uint8_t*)items, payload_size, (uint8_t*)&key, sizeof(puf_resp_t), out_mac);
}