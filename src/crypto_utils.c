#include <openssl/hmac.h>
#include <openssl/evp.h>
#include "common.h"


void calc_hmac_sha256(const uint8_t* data, size_t data_len, const uint8_t* key, size_t key_len, hmac_t out_mac) {
    unsigned int mac_len = SHA256_DIGEST;
    printf("[DEBUG HMAC] Calculating HMAC-SHA256\n");
    HMAC(EVP_sha256(), 
         key, key_len, 
         data, data_len, 
         out_mac, &mac_len);
}