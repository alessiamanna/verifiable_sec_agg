#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include "common.h"
#include "common_share.h"
#include "puf_data.h"


//wraps the HMAC sha256 implementation of the library
void calc_hmac_sha256(const uint8_t* data, size_t data_len, const uint8_t* key, size_t key_len, hmac_t out_mac);

//function to verify if the HMACs match
bool verify_hmac(hmac_t hmac1, hmac_t hmac2);

void generate_expanded_mask(UInt128 seed, size_t M, uint16_t* out_mask);
//wrappers to handle the protocol messages 
void sign_payload(update_t* p1, update_t* p2, puf_resp_t key, hmac_t out_mac);
void sign_node_set(node_set_t* set, puf_resp_t key, hmac_t out_mac);
void sign_shares_list(share_item_t* items, size_t count, puf_resp_t key, hmac_t out_mac);

#endif