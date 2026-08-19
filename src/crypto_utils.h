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
// ECC consistency check helpers
void ecc_generate_cc(ecc_point_t out_G1, ecc_point_t out_G2, ecc_scalar_t out_Scc1, ecc_scalar_t out_Scc2);
void hash_node_set_sha256(const node_set_t* set, uint8_t out_hash[SHA256_DIGEST]);
void ecc_shamir_create_shares(const ecc_scalar_t secret, int n, int k, ecc_scalar_t out_shares[MAX_NUM_CLIENTS]);
void ecc_shamir_interpolate_at_zero(const node_id_t* node_ids, const ecc_scalar_t* shares, int k, ecc_scalar_t out_secret);
void ecc_scalar_mul_add_mod(const ecc_scalar_t h, const ecc_scalar_t y, const ecc_scalar_t z, ecc_scalar_t out);
bool ecc_verify_cc(const ecc_point_t G1, const ecc_point_t G2, const ecc_scalar_t h, const ecc_scalar_t W);

#endif