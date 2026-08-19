#include <openssl/bn.h>
#include <openssl/ec.h>
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

void ecc_generate_cc(ecc_point_t out_G1, ecc_point_t out_G2, ecc_scalar_t out_Scc1, ecc_scalar_t out_Scc2){
    // questo è il gruppo G
    EC_GROUP *curve_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    BN_CTX *ctx = BN_CTX_new();

   
    BIGNUM *order = BN_new();
    EC_GROUP_get_order(curve_group, order, ctx);

    //mi devo calcolare Scc1 e Scc2 come bignum
    BIGNUM* Scc1 = BN_new();
    BIGNUM* Scc2 = BN_new();

    BN_rand_range(Scc1, order);
    BN_rand_range(Scc2, order);

    BN_bn2binpad(Scc1, out_Scc1, ECC_SCALAR_LEN);
    BN_bn2binpad(Scc2, out_Scc2, ECC_SCALAR_LEN);


    //  mi servono due punti sulla curva, G1 e G2 
    EC_POINT *P_G1 = EC_POINT_new(curve_group);
    EC_POINT *P_G2 = EC_POINT_new(curve_group);

    // G1 deve essere G*Scc1 e G2 deve essere G*Scc2 per cui mi serve moltiplicare
    // in teoria restituisce r = nG + mq, per cui servendomi solo nG metto a NULL il resto
    EC_POINT_mul(curve_group, P_G1, Scc1, NULL, NULL, ctx);
    EC_POINT_mul(curve_group, P_G2, Scc2, NULL, NULL, ctx);

    // dobbiamo serializzare per poter inviare
    EC_POINT_point2oct(curve_group, P_G1, POINT_CONVERSION_COMPRESSED, out_G1, ECC_POINT_LEN, ctx);
    EC_POINT_point2oct(curve_group, P_G2, POINT_CONVERSION_COMPRESSED, out_G2, ECC_POINT_LEN, ctx);

    EC_POINT_free(P_G1);
    EC_POINT_free(P_G2);
    BN_free(Scc1);
    BN_free(Scc2);
    BN_free(order);
    BN_CTX_free(ctx);
    EC_GROUP_free(curve_group);

}

// SHA256 hash of the dropout node set, used as the challenge scalar h in the consistency check
void hash_node_set_sha256(const node_set_t* set, uint8_t out_hash[SHA256_DIGEST]){
    unsigned int len = SHA256_DIGEST;
    EVP_Digest((const void*)set, sizeof(node_set_t), out_hash, &len, EVP_sha256(), NULL);
}

// Splits `secret` (a scalar mod the curve order) into `n` Shamir shares with threshold `k`,
// using a polynomial defined directly over the scalar field (mod n), so that shares are
// linearly combinable: for any public scalar h, h*share_i + share'_i is itself a valid
// share (at the same x = i+1) of h*secret + secret'.
void ecc_shamir_create_shares(const ecc_scalar_t secret, int n, int k, ecc_scalar_t out_shares[MAX_NUM_CLIENTS]){
    EC_GROUP *curve_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *order = BN_new();
    EC_GROUP_get_order(curve_group, order, ctx);

    BIGNUM *coeffs[k];
    coeffs[0] = BN_bin2bn(secret, ECC_SCALAR_LEN, NULL);
    for(int c = 1; c < k; c++){
        coeffs[c] = BN_new();
        BN_rand_range(coeffs[c], order);
    }

    BIGNUM *x = BN_new();
    BIGNUM *xpow = BN_new();
    BIGNUM *term = BN_new();
    BIGNUM *y = BN_new();

    for(int i = 0; i < n; i++){
        BN_set_word(x, i + 1);
        BN_one(xpow);
        BN_copy(y, coeffs[0]);

        for(int c = 1; c < k; c++){
            BN_mod_mul(xpow, xpow, x, order, ctx);
            BN_mod_mul(term, coeffs[c], xpow, order, ctx);
            BN_mod_add(y, y, term, order, ctx);
        }

        BN_bn2binpad(y, out_shares[i], ECC_SCALAR_LEN);
    }

    BN_free(x);
    BN_free(xpow);
    BN_free(term);
    BN_free(y);
    for(int c = 0; c < k; c++) BN_free(coeffs[c]);
    BN_free(order);
    BN_CTX_free(ctx);
    EC_GROUP_free(curve_group);
}

// Lagrange-interpolates `k` shares (at x = node_ids[i]+1) back to the polynomial's value at
// x=0, i.e. the shared secret, mod the curve order.
void ecc_shamir_interpolate_at_zero(const node_id_t* node_ids, const ecc_scalar_t* shares, int k, ecc_scalar_t out_secret){
    EC_GROUP *curve_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *order = BN_new();
    EC_GROUP_get_order(curve_group, order, ctx);

    BIGNUM *xs[k];
    BIGNUM *ys[k];
    for(int i = 0; i < k; i++){
        xs[i] = BN_new();
        BN_set_word(xs[i], node_ids[i] + 1);
        ys[i] = BN_bin2bn(shares[i], ECC_SCALAR_LEN, NULL);
    }

    BIGNUM *secret = BN_new(); BN_zero(secret);
    BIGNUM *num = BN_new();
    BIGNUM *den = BN_new();
    BIGNUM *tmp = BN_new();
    BIGNUM *tmp2 = BN_new();

    for(int i = 0; i < k; i++){
        BN_one(num);
        BN_one(den);
        for(int j = 0; j < k; j++){
            if(i == j) continue;
            // num *= -x_j mod order
            BN_mod_sub(tmp, order, xs[j], order, ctx); // safe even if xs[j] == 0 is impossible (x>=1)
            BN_mod_mul(num, num, tmp, order, ctx);
            // den *= (x_i - x_j) mod order
            BN_mod_sub(tmp2, xs[i], xs[j], order, ctx);
            BN_mod_mul(den, den, tmp2, order, ctx);
        }
        BN_mod_inverse(tmp, den, order, ctx); // tmp = den^-1
        BN_mod_mul(num, num, tmp, order, ctx); // num = L_i(0)
        BN_mod_mul(tmp, ys[i], num, order, ctx); // tmp = y_i * L_i(0)
        BN_mod_add(secret, secret, tmp, order, ctx);
    }

    BN_bn2binpad(secret, out_secret, ECC_SCALAR_LEN);

    for(int i = 0; i < k; i++){ BN_free(xs[i]); BN_free(ys[i]); }
    BN_free(secret);
    BN_free(num);
    BN_free(den);
    BN_free(tmp);
    BN_free(tmp2);
    BN_free(order);
    BN_CTX_free(ctx);
    EC_GROUP_free(curve_group);
}

// Computes w = (h*y + z) mod curve_order
void ecc_scalar_mul_add_mod(const ecc_scalar_t h, const ecc_scalar_t y, const ecc_scalar_t z, ecc_scalar_t out){
    EC_GROUP *curve_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *order = BN_new();
    EC_GROUP_get_order(curve_group, order, ctx);

    BIGNUM *h_bn = BN_bin2bn(h, ECC_SCALAR_LEN, NULL);
    BIGNUM *y_bn = BN_bin2bn(y, ECC_SCALAR_LEN, NULL);
    BIGNUM *z_bn = BN_bin2bn(z, ECC_SCALAR_LEN, NULL);
    BIGNUM *w_bn = BN_new();

    BN_mod_mul(w_bn, h_bn, y_bn, order, ctx);
    BN_mod_add(w_bn, w_bn, z_bn, order, ctx);

    BN_bn2binpad(w_bn, out, ECC_SCALAR_LEN);

    BN_free(h_bn);
    BN_free(y_bn);
    BN_free(z_bn);
    BN_free(w_bn);
    BN_free(order);
    BN_CTX_free(ctx);
    EC_GROUP_free(curve_group);
}

// Checks that G^W == G1^h * G2 (additive EC notation: W*G == h*G1 + G2).
// If it holds, then W == h*Scc1 + Scc2, proving the server correctly combined
// consistent shares of Scc1/Scc2 for the hash h of the dropout list it announced.
bool ecc_verify_cc(const ecc_point_t G1, const ecc_point_t G2, const ecc_scalar_t h, const ecc_scalar_t W){
    EC_GROUP *curve_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    BN_CTX *ctx = BN_CTX_new();

    EC_POINT *P_G1 = EC_POINT_new(curve_group);
    EC_POINT *P_G2 = EC_POINT_new(curve_group);
    bool ok = EC_POINT_oct2point(curve_group, P_G1, G1, ECC_POINT_LEN, ctx) == 1
           && EC_POINT_oct2point(curve_group, P_G2, G2, ECC_POINT_LEN, ctx) == 1;

    BIGNUM *h_bn = BN_bin2bn(h, ECC_SCALAR_LEN, NULL);
    BIGNUM *W_bn = BN_bin2bn(W, ECC_SCALAR_LEN, NULL);

    EC_POINT *term = EC_POINT_new(curve_group);
    EC_POINT *expected = EC_POINT_new(curve_group);
    EC_POINT *actual = EC_POINT_new(curve_group);

    if(ok){
        EC_POINT_mul(curve_group, term, NULL, P_G1, h_bn, ctx);   // term = h * G1
        EC_POINT_add(curve_group, expected, term, P_G2, ctx);     // expected = h*G1 + G2
        EC_POINT_mul(curve_group, actual, W_bn, NULL, NULL, ctx); // actual = W * G

        ok = (EC_POINT_cmp(curve_group, expected, actual, ctx) == 0);
    }

    EC_POINT_free(P_G1);
    EC_POINT_free(P_G2);
    EC_POINT_free(term);
    EC_POINT_free(expected);
    EC_POINT_free(actual);
    BN_free(h_bn);
    BN_free(W_bn);
    BN_CTX_free(ctx);
    EC_GROUP_free(curve_group);

    return ok;
}
