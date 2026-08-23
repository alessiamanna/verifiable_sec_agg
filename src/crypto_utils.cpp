#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <string.h>
#include "crypto_utils.h"
#include "common.h"

// Cached thread-local ECC context to eliminate OpenSSL allocation overhead
struct ECCContext {
    EC_GROUP* group;
    BIGNUM* order;
    BN_CTX* ctx;

    ECCContext() {
        group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
        ctx = BN_CTX_new();
        order = BN_new();
        EC_GROUP_get_order(group, order, ctx);
    }

    ~ECCContext() {
        if (order) BN_free(order);
        if (ctx) BN_CTX_free(ctx);
        if (group) EC_GROUP_free(group);
    }

    static ECCContext& get() {
        static thread_local ECCContext instance;
        return instance;
    }
};

void calc_hmac_sha256(const uint8_t* data, size_t data_len, const uint8_t* key, size_t key_len, hmac_t out_mac) {
    unsigned int mac_len = SHA256_DIGEST;
 
    HMAC(EVP_sha256(), 
         key, key_len, 
         data, data_len, 
         out_mac, &mac_len);
}

bool verify_hmac(const hmac_t hmac1, const hmac_t hmac2) {
    return memcmp(hmac1, hmac2, SHA256_DIGEST) == 0;
}

void sign_payload(const update_t* p1, const update_t* p2, size_t len, puf_resp_t key, hmac_t out_mac){
    size_t single_array_size = sizeof(update_t) * len;   
    unsigned int mac_len = SHA256_DIGEST;

    HMAC_CTX* ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, (const uint8_t*)&key, sizeof(puf_resp_t), EVP_sha256(), NULL);
    HMAC_Update(ctx, (const uint8_t*)p1, single_array_size);
    HMAC_Update(ctx, (const uint8_t*)p2, single_array_size);
    HMAC_Final(ctx, out_mac, &mac_len);
    HMAC_CTX_free(ctx);
}

void sign_node_set(const node_set_t *set, puf_resp_t key, hmac_t out_mac) {
    calc_hmac_sha256((const uint8_t*)set, sizeof(node_set_t), (const uint8_t*)&key, sizeof(puf_resp_t), out_mac);
}

void sign_shares_list(const share_item_t* items, size_t count, puf_resp_t key, hmac_t out_mac) {
    HMAC_CTX* ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, (const uint8_t*)&key, sizeof(puf_resp_t), EVP_sha256(), NULL);
    for (size_t i = 0; i < count; i++) {
        HMAC_Update(ctx, (const uint8_t*)&items[i].target_node_id, sizeof(items[i].target_node_id));
        HMAC_Update(ctx, (const uint8_t*)&items[i].type, sizeof(items[i].type));
        if (!items[i].share_data.empty()) {
            HMAC_Update(ctx, items[i].share_data.data(), items[i].share_data.size());
        }
        if (!items[i].share_verif.empty()) {
            HMAC_Update(ctx, items[i].share_verif.data(), items[i].share_verif.size());
        }
    }
    unsigned int mac_len = SHA256_DIGEST;
    HMAC_Final(ctx, out_mac, &mac_len);
    HMAC_CTX_free(ctx);
}

// SHA256 hash of the dropout node set, used as the challenge scalar h in the consistency check
void hash_node_set_sha256(const node_set_t* set, uint8_t out_hash[SHA256_DIGEST]){
    unsigned int len = SHA256_DIGEST;
    EVP_Digest((const void*)set, sizeof(node_set_t), out_hash, &len, EVP_sha256(), NULL);
}

void ecc_generate_cc(ecc_point_t out_G1, ecc_point_t out_G2, ecc_scalar_t out_Scc1, ecc_scalar_t out_Scc2) {
    auto& ecc = ECCContext::get();
    BN_CTX_start(ecc.ctx);

    BIGNUM* Scc1 = BN_CTX_get(ecc.ctx);
    BIGNUM* Scc2 = BN_CTX_get(ecc.ctx);

    BN_rand_range(Scc1, ecc.order);
    BN_rand_range(Scc2, ecc.order);

    BN_bn2binpad(Scc1, out_Scc1, ECC_SCALAR_LEN);
    BN_bn2binpad(Scc2, out_Scc2, ECC_SCALAR_LEN);

    EC_POINT *P_G1 = EC_POINT_new(ecc.group);
    EC_POINT *P_G2 = EC_POINT_new(ecc.group);

    EC_POINT_mul(ecc.group, P_G1, Scc1, NULL, NULL, ecc.ctx);
    EC_POINT_mul(ecc.group, P_G2, Scc2, NULL, NULL, ecc.ctx);

    EC_POINT_point2oct(ecc.group, P_G1, POINT_CONVERSION_COMPRESSED, out_G1, ECC_POINT_LEN, ecc.ctx);
    EC_POINT_point2oct(ecc.group, P_G2, POINT_CONVERSION_COMPRESSED, out_G2, ECC_POINT_LEN, ecc.ctx);

    EC_POINT_free(P_G1);
    EC_POINT_free(P_G2);
    BN_CTX_end(ecc.ctx);
}

void ecc_shamir_create_shares(const ecc_scalar_t secret, int n, int k, ecc_scalar_t out_shares[MAX_NUM_CLIENTS]) {
    auto& ecc = ECCContext::get();
    BN_CTX_start(ecc.ctx);

    BIGNUM *coeffs[k];
    coeffs[0] = BN_CTX_get(ecc.ctx);
    BN_bin2bn(secret, ECC_SCALAR_LEN, coeffs[0]);

    for (int c = 1; c < k; c++) {
        coeffs[c] = BN_CTX_get(ecc.ctx);
        BN_rand_range(coeffs[c], ecc.order);
    }

    BIGNUM *x = BN_CTX_get(ecc.ctx);
    BIGNUM *xpow = BN_CTX_get(ecc.ctx);
    BIGNUM *term = BN_CTX_get(ecc.ctx);
    BIGNUM *y = BN_CTX_get(ecc.ctx);

    for (int i = 0; i < n; i++) {
        BN_set_word(x, i + 1);
        BN_one(xpow);
        BN_copy(y, coeffs[0]);

        for (int c = 1; c < k; c++) {
            BN_mod_mul(xpow, xpow, x, ecc.order, ecc.ctx);
            BN_mod_mul(term, coeffs[c], xpow, ecc.order, ecc.ctx);
            BN_mod_add(y, y, term, ecc.order, ecc.ctx);
        }

        BN_bn2binpad(y, out_shares[i], ECC_SCALAR_LEN);
    }

    BN_CTX_end(ecc.ctx);
}

void ecc_shamir_interpolate_at_zero(const node_id_t* node_ids, const ecc_scalar_t* shares, int k, ecc_scalar_t out_secret) {
    auto& ecc = ECCContext::get();
    BN_CTX_start(ecc.ctx);

    BIGNUM *xs[k];
    BIGNUM *ys[k];
    for (int i = 0; i < k; i++) {
        xs[i] = BN_CTX_get(ecc.ctx);
        BN_set_word(xs[i], node_ids[i] + 1);
        ys[i] = BN_CTX_get(ecc.ctx);
        BN_bin2bn(shares[i], ECC_SCALAR_LEN, ys[i]);
    }

    BIGNUM *secret = BN_CTX_get(ecc.ctx); 
    BN_zero(secret);
    BIGNUM *num = BN_CTX_get(ecc.ctx);
    BIGNUM *den = BN_CTX_get(ecc.ctx);
    BIGNUM *tmp = BN_CTX_get(ecc.ctx);
    BIGNUM *tmp2 = BN_CTX_get(ecc.ctx);

    for (int i = 0; i < k; i++) {
        BN_one(num);
        BN_one(den);
        for (int j = 0; j < k; j++) {
            if (i == j) continue;
            // num *= -x_j mod order
            BN_mod_sub(tmp, ecc.order, xs[j], ecc.order, ecc.ctx);
            BN_mod_mul(num, num, tmp, ecc.order, ecc.ctx);
            // den *= (x_i - x_j) mod order
            BN_mod_sub(tmp2, xs[i], xs[j], ecc.order, ecc.ctx);
            BN_mod_mul(den, den, tmp2, ecc.order, ecc.ctx);
        }
        BN_mod_inverse(tmp, den, ecc.order, ecc.ctx);
        BN_mod_mul(num, num, tmp, ecc.order, ecc.ctx);
        BN_mod_mul(tmp, ys[i], num, ecc.order, ecc.ctx);
        BN_mod_add(secret, secret, tmp, ecc.order, ecc.ctx);
    }

    BN_bn2binpad(secret, out_secret, ECC_SCALAR_LEN);
    BN_CTX_end(ecc.ctx);
}

void ecc_scalar_mul_add_mod(const ecc_scalar_t h, const ecc_scalar_t y, const ecc_scalar_t z, ecc_scalar_t out) {
    auto& ecc = ECCContext::get();
    BN_CTX_start(ecc.ctx);

    BIGNUM *h_bn = BN_CTX_get(ecc.ctx);
    BIGNUM *y_bn = BN_CTX_get(ecc.ctx);
    BIGNUM *z_bn = BN_CTX_get(ecc.ctx);
    BIGNUM *w_bn = BN_CTX_get(ecc.ctx);

    BN_bin2bn(h, ECC_SCALAR_LEN, h_bn);
    BN_bin2bn(y, ECC_SCALAR_LEN, y_bn);
    BN_bin2bn(z, ECC_SCALAR_LEN, z_bn);

    BN_mod_mul(w_bn, h_bn, y_bn, ecc.order, ecc.ctx);
    BN_mod_add(w_bn, w_bn, z_bn, ecc.order, ecc.ctx);

    BN_bn2binpad(w_bn, out, ECC_SCALAR_LEN);
    BN_CTX_end(ecc.ctx);
}

bool ecc_verify_cc(const ecc_point_t G1, const ecc_point_t G2, const ecc_scalar_t h, const ecc_scalar_t W) {
    auto& ecc = ECCContext::get();
    BN_CTX_start(ecc.ctx);

    EC_POINT *P_G1 = EC_POINT_new(ecc.group);
    EC_POINT *P_G2 = EC_POINT_new(ecc.group);
    bool ok = (EC_POINT_oct2point(ecc.group, P_G1, G1, ECC_POINT_LEN, ecc.ctx) == 1)
           && (EC_POINT_oct2point(ecc.group, P_G2, G2, ECC_POINT_LEN, ecc.ctx) == 1);

    BIGNUM *h_bn = BN_CTX_get(ecc.ctx);
    BIGNUM *W_bn = BN_CTX_get(ecc.ctx);
    BN_bin2bn(h, ECC_SCALAR_LEN, h_bn);
    BN_bin2bn(W, ECC_SCALAR_LEN, W_bn);

    EC_POINT *term = EC_POINT_new(ecc.group);
    EC_POINT *expected = EC_POINT_new(ecc.group);
    EC_POINT *actual = EC_POINT_new(ecc.group);

    if (ok) {
        EC_POINT_mul(ecc.group, term, NULL, P_G1, h_bn, ecc.ctx);
        EC_POINT_add(ecc.group, expected, term, P_G2, ecc.ctx);
        EC_POINT_mul(ecc.group, actual, W_bn, NULL, NULL, ecc.ctx);

        ok = (EC_POINT_cmp(ecc.group, expected, actual, ecc.ctx) == 0);
    }

    EC_POINT_free(P_G1);
    EC_POINT_free(P_G2);
    EC_POINT_free(term);
    EC_POINT_free(expected);
    EC_POINT_free(actual);
    BN_CTX_end(ecc.ctx);

    return ok;
}