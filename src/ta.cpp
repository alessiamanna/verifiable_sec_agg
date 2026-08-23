#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <vector>

#include "crypto_utils.h"
#include "msg_type.h"
#include "puf_data.h"
#include "server.h"
#include "puf_utils.h"
#include "common_share.h"
#include "common.h"
#include "sss/sss.h"
#include "puf_manager.h"

#define CC_SIM 0xCCCC

void secret_padding(uint8_t* padded_secret, puf_resp_t secret){
    memset(padded_secret, 0, sss_MLEN);
    memcpy(padded_secret, &secret, sizeof(puf_resp_t));
}

static void vector_add(update_t* acc, const update_t* input, size_t len) {
    for(size_t i = 0; i < len; i++) acc[i] += input[i];
}

protocol_key_t simulated_key(node_id_t node_helper, node_id_t node_target) {
    return UInt128::from_uint32(node_helper) ^ 
           UInt128::from_uint32(node_target) ^ 
           UInt128::from_uint32(0xCAFEBABE);
}

static void ta_offset_helper(int N, int K, size_t update_len, puf_index_t base_idx, share_db_idx_t db_idx) {
    for (node_id_t target = 0; target < N; target++) {
        ta_chains_t target_chains;
        get_ta_chains(target, base_idx, &target_chains);

        puf_resp_t secret_scalar;
        switch (db_idx) {
            case DB_IDX_MASK_DATA:   secret_scalar = target_chains.mask_chain.d_mask_data; break;
            case DB_IDX_NOISE_DATA:  secret_scalar = target_chains.mask_chain.d_noise_data; break;
            case DB_IDX_MASK_VERIF:  secret_scalar = target_chains.mask_chain.d_mask_verif; break;
            case DB_IDX_NOISE_VERIF: secret_scalar = target_chains.mask_chain.d_noise_verif; break;
            default: return;
        }

        std::vector<puf_resp_t> p_j(update_len);
        get_device_specific_key(target, update_len, p_j.data()); 
        
        std::vector<update_t> expanded_secret(update_len);
        expand_puf_response(secret_scalar, p_j.data(), update_len, expanded_secret.data()); 

        std::vector<std::vector<sss_share_t>> real_shares(update_len, std::vector<sss_share_t>(N));
        for (size_t m = 0; m < update_len; m++) {
            uint8_t padded_secret[sss_MLEN];
            secret_padding(padded_secret, expanded_secret[m]);
            sss_create_shares(reinterpret_cast<sss_Share*>(real_shares[m].data()), padded_secret, N, K);
        }

        for (node_id_t helper = 0; helper < N; helper++) {
            if (helper == target || !recovery_topology_has_edge(helper, target)) continue;

            ta_chains_t helper_chains;
            get_ta_chains(helper, base_idx, &helper_chains);

            puf_resp_t puf_h;
            switch (db_idx) {
                case DB_IDX_MASK_DATA:   puf_h = helper_chains.share_chain.share_mask; break;
                case DB_IDX_NOISE_DATA:  puf_h = helper_chains.share_chain.share_noise; break;
                case DB_IDX_MASK_VERIF:  puf_h = helper_chains.share_chain.share_mask_verif; break;
                case DB_IDX_NOISE_VERIF: puf_h = helper_chains.share_chain.share_noise_verif; break;
                default: continue;
            }

            protocol_key_t k = simulated_key(helper, target);
            size_t total_share_len = update_len * sss_SHARE_LEN;
            std::vector<uint8_t> share_h(total_share_len);
            compute_share_h(puf_h, k, share_h.data(), total_share_len);

            std::vector<uint8_t> offset(total_share_len);
            for (size_t m = 0; m < update_len; m++) {
                for (size_t j = 0; j < sss_SHARE_LEN; j++) {
                    offset[m * sss_SHARE_LEN + j] = real_shares[m][helper][j] ^ share_h[m * sss_SHARE_LEN + j];
                }
            }

            server_db_store_offset(helper, target, db_idx, offset.data(), update_len);
        }
    }
}

void ta_compute_offset(int N, int K, size_t update_len, puf_index_t base_idx){
    printf("[TA] Generating offsets\n");
    
    server_db_init();

    ta_offset_helper(N, K, update_len, base_idx, DB_IDX_MASK_DATA);
    ta_offset_helper(N, K, update_len, base_idx, DB_IDX_NOISE_DATA);
    ta_offset_helper(N, K, update_len, base_idx, DB_IDX_MASK_VERIF);
    ta_offset_helper(N, K, update_len, base_idx, DB_IDX_NOISE_VERIF);
    
    printf("[TA] offsets generated\n");
}

void ta_send_global_masks(server_t* srv, int N, size_t update_len, puf_index_t base_idx){
    printf("[TA] Computing global mask\n");

    ta_mask_setup_t masks_msg;
    masks_msg.type = MSG_TA_MASK_SETUP;
    masks_msg.len = static_cast<uint32_t>(update_len);
    masks_msg.global_mask_sum.assign(update_len, UInt128{0,0,0,0});
    masks_msg.global_mask_verif.assign(update_len, UInt128{0,0,0,0});

    std::vector<update_t> global_mask_sum(update_len, UInt128{0,0,0,0});
    std::vector<update_t> global_mask_verif(update_len, UInt128{0,0,0,0});

    for(int i = 0; i < N; i++){
        ta_chains_t chains;
        get_ta_chains(i, base_idx, &chains);

        std::vector<puf_resp_t> p_j(update_len);
        get_device_specific_key(i, update_len, p_j.data());

        std::vector<update_t> expanded_mask(update_len);
        expand_puf_response(chains.mask_chain.d_mask_data, p_j.data(), update_len, expanded_mask.data());
        vector_add(global_mask_sum.data(), expanded_mask.data(), update_len);
        
        std::vector<update_t> expanded_verif(update_len);
        expand_puf_response(chains.mask_chain.d_mask_verif, p_j.data(), update_len, expanded_verif.data());
        vector_add(global_mask_verif.data(), expanded_verif.data(), update_len);
    }

    masks_msg.global_mask_sum = global_mask_sum;
    masks_msg.global_mask_verif = global_mask_verif;

    server_set_ta_sums(srv, masks_msg.global_mask_sum.data(), masks_msg.global_mask_verif.data(), update_len);

    printf("[TA] Global masks sent to server\n");
}

void ta_compute_cc_offset(int N, int K, puf_index_t base_idx){
    printf("[TA] Generating CC offsets\n");

    ecc_point_t G1, G2;
    ecc_scalar_t Scc1, Scc2;

    ecc_generate_cc(G1, G2, Scc1, Scc2);
    server_db_store_commitments(G1, G2);

    ecc_scalar_t shares_y[MAX_NUM_CLIENTS];
    ecc_scalar_t shares_z[MAX_NUM_CLIENTS];
    ecc_shamir_create_shares(Scc1, N, K, shares_y);
    ecc_shamir_create_shares(Scc2, N, K, shares_z);

    for (node_id_t target = 0; target < N; target++){
        ta_chains_t chains;
        get_ta_chains(target, base_idx, &chains);

        puf_resp_t puf_cc1 = chains.share_chain.share_cc1;
        puf_resp_t puf_cc2 = chains.share_chain.share_cc2;

        protocol_key_t k = get_shared_key(target, CC_SIM);

        uint8_t mask_y[ECC_SCALAR_LEN];
        uint8_t mask_z[ECC_SCALAR_LEN];

        compute_share_h(puf_cc1, k, mask_y, ECC_SCALAR_LEN);
        compute_share_h(puf_cc2, k, mask_z, ECC_SCALAR_LEN);

        uint8_t offset_y[ECC_SCALAR_LEN];
        uint8_t offset_z[ECC_SCALAR_LEN];

        for(size_t j = 0; j < ECC_SCALAR_LEN; j++){
            offset_y[j] = shares_y[target][j] ^ mask_y[j];
            offset_z[j] = shares_z[target][j] ^ mask_z[j];
        }

        server_db_store_offset_cc(target, offset_y, offset_z);
    }
    printf("[TA] CC offsets generated\n");
}
