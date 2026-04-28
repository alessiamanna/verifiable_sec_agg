#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "msg_type.h"
#include "puf_data.h"
#include "server.h"
#include "puf_utils.h"
#include "common_share.h"
#include "common.h"
#include "sss/sss.h"
#include "puf_manager.h"


void secret_padding(uint8_t* padded_secret, puf_resp_t secret){
    memset(padded_secret, 0, sss_MLEN);
    memcpy(padded_secret, &secret, sizeof(puf_resp_t));
}

// spostala in utils
static void vector_add(update_t* acc, update_t* input) {
    for(int i=0; i<UPDATE_LEN; i++) acc[i] += input[i];
}

protocol_key_t simulated_key(node_id_t node_helper, node_id_t node_target) {
    return UInt128::from_uint32(node_helper) ^ 
           UInt128::from_uint32(node_target) ^ 
           UInt128::from_uint32(0xCAFEBABE);
}


static void ta_offset_helper(int N, int K, puf_index_t base_idx, share_db_idx_t db_idx) {
    for (node_id_t target = 0; target < N; target++) {
        // Retrieve the full set of chains for the target node
        ta_chains_t target_chains;
        get_ta_chains(target, base_idx, &target_chains);

        // Determine which secret to share based on the DB index
        puf_resp_t secret_scalar;
        switch (db_idx) {
            case DB_IDX_MASK_DATA:   secret_scalar = target_chains.mask_chain.d_mask_data; break;
            case DB_IDX_NOISE_DATA:  secret_scalar = target_chains.mask_chain.d_noise_data; break;
            case DB_IDX_MASK_VERIF:  secret_scalar = target_chains.mask_chain.d_mask_verif; break;
            case DB_IDX_NOISE_VERIF: secret_scalar = target_chains.mask_chain.d_noise_verif; break;
            default: return;
        }

        puf_resp_t p_j[UPDATE_LEN];
        get_device_specific_key(target, p_j); 
        
        update_t expanded_secret[UPDATE_LEN];
        expand_puf_response(secret_scalar, p_j, expanded_secret); 

        sss_Share real_shares[UPDATE_LEN][MAX_NUM_CLIENTS];
        for (int m = 0; m < UPDATE_LEN; m++) {
            uint8_t padded_secret[sss_MLEN];
            secret_padding(padded_secret, expanded_secret[m]);
            sss_create_shares(real_shares[m], padded_secret, N, K);
        }

        for (node_id_t helper = 0; helper < N; helper++) {
            if (helper == target) continue;

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
            size_t total_share_len = UPDATE_LEN * sss_SHARE_LEN;
            uint8_t share_h[total_share_len];
            compute_share_h(puf_h, k, share_h, total_share_len);

            uint8_t offset[UPDATE_LEN][sss_SHARE_LEN];
            for (int m = 0; m < UPDATE_LEN; m++) {
                for (size_t j = 0; j < sss_SHARE_LEN; j++) {
                    offset[m][j] = real_shares[m][helper][j] ^ share_h[m * sss_SHARE_LEN + j];
                }
            }

            server_db_store_offset(helper, target, db_idx, offset);
        }
    }
}

void ta_compute_offset(int N, int K, puf_index_t base_idx){
    printf("[TA] Generating offsets\n");
    
    server_db_init();

    ta_offset_helper(N, K, base_idx, DB_IDX_MASK_DATA);
    ta_offset_helper(N, K, base_idx, DB_IDX_NOISE_DATA);
    ta_offset_helper(N, K, base_idx, DB_IDX_MASK_VERIF);
    ta_offset_helper(N, K, base_idx, DB_IDX_NOISE_VERIF);
    
    printf("[TA] offsets generated\n");

}

void ta_send_global_masks(server_t* srv, int N, puf_index_t base_idx){
    printf("[TA] Computing global mask\n");

    ta_mask_setup_t masks_msg;
    masks_msg.type = MSG_TA_MASK_SETUP;

    update_t global_mask_sum[UPDATE_LEN];
    update_t global_mask_verif[UPDATE_LEN];

    memset(global_mask_sum, 0, sizeof(global_mask_sum));
    memset(global_mask_verif, 0, sizeof(global_mask_verif));

    for(int i = 0; i < N; i++){
        ta_chains_t chains;
        get_ta_chains(i, base_idx, &chains);

        puf_resp_t p_j[UPDATE_LEN];
        get_device_specific_key(i, p_j);

        update_t expanded_mask[UPDATE_LEN];
        expand_puf_response(chains.mask_chain.d_mask_data, p_j, expanded_mask);
        vector_add(global_mask_sum, expanded_mask);
        
        update_t expanded_verif[UPDATE_LEN];
        expand_puf_response(chains.mask_chain.d_mask_verif, p_j, expanded_verif);
        vector_add(global_mask_verif, expanded_verif);
    }

    memcpy(masks_msg.global_mask_sum, global_mask_sum, sizeof(global_mask_sum));
    memcpy(masks_msg.global_mask_verif, global_mask_verif, sizeof(global_mask_verif));

    memcpy(srv->ta_mask_x, masks_msg.global_mask_sum, sizeof(srv->ta_mask_x));
    memcpy(srv->ta_mask_hat, masks_msg.global_mask_verif, sizeof(srv->ta_mask_hat));

    printf("[TA] Global masks sent to server\n");
}

