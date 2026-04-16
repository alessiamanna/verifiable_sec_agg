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
static void ta_offset_helper(int N, int K, puf_index_t base_idx, int link_secret_offset, int link_helper_offset, int db_type_idx){
    for(node_id_t target = 0; target < N; target++){
        puf_resp_t secret = get_puf_link_ta(target, base_idx + link_secret_offset);

        uint8_t padded_secret[sss_MLEN];
        secret_padding(padded_secret, secret);

        sss_Share real_shares[MAX_NUM_CLIENTS];
        sss_create_shares(real_shares, padded_secret, N, K);

        for(node_id_t helper = 0; helper < N; helper++){
            if(helper == target) continue;

            puf_resp_t puf_h = get_puf_link_ta(helper, base_idx + link_helper_offset);
            protocol_key_t k = simulated_key(helper, target);

            uint8_t share_h[sss_SHARE_LEN];
            memset(share_h, 0, sss_SHARE_LEN);
            compute_share_h(puf_h, k, share_h);

            uint8_t offset[sss_SHARE_LEN];
            for(size_t j = 0; j < sss_SHARE_LEN; j++){
                offset[j] = real_shares[helper][j] ^ share_h[j];
            }

            server_db_store_offset(helper, target, static_cast<share_db_idx_t>(db_type_idx), offset);        }
    }
}



void ta_compute_offset(int N, int K, puf_index_t base_idx){
    printf("[TA] Generating offsets\n");
    
    server_db_init();

    ta_offset_helper(N, K, base_idx, LINK_MASK_DATA, LINK_TA_4, DB_IDX_MASK_DATA);

    ta_offset_helper(N, K, base_idx, LINK_NOISE_DATA, LINK_TA_5, DB_IDX_NOISE_DATA);

    ta_offset_helper(N, K, base_idx, LINK_MASK_VERIF, LINK_TA_6, DB_IDX_MASK_VERIF);

    ta_offset_helper(N, K, base_idx, LINK_NOISE_VERIF, LINK_TA_7, DB_IDX_NOISE_VERIF);
    
    printf("[TA] offsets generated\n");

}

void ta_send_global_masks(server_t* srv, int N, puf_index_t base_idx){

    printf("[TA] Computing global mask and sending it to the server\n");

    ta_mask_setup_t masks_msg;
    masks_msg.type = MSG_TA_MASK_SETUP;

    update_t global_mask_sum[UPDATE_LEN];
    update_t global_mask_verif[UPDATE_LEN];

    memset(global_mask_sum, 0, sizeof(global_mask_sum));
    memset(global_mask_verif, 0, sizeof(global_mask_verif));

    // The Trusted Authority can query the devices' PUFs
    for(int i = 0; i < N; i++){
        puf_resp_t mask = get_puf_link_ta(i, base_idx + LINK_MASK_DATA);
        vector_add(global_mask_sum, (update_t*)&mask);
        
        puf_resp_t mask_verif = get_puf_link_ta(i, base_idx + LINK_MASK_VERIF);
        vector_add(global_mask_verif, (update_t*)&mask_verif);
    }

    memcpy(&masks_msg.global_mask_sum, global_mask_sum, sizeof(payload_t));
    memcpy(&masks_msg.global_mask_verif, global_mask_verif, sizeof(payload_t));

    // This should be a ta.send 
    memcpy(srv->ta_mask_x, &masks_msg.global_mask_sum,sizeof(srv->ta_mask_x));
    memcpy(srv->ta_mask_hat, &masks_msg.global_mask_verif, sizeof(srv->ta_mask_hat));

    printf("[TA] Global masks sent to server\n");
}

