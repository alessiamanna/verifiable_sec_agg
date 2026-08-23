#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <vector>

#include "node.h"
#include "common.h"
#include "common_share.h"
#include "int128.h"
#include "msg_type.h"
#include "puf_data.h"
#include "puf_utils.h"
#include "crypto_utils.h"
#include "puf_manager.h"
#include "server.h"
#include "sss/sss.h"

#define CC_SIM 0xCCCC

void node_cc_data(node_t* node){
    #if DEBUG
    printf("[NODE %d] Fetching consistency data\n", node->node_id);
    #endif

    server_db_get_commitments(node->consistency_data.G1, node->consistency_data.G2);

    uint8_t offset_y[ECC_SCALAR_LEN];
    uint8_t offset_z[ECC_SCALAR_LEN];
    server_db_get_offset_cc(node->node_id, offset_y, offset_z);

    ta_chains_t chains;
    get_ta_chains(node->node_id, node->current_link_ta, &chains);

    puf_resp_t puf_cc1 = chains.share_chain.share_cc1;
    puf_resp_t puf_cc2 = chains.share_chain.share_cc2;

    protocol_key_t k = get_shared_key(node->node_id, CC_SIM);

    uint8_t mask_y[ECC_SCALAR_LEN];
    uint8_t mask_z[ECC_SCALAR_LEN];

    compute_share_h(puf_cc1, k, mask_y, ECC_SCALAR_LEN);
    compute_share_h(puf_cc2, k, mask_z, ECC_SCALAR_LEN);

    for(size_t j = 0; j < ECC_SCALAR_LEN; j++){
        node->consistency_data.y_j[j] = offset_y[j] ^ mask_y[j];
        node->consistency_data.z_j[j] = offset_z[j] ^ mask_z[j];
    }
}

void node_compute_cc_value(node_t* node, node_set_t* dropout_set, node_cc_msg_t* out_msg){
    #if DEBUG
    printf("[NODE %d] Computing consistency check value\n", node->node_id);
    #endif

    uint8_t h[SHA256_DIGEST];
    hash_node_set_sha256(dropout_set, h);

    ecc_scalar_t w_j;
    ecc_scalar_mul_add_mod(h, node->consistency_data.y_j, node->consistency_data.z_j, w_j);

    out_msg->type = MSG_NODE_SEND_CC_VALUE;
    out_msg->node_id = node->node_id;
    memcpy(out_msg->w_j, w_j, ECC_SCALAR_LEN);
}

bool node_verify_cc_result(node_t* node, node_set_t* dropout_set, srv_cc_result_t* result_msg){
    uint8_t h[SHA256_DIGEST];
    hash_node_set_sha256(dropout_set, h);

    bool ok = ecc_verify_cc(node->consistency_data.G1, node->consistency_data.G2, h, result_msg->W);

    if(!ok){
        printf("[NODE %d] CONSISTENCY CHECK FAILED: server's dropout list is not consistent. Aborting round.\n", node->node_id);
    }
    #if DEBUG
    else{
        printf("[NODE %d] Consistency check passed\n", node->node_id);
    }
    #endif

    return ok;
}

void node_setup(node_t *node, node_id_t node_id, size_t update_len, io_interface_t io){
    node->node_id = node_id;
    node->srv_id = 0;
    node->update_len = static_cast<uint32_t>(update_len);
    node->data_update.assign(update_len, UInt128{0,0,0,0});
    node->io = io;

    node->current_link_ta = INITIAL_LINK;
    node->current_link_srv = INITIAL_LINK;
    node->K_j.node_count = 0;

    node->current_out_update = nullptr;
    node->current_in_drop_msg = nullptr;
    node->current_out_shares = nullptr;
    node->current_in_global = nullptr;

    node->current_state = node_state_compute_update;
}

void run_node_state(node_t* node){
    if (node->current_state) {
        node->current_state(node);
    }
}

void node_state_compute_update(node_t *node){
    #if DEBUG
        printf("[NODE %d] Sending local update to server \n", node->node_id);
    #endif

    size_t len = node->update_len;

    node_local_update_t local_update_msg;
    local_update_msg.type = MSG_NODE_SEND_LOCAL_UPDATE;
    local_update_msg.node_id = node->node_id;
    local_update_msg.len = static_cast<uint32_t>(len);
    local_update_msg.n_0.resize(len);
    local_update_msg.n_1.resize(len);

    ta_chains_t ta_chains;
    get_ta_chains(node->node_id, node->current_link_ta, &ta_chains);

    transport_chain_t srv_chain;
    get_transport_chain(node->current_link_srv, &srv_chain);

    std::vector<puf_resp_t> p_j(len);
    get_device_specific_key(node->node_id, len, p_j.data());
   
    std::vector<update_t> mask_data(len);
    std::vector<update_t> noise_data(len);
    std::vector<update_t> mask_verif(len);
    std::vector<update_t> noise_verif(len);

    expand_puf_response(ta_chains.mask_chain.d_mask_data, p_j.data(), len, mask_data.data());
    expand_puf_response(ta_chains.mask_chain.d_noise_data, p_j.data(), len, noise_data.data());
    expand_puf_response(ta_chains.mask_chain.d_mask_verif, p_j.data(), len, mask_verif.data());
    expand_puf_response(ta_chains.mask_chain.d_noise_verif, p_j.data(), len, noise_verif.data());

    std::vector<update_t> temp_update(len);
    std::vector<update_t> temp_verif(len);

    for(size_t i = 0; i < len; i++){
        update_t x = node->data_update[i];
        update_t x_verify = (x * VERIF_A) + UInt128::from_uint32(VERIF_B);
        
        temp_update[i] = x + mask_data[i] + noise_data[i];
        temp_verif[i] = x_verify + mask_verif[i] + noise_verif[i];
    }

    for(size_t i = 0; i < len; i++){
        local_update_msg.n_0[i] = encrypt_puf(temp_update[i], srv_chain.l_0_data);
        local_update_msg.n_1[i] = encrypt_puf(temp_verif[i], srv_chain.l_1_verif);
    }

    sign_payload(temp_update.data(), temp_verif.data(), len, srv_chain.l_2_hmac_local, local_update_msg.n_2);

    if (node->current_out_update) {
        *node->current_out_update = local_update_msg;
    }

    #if DEBUG
        printf("[NODE %d] Update sent \n", node->node_id);
    #endif
    node->current_state = node_state_wait_for_server;
}

void node_state_wait_for_server(node_t *node){
    #if DEBUG
    printf("[NODE %d] Waiting for server \n", node->node_id);
    #endif

    transport_chain_t srv_chain;
    get_transport_chain(node->current_link_srv, &srv_chain);

    ta_chains_t ta_chains;
    get_ta_chains(node->node_id, node->current_link_ta, &ta_chains);
    srv_dropout_list_t srv_dropout_msg;

    if (node->current_in_drop_msg) {
        srv_dropout_msg = *node->current_in_drop_msg;
    } else {
        return;
    }

    #if DEBUG
    printf("[NODE %d] Received dropout set from the server. Checking if shares can be recovered \n", node->node_id);
    #endif

    hmac_t calc_hmac;
    node_set_t local_z_set = srv_dropout_msg.n_3;
    sign_node_set(&local_z_set, srv_chain.l_3_hmac_drop, calc_hmac);    
    if(!verify_hmac(calc_hmac, srv_dropout_msg.n_4)){
        printf("[NODE %d] HMAC mismatch on dropout list!\n", node->node_id);
        return;
    }

    node_shares_msg_t share_rec_msg;
    share_rec_msg.type = MSG_NODE_SEND_SHARES;
    share_rec_msg.node_id = node->node_id;
    share_rec_msg.item_cnt = 0;

    node_set_t Z_j = srv_dropout_msg.n_3;
    size_t len = node->update_len;

    for(int i = 0; i < node->K_j.node_count; i++){
        if (share_rec_msg.item_cnt >= MAX_SHARES) break; 
        
        node_id_t target_id = node->K_j.node_id[i];
        bool is_dropout = (node_is_present(&Z_j, target_id));
        protocol_key_t shared_key = get_shared_key(node->node_id, target_id);

        share_item_t* item_data = &share_rec_msg.items[share_rec_msg.item_cnt];
        item_data->target_node_id = target_id;
        item_data->share_data.resize(len * sss_SHARE_LEN);
        item_data->share_verif.resize(len * sss_SHARE_LEN);

        if(is_dropout){
            item_data->type = SHARE_TYPE_MASK;
            compute_share_h(ta_chains.share_chain.share_mask, shared_key, item_data->share_data.data(), len * sss_SHARE_LEN);
            compute_share_h(ta_chains.share_chain.share_mask_verif, shared_key, item_data->share_verif.data(), len * sss_SHARE_LEN);
        }
        else{
            item_data->type = SHARE_TYPE_NOISE;
            compute_share_h(ta_chains.share_chain.share_noise, shared_key, item_data->share_data.data(), len * sss_SHARE_LEN);
            compute_share_h(ta_chains.share_chain.share_noise_verif, shared_key, item_data->share_verif.data(), len * sss_SHARE_LEN);
        }
        share_rec_msg.item_cnt++;
    }

    sign_shares_list(share_rec_msg.items, share_rec_msg.item_cnt, srv_chain.l_4_hmac_shares, share_rec_msg.n_6);

    if (node->current_out_shares) {
        *node->current_out_shares = share_rec_msg;
    }

    node->current_state = node_state_wait_final;
}

void node_state_wait_final(node_t *node){
    #if DEBUG
    printf("[NODE %d] Finalizing aggregation\n", node->node_id);
    #endif

    transport_chain_t srv_chain;
    get_transport_chain(node->current_link_srv, &srv_chain);

    srv_global_update_t final_msg;
    if (node->current_in_global) {
        final_msg = *node->current_in_global;
    } else {
        return;
    }

    size_t len = final_msg.len;
    std::vector<update_t> clean_sum(len);
    std::vector<update_t> clean_verif(len);

    for(size_t i = 0; i < len; i++){
        clean_sum[i] = decrypt_puf(final_msg.n_7[i], srv_chain.l_5_final_data);
        clean_verif[i] = decrypt_puf(final_msg.n_8[i], srv_chain.l_6_final_verif);
    }

    hmac_t calc_hmac;
    sign_payload(final_msg.n_7.data(), final_msg.n_8.data(), len, srv_chain.l_7_global, calc_hmac);

    if(!verify_hmac(calc_hmac, final_msg.n_9)){
        printf("[NODE %d] INTEGRITY ERROR: Global Update HMAC mismatch!\n", node->node_id);
        return;
    }

    uint32_t N_participants = final_msg.num_participants;

    printf("[NODE %d DEBUG] Decrypted Values (First 3):\n", node->node_id);
    if (len > 0) {
        printf("   -> Sum Data:  %u", clean_sum[0].data[0]);
        if (len > 1) printf(", %u", clean_sum[1].data[0]);
        if (len > 2) printf(", %u", clean_sum[2].data[0]);
        printf(" ...\n");

        printf("   -> Sum Verif: %u", clean_verif[0].data[0]);
        if (len > 1) printf(", %u", clean_verif[1].data[0]);
        if (len > 2) printf(", %u", clean_verif[2].data[0]);
        printf(" ...\n");
    }
    
    int errors = 0;
    for(size_t i = 0; i < len; i++){
        update_t expected_verif = (clean_sum[i] * VERIF_A) + UInt128::from_uint32(N_participants * VERIF_B);
        
        if(!(clean_verif[i] == expected_verif)){
            errors++;
            #if DEBUG
            printf("[NODE %d] Math mismatch at idx %zu\n", node->node_id, i);
            #endif

            printf("[NODE %d ERROR] Math Mismatch at index %zu:\n", node->node_id, i);
            printf("   -> Data: %u\n", clean_sum[i].data[0]);
            printf("   -> Expected Verif (Data*A+B): %u\n", expected_verif.data[0]);
            printf("   -> Actual Verif (Received):   %u\n", clean_verif[i].data[0]);
        }
    }

    if(errors > 0){
        #if DEBUG
        printf("[NODE %d] VERIFIABILITY ERROR: Server result is mathematically invalid (%d errors)\n", node->node_id, errors);
        #endif
        return;
    }

    #if DEBUG
    printf("[NODE %d] Round completed successfully. Result verified.\n", node->node_id);
    #endif

    node->data_update = clean_sum;

    node->current_link_ta += MASK_CHAIN_LEN + SHARE_CHAIN_LEN;
    node->current_link_srv += TRANSPORT_CHAIN_LEN;

    node->current_state = node_state_compute_update;
}
