#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "node.h"
#include "common.h"
#include "common_share.h"
#include "int128.h"
#include "msg_type.h"
#include "puf_data.h"
#include "puf_utils.h"
#include "crypto_utils.h"
#include "puf_manager.h"
#include "sss/sss.h"


void node_setup(node_t *node, node_id_t node_id, io_interface_t io){
    memset(node, 0, sizeof(node_t));

    node->node_id = node_id;
    node->io = io;

    node->current_link_ta = INITIAL_LINK;
    node->current_link_srv = INITIAL_LINK;

    // First state of the FSM
    node->current_state = node_state_compute_update;
}

void run_node_state(node_t* node){
    node->current_state(node);
}

void node_state_compute_update(node_t *node){
    #if DEBUG
        printf("[NODE %d] Sending local update to server \n", node->node_id);
    #endif

    // Prepare the message 
    node_local_update_t local_update_msg;
    memset(&local_update_msg, 0, sizeof(node_local_update_t));
    local_update_msg.type = MSG_NODE_SEND_LOCAL_UPDATE;
    local_update_msg.node_id = node->node_id;

    // The node computes y_j and y_hat_j to send to the server
    // We need to retrieve links from the TA
    ta_chains_t ta_chains;
    get_ta_chains(node->node_id, node->current_link_ta, &ta_chains);

    transport_chain_t srv_chain;
    get_transport_chain(node->current_link_srv, &srv_chain);

    puf_resp_t p_j[UPDATE_LEN];
    get_device_specific_key(node->node_id, p_j);
   
    update_t mask_data[UPDATE_LEN];
    update_t noise_data[UPDATE_LEN];
    update_t mask_verif[UPDATE_LEN];
    update_t noise_verif[UPDATE_LEN];

    expand_puf_response(ta_chains.mask_chain.d_mask_data, p_j, mask_data);
    expand_puf_response(ta_chains.mask_chain.d_noise_data, p_j, noise_data);
    expand_puf_response(ta_chains.mask_chain.d_mask_verif, p_j, mask_verif);
    expand_puf_response(ta_chains.mask_chain.d_noise_verif, p_j, noise_verif);

    update_t temp_update[UPDATE_LEN];
    update_t temp_verif[UPDATE_LEN];

    for(int i = 0; i < UPDATE_LEN; i++){
        update_t x = node->data_update[i];
        update_t x_verify = (x * VERIF_A) + UInt128::from_uint32(VERIF_B);
        
        temp_update[i] = x + mask_data[i] + noise_data[i];
        temp_verif[i] = x_verify + mask_verif[i] + noise_verif[i];
    }
    
    //treated like 128bit values for encryption operation 
    
    //copy the values of 16bit * n components updates
    //memcpy(&y_j, temp_update, sizeof(y_j));
    //memcpy(&y_j_hat, temp_verif, sizeof(y_j_hat));

    //packet construction
    for(int i = 0; i < UPDATE_LEN; i++){
        local_update_msg.n_0[i] = encrypt_puf(temp_update[i], srv_chain.l_0_data);
        local_update_msg.n_1[i] = encrypt_puf(temp_verif[i], srv_chain.l_1_verif);
    }

    sign_payload(temp_update, temp_verif, srv_chain.l_2_hmac_local, local_update_msg.n_2);

    if(node->io.send(node->io.obj, (uint8_t*)&local_update_msg, sizeof(local_update_msg)) == OK){
        #if DEBUG
            printf("[NODE %d] Update sent \n", node->node_id);
        #endif
        node->current_state = node_state_wait_for_server;
    } else{
        #if DEBUG
            printf("[NODE %d] Error while sending update", node->node_id);
        #endif
    }
}

void node_state_wait_for_server(node_t *node){
    #if DEBUG
    printf("[NODE %d] Waiting for server \n", node->node_id);
    #endif

    // In this phase, the node waits for the dropout list Z_j
    // It then checks the HMAC of the received message
    // Once verified, it checks if it can recover a share for any of the nodes in Z_j

  
    // Check if HMAC 
    transport_chain_t srv_chain;
    get_transport_chain(node->current_link_srv, &srv_chain);

    ta_chains_t ta_chains;
    get_ta_chains(node->node_id, node->current_link_ta, &ta_chains);
    srv_dropout_list_t srv_dropout_msg;
    memset(&srv_dropout_msg, 0, sizeof(srv_dropout_list_t));
    size_t out_len = 0;

    if(node->io.recv(node->io.obj, (uint8_t*)&srv_dropout_msg, sizeof(srv_dropout_list_t), &out_len) != OK){
        #if DEBUG
        printf("[NODE] Error in message reception \n");
        #endif
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
    // Message to send back to the server containing the shares
    node_shares_msg_t share_rec_msg;
    memset(&share_rec_msg, 0, sizeof(node_shares_msg_t));
    share_rec_msg.type = MSG_NODE_SEND_SHARES;
    share_rec_msg.node_id = node->node_id;
    share_rec_msg.item_cnt = 0;

    node_set_t Z_j = srv_dropout_msg.n_3;

    for(int i = 0; i < node->K_j.node_count; i++){
        if (share_rec_msg.item_cnt >= MAX_SHARES) break; 
        
        node_id_t target_id = node->K_j.node_id[i];

        bool is_dropout = (node_is_present(&Z_j, target_id));

        protocol_key_t shared_key = get_shared_key(node->node_id, target_id);

        share_item_t* item_data = &share_rec_msg.items[share_rec_msg.item_cnt];
        item_data->target_node_id = target_id;

        if(is_dropout){
            // If the node is a dropout, then we have to recover the shares to cancel out the mask
            //implementa la logica di recupero delle share.
            item_data->type = SHARE_TYPE_MASK;

            compute_share_h(ta_chains.share_chain.share_mask,       shared_key, (uint8_t*)item_data->share_data, UPDATE_LEN*sss_SHARE_LEN);
            compute_share_h(ta_chains.share_chain.share_mask_verif, shared_key, (uint8_t*)item_data->share_verif, UPDATE_LEN*sss_SHARE_LEN);
        }
        else{
            // Otherwise, we only have to recover the shares to remove the noise.
            item_data->type = SHARE_TYPE_NOISE;
            //implementa la logica di recupero delle share.
            printf("I'm here\n");
            compute_share_h(ta_chains.share_chain.share_noise,       shared_key, (uint8_t*)item_data->share_data, UPDATE_LEN*sss_SHARE_LEN);
            compute_share_h(ta_chains.share_chain.share_noise_verif, shared_key, (uint8_t*)item_data->share_verif, UPDATE_LEN*sss_SHARE_LEN);

        }
        share_rec_msg.item_cnt++;

    }

    sign_shares_list(share_rec_msg.items, share_rec_msg.item_cnt, srv_chain.l_4_hmac_shares, share_rec_msg.n_6);

    // We send the message to the server
    node->io.send(node->io.obj, (uint8_t*)&share_rec_msg, sizeof(share_rec_msg));
    node->current_state = node_state_wait_final;
}

void node_state_wait_final(node_t *node){
    #if DEBUG
    printf("[NODE %d] Finalizing aggregation\n", node->node_id);
    #endif
    transport_chain_t srv_chain;
    get_transport_chain(node->current_link_srv, &srv_chain );

    srv_global_update_t final_msg;
    size_t out_len;

    if(node->io.recv(node->io.obj, (uint8_t*)&final_msg, sizeof(srv_global_update_t), &out_len) != OK){
        #if DEBUG
        printf("[NODE %d] Error in message reception \n", node->node_id);
        #endif
        return;
    }

    update_t clean_sum[UPDATE_LEN];
    update_t clean_verif[UPDATE_LEN];

    // decrypt
    for(int i = 0; i < UPDATE_LEN; i++){
        clean_sum[i] = decrypt_puf(final_msg.n_7[i], srv_chain.l_5_final_data);
        clean_verif[i] = decrypt_puf(final_msg.n_8[i], srv_chain.l_6_final_verif);
    }
    hmac_t calc_hmac;
    sign_payload(final_msg.n_7, final_msg.n_8, srv_chain.l_7_global, calc_hmac);

    if(!verify_hmac(calc_hmac, final_msg.n_9)){
        printf("[NODE %d] INTEGRITY ERROR: Global Update HMAC mismatch!\n", node->node_id);
        return;
    }

    // Check verifiability
    int N_participants = 3;

    printf("[NODE %d DEBUG] Decrypted Values (First 3):\n", node->node_id);
    printf("   -> Sum Data:  %u, %u, %u ...\n", clean_sum[0].data[0], clean_sum[1].data[0], clean_sum[2].data[0]);
    printf("   -> Sum Verif: %u, %u, %u ...\n", clean_verif[0].data[0], clean_verif[1].data[0], clean_verif[2].data[0]);
    
    int errors = 0;
    for(int i = 0; i < UPDATE_LEN; i++){
        update_t expected_verif = (clean_sum[i] * VERIF_A) + UInt128::from_uint32(N_participants*VERIF_B);
        
        if(!(clean_verif[i] == expected_verif)){
            errors++;
            #if DEBUG
            printf("[NODE %d] Math mismatch at idx %d\n", node->node_id, i);
            #endif

            printf("[NODE %d ERROR] Math Mismatch at index %d:\n", node->node_id, i);
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

   
    memcpy(node->data_update, clean_sum, sizeof(node->data_update));

    // Update links for next iteration
    node->current_link_ta += MASK_CHAIN_LEN + SHARE_CHAIN_LEN;
    node->current_link_srv += TRANSPORT_CHAIN_LEN;

    node->current_state = node_state_compute_update;
}
