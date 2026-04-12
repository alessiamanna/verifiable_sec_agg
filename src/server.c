#include "server.h"
#include "common.h"
#include "common_share.h"
#include "puf_data.h"
#include "msg_type.h"
#include "puf_utils.h"
#include "sss/sss.h"
#include "crypto_utils.h"

#include <stdio.h>
#include <string.h>

#define K 2 // SSS Threshold


// DB to store the offsets precomputed by the Trusted Authority
uint8_t server_offset_db[MAX_NUM_CLIENTS][MAX_NUM_CLIENTS][4][sss_SHARE_LEN];
bool db_has_entry[MAX_NUM_CLIENTS][MAX_NUM_CLIENTS][4];

// Keeps reconstruction context for both verifiability and data
static recon_ctx_t ctx_mask[MAX_NUM_CLIENTS];
static recon_ctx_t ctx_noise[MAX_NUM_CLIENTS];

static recon_ctx_t ctx_mask_verif[MAX_NUM_CLIENTS]; 
static recon_ctx_t ctx_noise_verif[MAX_NUM_CLIENTS];


// Utility to print, remove later
static void print_vec_head(const char* label, update_t* vec) {
    #if DEBUG
    printf("   [%s] First element: %u\n", label, (uint32_t)vec[0]); 
    #endif
}

//------ UTILITY FUNCTIONS ------

static void server_reset_buffers(server_t* srv){
    memset(srv->aggr_sum, 0, sizeof(srv->aggr_sum));
    memset(srv->aggr_verif, 0, sizeof(srv->aggr_verif));
    memset(srv->dropped_mask_x, 0, sizeof(srv->dropped_mask_x));
    memset(srv->droppes_mask_hat, 0, sizeof(srv->droppes_mask_hat));
    memset(srv->active_noise_x, 0, sizeof(srv->active_noise_x));
    memset(srv->active_noise_hat, 0, sizeof(srv->active_noise_hat));
    srv->J_prime_set.node_count = 0;
    srv->Z_set.node_count = 0;
}
// Add vector spostala in utils
static void vector_add(update_t* acc, update_t* input) {
    for(int i=0; i<UPDATE_LEN; i++) acc[i] += input[i];
}

// Subtract vector
static void vector_sub(update_t* acc, update_t* input) {
    for(int i=0; i<UPDATE_LEN; i++) acc[i] -= input[i];
}

// ------ SERVER FUNCTIONS ------

// Initialize server DB with empty entries
void server_db_init(){
    memset(db_has_entry, 0, sizeof(db_has_entry));
    memset(server_offset_db, 0, sizeof(server_offset_db));
}

// Store offsets
void server_db_store_offset(node_id_t helper, node_id_t target, int type_idx, uint8_t* offset) {
    if (helper >= MAX_NUM_CLIENTS || target >= MAX_NUM_CLIENTS) {
        #if DEBUG
        printf("[SERVER DB] Error Store: Node ID out of bounds (H:%d, T:%d)\n", helper, target);
        #endif
        return;
    }
    
    if (type_idx < 0 || type_idx > 3) {
        #if DEBUG
        printf("[SERVER DB] Error Store: Invalid Type Index %d\n", type_idx);
        #endif
        return;
    }

    memcpy(server_offset_db[helper][target][type_idx], offset, sss_SHARE_LEN);
    
    db_has_entry[helper][target][type_idx] = true;
}

// Function to retrieve offset value
uint8_t* server_db_get_offset(node_id_t helper, node_id_t target, int type_idx) {
    
    if (helper >= MAX_NUM_CLIENTS || target >= MAX_NUM_CLIENTS) {
        return NULL; 
    }
    
    if (type_idx < 0 || type_idx > 3) {
        return NULL; 
    }

    if (!db_has_entry[helper][target][type_idx]) {
        return NULL; 
    }

    return server_offset_db[helper][target][type_idx];
}

static bool dropout_recovered(server_t* srv){
    for(int i=0; i<srv->Z_set.node_count; i++) {
        node_id_t d_id = srv->Z_set.node_id[i];
        if (!ctx_mask[d_id].done || !ctx_mask_verif[d_id].done) {
            return false;
        }
    }
    return true;
}

// Run current FSM state
void server_run_state(server_t *srv){
    if(srv->current_state){
        srv->current_state(srv);
    }
}

// Initialize server to prepare it for the first 
void server_setup(server_t *srv, srv_id_t id, io_interface_t io){
    memset(srv, 0, sizeof(server_t));
    srv->srv_id = id;
    srv->io = io;
    srv->current_link_srv = INITIAL_LINK;

    srv->J_set.node_count = 0;
    srv->J_prime_set.node_count = 0;

    for(int i = 0; i < MAX_NUM_CLIENTS; i++){
        node_set_add(&srv->J_set, i); 
    }

    srv->current_state = srv_state_wait_updates; 
}

// In this phase the server receives updates from the nodes
// It then checks for dropouts, and sends a list of nodes to recover their shares
void srv_state_wait_updates(server_t* srv){

    node_local_update_t rcv_msg;
    memset(&rcv_msg, 0, sizeof(node_local_update_t));
    size_t out_len = 0;

    if(srv->io.recv(srv->io.obj,(uint8_t*)&rcv_msg, sizeof(node_local_update_t), &out_len) != OK){
        #if DEBUG
        printf("[SERVER] Error in receiving update\n");
        #endif
    }

    if(node_is_present(&srv->J_prime_set, rcv_msg.node_id)) return; //skip it if already present in this round, means the node sent the update twice in the same round

    // Get srv link l0 and l1 to extract the decrypted update
    puf_index_t srv_idx = srv->current_link_srv;
    puf_resp_t l_0 = get_puf_link_srv(srv_idx + OFF_SRV_0);
    puf_resp_t l_1 = get_puf_link_srv(srv_idx + OFF_SRV_1);

    payload_t y_clean = decrypt_puf(rcv_msg.n_0, l_0);
    payload_t y_hat_clean = decrypt_puf(rcv_msg.n_1, l_1);

    // HMAC check == n2?
    puf_resp_t l_2 = get_puf_link_srv(srv_idx + OFF_SRV_2);
    hmac_t calc_hmac;
    sign_payload(y_clean, y_hat_clean, l_2, calc_hmac);

    if(!verify_hmac(calc_hmac, rcv_msg.n_2)){
        printf("[SERVER] HMAC mismatch from node %d\n", rcv_msg.node_id);
        return; 
    }

    #if DEBUG 
    printf("[SERVER] aggregating update from %d\n", rcv_msg.node_id);
    #endif

    // Aggregate partial sum 
    vector_add(srv->aggr_sum, (update_t*)&y_clean);
    vector_add(srv->aggr_verif, (update_t*)&y_hat_clean);

    // Add node to set J of participating nodes 
    node_set_add(&srv->J_prime_set, rcv_msg.node_id);

    // Ci vorrebbe un timeout prima di passare a req_shares? Per ora faccio la transizione direttamente nel main

   /* if(srv->J_prime_set.node_count >= 2){
        srv->current_state = srv_state_req_shares;
    }*/

}

// In this phase, the server sends a broadcast message to all the participating nodes requesting shares to recover both dropout masks and noise shares
void srv_state_req_shares(server_t* srv){
    #if DEBUG
    printf("[SERVER] Calculating dropouts");
    #endif

    // Setup message to send to node
    srv_dropout_list_t srv_drop_msg;
    memset(&srv_drop_msg, 0, sizeof(srv_dropout_list_t));
    srv_drop_msg.type = MSG_SRV_SEND_DROP_LIST;
    srv_drop_msg.srv_id = srv->srv_id;

    // This set contains a list of dropout node IDs 
    srv->Z_set.node_count = 0;

    for(int i = 0; i < srv->J_set.node_count; i++){
        node_id_t id = srv->J_set.node_id[i];
        // If the node is in J but not in J', it means it's a dropout
        if(!node_is_present(&srv->J_prime_set, id)){
            node_set_add(&srv->Z_set, id);
        }
    }

    printf("[SERVER] Dropouts: %d\n", srv->Z_set.node_count);

    memcpy(&srv_drop_msg.n_3, &srv->Z_set, sizeof(node_set_t));

    // Compute HMAC
    puf_index_t srv_idx = srv->current_link_srv;
    puf_resp_t l_3 = get_puf_link_srv(srv_idx + OFF_SRV_3);
    
    sign_node_set(&srv_drop_msg.n_3, l_3, srv_drop_msg.n_4);

    srv->io.send(srv->io.obj, (uint8_t*)&srv_drop_msg, sizeof(srv_drop_msg));

    // Reset context to keep track of currently received shares
    memset(ctx_mask, 0, sizeof(ctx_mask));
    memset(ctx_noise, 0, sizeof(ctx_noise));

    memset(ctx_mask_verif, 0, sizeof(ctx_mask_verif));
    memset(ctx_noise_verif, 0, sizeof(ctx_noise_verif));

    // To store partial mask/noise aggregation results
    memset(srv->dropped_mask_x, 0, sizeof(srv->dropped_mask_x)); 
    memset(srv->droppes_mask_hat, 0, sizeof(srv->droppes_mask_hat)); 
    
    memset(srv->active_noise_x, 0, sizeof(srv->active_noise_x)); 
    memset(srv->active_noise_hat, 0, sizeof(srv->active_noise_hat)); 

    srv->current_state = srv_state_wait_recovery;


}   

// In this phase, the server waits for the shares recovered by the nodes
void srv_state_wait_recovery(server_t* srv){

    node_shares_msg_t share_msg;
    size_t out_len = 0;

    if(srv->io.recv(srv->io.obj, (uint8_t*)&share_msg, sizeof(node_shares_msg_t), &out_len) != OK){
        return; 
    }

    // HMAC == n_6? check msg integrity
    puf_index_t srv_idx = srv->current_link_srv;
    puf_resp_t l_4_srv = get_puf_link_srv(srv_idx + OFF_SRV_4);
    hmac_t calc_hmac;

    sign_shares_list(share_msg.items, share_msg.item_cnt, l_4_srv, calc_hmac);

    if (!verify_hmac(calc_hmac, share_msg.n_6)) {
        #if DEBUG
        printf("[SERVER] HMAC Mismatch from node %d. Ignoring.\n", share_msg.node_id);
        #endif
        return;
    }
    #if DEBUG
    printf("[SERVER] Processing %d shares from node %d\n", share_msg.item_cnt, share_msg.node_id);
    #endif


    // For each share in the received message, check if it belongs to a dropout node or not.
    for(int i = 0; i < share_msg.item_cnt; i++){
        
        share_item_t* item = &share_msg.items[i]; // Share data
        node_id_t helper = share_msg.node_id;  
        node_id_t target = item->target_node_id; 

        recon_ctx_t *ctx_data = NULL;
        recon_ctx_t *ctx_verif = NULL;
        int db_idx_data = -1;
        int db_idx_verif = -1;

        
        if (node_is_present(&srv->Z_set, target)) { // Recover real share for dropout mask
            if (item->type == SHARE_TYPE_NOISE) continue; // error, the node shouldnt be in the dropout set

            ctx_data = &ctx_mask[target];
            ctx_verif = &ctx_mask_verif[target];
            db_idx_data = DB_IDX_MASK_DATA;
            db_idx_verif = DB_IDX_MASK_VERIF;
        } 
        else {
            if (item->type == SHARE_TYPE_MASK) continue;

            ctx_data = &ctx_noise[target];
            ctx_verif = &ctx_noise_verif[target];
            db_idx_data = DB_IDX_NOISE_DATA;
            db_idx_verif = DB_IDX_NOISE_VERIF;
        }

       // If not all shares have been recovered, get the offset and compute the real share = offset ^ H_share
        if (!ctx_data->done) {
            uint8_t* off = server_db_get_offset(helper, target, db_idx_data);
            if(off && ctx_data->count < MAX_NUM_CLIENTS){
                for(int j = 0; j < sss_SHARE_LEN; j++){
                    ctx_data->share[ctx_data->count][j] = item->share_data[j] ^ off[j];
                }
                ctx_data->count++;
                
            }
        }

        if (!ctx_verif->done) {
            uint8_t* off = server_db_get_offset(helper, target, db_idx_verif);
            if(off && ctx_verif->count < MAX_NUM_CLIENTS){
                for(int j = 0; j < sss_SHARE_LEN; j++){
                    ctx_verif->share[ctx_verif->count][j] = item->share_verif[j] ^ off[j];
                }
                ctx_verif->count++;
            }
        }
    }

    uint8_t secret_buf[sss_MLEN];

    for(int t = 0; t < MAX_NUM_CLIENTS; t++){
        // If the node is a dropout, recover shares and add them to the dropped_mask buffer
        if (node_is_present(&srv->Z_set, t)) {
            if (!ctx_mask[t].done && ctx_mask[t].count >= K) {
                if (sss_combine_shares(secret_buf, ctx_mask[t].share, K) == 0) {
                    puf_resp_t val; 
                    memcpy(&val, secret_buf, sizeof(val));
                    vector_add(srv->dropped_mask_x, (update_t*)&val);
                    ctx_mask[t].done = true; // if threshold shares have been reached, mark as done
                    #if DEBUG
                    printf("   -> Recovered Mask Data for Dropout %d\n", t);
                    #endif
                }
            }
            if (!ctx_mask_verif[t].done && ctx_mask_verif[t].count >= K) {
                if (sss_combine_shares(secret_buf, ctx_mask_verif[t].share, K) == 0) {
                    puf_resp_t val; 
                    memcpy(&val, secret_buf, sizeof(val));
                    vector_add(srv->droppes_mask_hat, (update_t*)&val); 
                    ctx_mask_verif[t].done = true;
                    #if DEBUG
                    printf("   -> Recovered Mask Verif for Dropout %d\n", t);
                    #endif
                }
            }
        }
        // Otherwise, it means it's not a dropout and only noise has to be recovered.
        else { 
            if (!ctx_noise[t].done && ctx_noise[t].count >= K) {
                if (sss_combine_shares(secret_buf, ctx_noise[t].share, K) == 0) {
                    puf_resp_t val; 
                    memcpy(&val, secret_buf, sizeof(val));
                    vector_add(srv->active_noise_x, (update_t*)&val); // add to accumulator
                    ctx_noise[t].done = true; // if threshold shares have been reached, mark as done
                }
            }
            if (!ctx_noise_verif[t].done && ctx_noise_verif[t].count >= K) {
                if (sss_combine_shares(secret_buf, ctx_noise_verif[t].share, K) == 0) {
                    puf_resp_t val; 
                    memcpy(&val, secret_buf, sizeof(val));
                    vector_add(srv->active_noise_hat, (update_t*)&val); // add to accumulator
                    ctx_noise_verif[t].done = true;
                }
            }
        }
    }

    if (dropout_recovered(srv) == true) {
        #if DEBUG
        printf("[SERVER] Recovery complete. Finalizing.\n");
        #endif
        srv->current_state = srv_state_compute_global;
    }
}

// In this phase, the server computes the global final update
void srv_state_compute_global(server_t* srv){
    printf("[SERVER] Finalizing Round...\n");

    print_vec_head("1. Aggregate Sum (Encrypted)", srv->aggr_sum);
    print_vec_head("2. TA Mask (Total)", srv->ta_mask_x);
    print_vec_head("3. Dropped Mask (Recovered)", srv->dropped_mask_x);
    print_vec_head("4. Active Noise (Recovered)", srv->active_noise_x);

    srv_global_update_t msg;
    msg.type = MSG_SRV_SEND_GLOBAL_UPDATE;
    msg.srv_id = srv->srv_id;
    
    // Subtract masks and noise. 
    update_t final_sum_vec[UPDATE_LEN];
    memcpy(final_sum_vec, srv->aggr_sum, sizeof(final_sum_vec)); 
    vector_sub(final_sum_vec, srv->ta_mask_x);      
    vector_add(final_sum_vec, srv->dropped_mask_x); 
    vector_sub(final_sum_vec, srv->active_noise_x); 

    // For verification
    update_t final_verif_vec[UPDATE_LEN];
    memcpy(final_verif_vec, srv->aggr_verif, sizeof(final_verif_vec));
    vector_sub(final_verif_vec, srv->ta_mask_hat);       
    vector_add(final_verif_vec, srv->droppes_mask_hat); 
    vector_sub(final_verif_vec, srv->active_noise_hat); 

    payload_t payload_sum, payload_verif;
    
    memcpy(&payload_sum, final_sum_vec, sizeof(payload_t));
    memcpy(&payload_verif, final_verif_vec, sizeof(payload_t));

    puf_index_t srv_idx = srv->current_link_srv;
    puf_resp_t l5 = get_puf_link_srv(srv_idx + OFF_SRV_5);
    puf_resp_t l6 = get_puf_link_srv(srv_idx + OFF_SRV_6);

    // Encrpyt global sum and global sum verif to broadcast to nodes
    msg.n_7 = encrypt_puf(payload_sum, l5);
    msg.n_8 = encrypt_puf(payload_verif, l6);
   
    puf_resp_t l7_key = get_puf_link_srv(srv_idx + OFF_SRV_7);
    sign_payload(msg.n_7, msg.n_8, l7_key, msg.n_9);
    srv->io.send(srv->io.obj, (uint8_t*)&msg, sizeof(msg));

    printf("[SERVER] Global Update Sent. Round Complete.\n");

    // Update link count
    srv->current_link_srv += 8; 
    
    // Reset mem
    server_reset_buffers(srv);
    // Get ready for the next iteration of the protocol
    srv->current_state = srv_state_wait_updates;
}