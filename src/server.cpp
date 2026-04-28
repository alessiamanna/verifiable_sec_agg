#include "server.h"
#include "common.h"
#include "common_share.h"
#include "puf_data.h"
#include "msg_type.h"
#include "puf_utils.h"
#include "puf_manager.h"
#include "sss/sss.h"
#include "crypto_utils.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define K 2 // SSS Threshold


// DB to store the offsets precomputed by the Trusted Authority
static server_offset_db_t offset_db;

// Keeps reconstruction context for both verifiability and data
static recon_ctx_t ctx_mask[MAX_NUM_CLIENTS];
static recon_ctx_t ctx_noise[MAX_NUM_CLIENTS];

static recon_ctx_t ctx_mask_verif[MAX_NUM_CLIENTS]; 
static recon_ctx_t ctx_noise_verif[MAX_NUM_CLIENTS];

typedef struct{
    recon_ctx_t* ctx_data;
    recon_ctx_t* ctx_verif;

    int db_idx_data;
    int db_idx_verif;
} share_target_t;


// Utility to print, remove later
static void print_vec_head(const char* label, update_t* vec) {
    #if DEBUG
    printf("   [%s] First element: %u\n", label, vec[0].data[0]); 
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
    memset(&offset_db, 0, sizeof(offset_db));
}

// Store offsets
void server_db_store_offset(node_id_t helper, node_id_t target, share_db_idx_t idx, uint8_t offset[UPDATE_LEN][sss_SHARE_LEN]) {
    if (helper >= MAX_NUM_CLIENTS || target >= MAX_NUM_CLIENTS  || idx >= DB_IDX_COUNT) {
        #if DEBUG
            printf("[SERVER DB] Error Store: Node ID out of bounds (H:%d, T:%d)\n", helper, target);
        #endif
        return;
    }

    share_offset_entry_t* e = &offset_db.entries[helper][target][idx];

    memcpy(e->offset, offset, UPDATE_LEN * sss_SHARE_LEN);
    e->valid = true;
}


// Function to retrieve offset value
uint8_t* server_db_get_offset(node_id_t helper, node_id_t target, share_db_idx_t idx) {
    if (helper >= MAX_NUM_CLIENTS || target >= MAX_NUM_CLIENTS || idx >= DB_IDX_COUNT) {
        return NULL; 
    }
    share_offset_entry_t* e = &offset_db.entries[helper][target][idx];
    
    if(e->valid){
        return (uint8_t*)e->offset;
    }
    return NULL;
}

static bool dropout_recovered(server_t* srv){
    for(int i=0; i<srv->Z_set.node_count; i++) {
        node_id_t d_id = srv->Z_set.node_id[i];
        if (!ctx_mask[d_id].done || !ctx_mask_verif[d_id].done) {
            return false;
        }
    }

    for(int i=0; i<srv->J_prime_set.node_count; i++) {
        node_id_t a_id = srv->J_prime_set.node_id[i];
        if (!ctx_noise[a_id].done || !ctx_noise_verif[a_id].done) {
            return false;
        }
    }
    return true;
}


// functions to handle shares

static bool get_share_target(server_t* srv, share_item_t* item, node_id_t target, share_target_t* out_target){

    #if DEBUG
    printf("[ROUTE] target=%d type=%d is_dropout=%d\n",
           target,
           item->type,
           node_is_present(&srv->Z_set, target));
    #endif

    printf("[ROUTE] Z_set contents: ");
for (int i = 0; i < srv->Z_set.node_count; i++)
    printf("%d ", srv->Z_set.node_id[i]);
printf("\n");

    if(node_is_present(&srv->Z_set, target)){
        if(item->type == SHARE_TYPE_NOISE) return false;
        // If the target is a dropout, we need to recover both mask and noise shares to reconstruct the dropout mask
        out_target->ctx_data = &ctx_mask[target];
        out_target->ctx_verif = &ctx_mask_verif[target];
        out_target->db_idx_data = DB_IDX_MASK_DATA;
        out_target->db_idx_verif = DB_IDX_MASK_VERIF;
    }
    else{
        // If the target is active, we only need to recover the noise shares to remove the noise from the aggregated sum
        if(item->type == SHARE_TYPE_MASK) return false;
        out_target->ctx_data = &ctx_noise[target];
        out_target->ctx_verif = &ctx_noise_verif[target];
        out_target->db_idx_data = DB_IDX_NOISE_DATA;
        out_target->db_idx_verif = DB_IDX_NOISE_VERIF;
    }
    return true;
}


static void accumulate_share(recon_ctx_t* ctx, node_id_t helper, node_id_t target, int db_idx, uint8_t raw_share[UPDATE_LEN][sss_SHARE_LEN]){
    if(ctx->done || ctx->count >= MAX_NUM_CLIENTS) return;
    
    uint8_t* off_ptr = server_db_get_offset(helper, target, static_cast<share_db_idx_t>(db_idx));    
    if(!off_ptr) return;
    
    uint8_t (*off)[sss_SHARE_LEN] = (uint8_t (*)[sss_SHARE_LEN])off_ptr;

    for(int m = 0; m < UPDATE_LEN; m++) {
        for(size_t j = 0; j < sss_SHARE_LEN; j++){
            ctx->share[m][ctx->count][j] = raw_share[m][j] ^ off[m][j];
        }
    }
    ctx->count++;
}

static void try_reconstruction(recon_ctx_t* ctx, update_t* buffer_acc){
    if(ctx->done || ctx->count < K) return;
    
    update_t recovered_vector[UPDATE_LEN];
    int success_count = 0;

    for(int m = 0; m < UPDATE_LEN; m++) {
        uint8_t secret_buff[sss_MLEN];
        if(sss_combine_shares(secret_buff, ctx->share[m], K) == 0){
            memcpy(&recovered_vector[m], secret_buff, sizeof(update_t));
            success_count++;
        }
    }

    // Only commit if all components of the vector reconstructed successfully
    if(success_count == UPDATE_LEN) {
        vector_add(buffer_acc, recovered_vector);
        ctx->done = true; 
    }
}

static void compute_dropout_set(server_t* srv){
    // This set contains a list of dropout node IDs 
    srv->Z_set.node_count = 0;

    for(int i = 0; i < srv->J_set.node_count; i++){
        node_id_t id = srv->J_set.node_id[i];
        // If the node is in J but not in J', it means it's a dropout
        if(!node_is_present(&srv->J_prime_set, id)){
            node_set_add(&srv->Z_set, id);
        }
    }

}

static void compute_global_result(update_t* out_vec, update_t* aggr, update_t* ta_mask, update_t* dropped_mask, update_t* active_noise){
    memcpy(out_vec, aggr, sizeof(update_t)*UPDATE_LEN);
    vector_sub(out_vec, ta_mask);
    vector_add(out_vec, dropped_mask);
    vector_sub(out_vec, active_noise);
  
}

static void reset_ctx(server_t* srv){
    memset(ctx_mask,        0, sizeof(ctx_mask));
    memset(ctx_noise,       0, sizeof(ctx_noise));
    memset(ctx_mask_verif,  0, sizeof(ctx_mask_verif));
    memset(ctx_noise_verif, 0, sizeof(ctx_noise_verif));
    memset(srv->dropped_mask_x,   0, sizeof(srv->dropped_mask_x));
    memset(srv->droppes_mask_hat, 0, sizeof(srv->droppes_mask_hat));
    memset(srv->active_noise_x,   0, sizeof(srv->active_noise_x));
    memset(srv->active_noise_hat, 0, sizeof(srv->active_noise_hat));
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

    if(srv->io.recv(srv->io.obj,(uint8_t*)&rcv_msg, sizeof(node_local_update_t), &out_len) != OK || out_len == 0){
        srv->iterations_count++;

        if(srv->iterations_count > 5 && srv->J_prime_set.node_count >= 2){
            #if DEBUG
            printf("[SERVER] Timeout, received from %d nodes, starting recovery phase\n", srv->J_prime_set.node_count);
            #endif
            srv->iterations_count = 0;
            srv->current_state = srv_state_req_shares;
        }
        return;
    }

    srv->iterations_count = 0;

    if(node_is_present(&srv->J_prime_set, rcv_msg.node_id)) return; //skip it if already present in this round, means the node sent the update twice in the same round

    transport_chain_t srv_chain;
    get_transport_chain(srv->current_link_srv, &srv_chain);

    update_t y_clean[UPDATE_LEN];
    update_t y_hat_clean[UPDATE_LEN];

    for(int i = 0; i < UPDATE_LEN; i++){
     y_clean[i] = decrypt_puf(rcv_msg.n_0[i], srv_chain.l_0_data);
     y_hat_clean[i] = decrypt_puf(rcv_msg.n_1[i], srv_chain.l_1_verif);
    }
 
    hmac_t calc_hmac;
    sign_payload(y_clean, y_hat_clean, srv_chain.l_2_hmac_local, calc_hmac);

    if(!verify_hmac(calc_hmac, rcv_msg.n_2)){
        printf("[SERVER] HMAC mismatch from node %d\n", rcv_msg.node_id);
        return; 
    }

    #if DEBUG 
    printf("[SERVER] aggregating update from %d\n", rcv_msg.node_id);
    #endif

    // Aggregate partial sum 
    vector_add(srv->aggr_sum, y_clean);
    vector_add(srv->aggr_verif, y_hat_clean);
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
    compute_dropout_set(srv);
    // Setup message to send to node
    srv_dropout_list_t srv_drop_msg;
    memset(&srv_drop_msg, 0, sizeof(srv_dropout_list_t));
    srv_drop_msg.type = MSG_SRV_SEND_DROP_LIST;
    srv_drop_msg.srv_id = srv->srv_id;

    
    printf("[SERVER] Dropouts: %d\n", srv->Z_set.node_count);
    memcpy(&srv_drop_msg.n_3, &srv->Z_set, sizeof(node_set_t));

    // Compute HMAC
    transport_chain_t srv_chain;
    get_transport_chain(srv->current_link_srv, &srv_chain);
    sign_node_set(&srv->Z_set, srv_chain.l_3_hmac_drop, srv_drop_msg.n_4);

    srv->io.send(srv->io.obj, (uint8_t*)&srv_drop_msg, sizeof(srv_drop_msg));

    // Reset context to keep track of currently received shares
    reset_ctx(srv);
    srv->current_state = srv_state_wait_recovery;
}   

// In this phase, the server waits for the shares recovered by the nodes

//this can be refactored 
void srv_state_wait_recovery(server_t* srv){

    node_shares_msg_t share_msg;
    size_t out_len = 0;

    if(srv->io.recv(srv->io.obj, (uint8_t*)&share_msg, sizeof(node_shares_msg_t), &out_len) != OK){
        return; 
    }

    transport_chain_t srv_chain;
    get_transport_chain(srv->current_link_srv, &srv_chain);
    hmac_t calc_hmac;

    sign_shares_list(share_msg.items, share_msg.item_cnt, srv_chain.l_4_hmac_shares, calc_hmac);

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
    for(share_cnt_t i = 0; i < share_msg.item_cnt; i++){
        
        share_item_t* item = &share_msg.items[i]; // Share data
        node_id_t helper = share_msg.node_id;  
        node_id_t target = item->target_node_id; 

        share_target_t share_target;
        if(!get_share_target(srv, item, target, &share_target)){
            #if DEBUG
            printf("[SERVER] Invalid share type %d for target %d. Ignoring.\n", item->type, target);
            #endif
            continue; // skip invalid shares
        }

        accumulate_share(share_target.ctx_data, helper, target, share_target.db_idx_data, item->share_data);
        accumulate_share(share_target.ctx_verif, helper, target, share_target.db_idx_verif, item->share_verif);
    }

    for(int t = 0; t < MAX_NUM_CLIENTS; t++){
        // If the node is a dropout, recover shares and add them to the dropped_mask buffer
        if (node_is_present(&srv->Z_set, t)) {
           try_reconstruction(&ctx_mask[t], srv->dropped_mask_x);
           try_reconstruction(&ctx_mask_verif[t], srv->droppes_mask_hat);
        }
        // Otherwise, it means it's not a dropout and only noise has to be recovered.
        else { 
                try_reconstruction(&ctx_noise[t], srv->active_noise_x);
                try_reconstruction(&ctx_noise_verif[t], srv->active_noise_hat);
        }
    }

    if (dropout_recovered(srv) == true) {
        #if DEBUG
        printf("[SERVER] Recovery complete. Finalizing.\n");
        #endif
        //srv->current_state = srv_state_compute_global;
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
    msg.num_participants = srv->J_prime_set.node_count;

    compute_global_result(srv->clear_res, srv->aggr_sum, srv->ta_mask_x, srv->dropped_mask_x, srv->active_noise_x);
   
    // For verification
    update_t final_verif_vec[UPDATE_LEN];
    compute_global_result(final_verif_vec, srv->aggr_verif, srv->ta_mask_hat, srv->droppes_mask_hat, srv->active_noise_hat);

    transport_chain_t srv_chain;
    get_transport_chain(srv->current_link_srv, &srv_chain);
    // Encrpyt global sum and global sum verif to broadcast to nodes
    for(int i = 0; i < UPDATE_LEN; i++){
        msg.n_7[i] = encrypt_puf(srv->clear_res[i], srv_chain.l_5_final_data);
        msg.n_8[i] = encrypt_puf(final_verif_vec[i], srv_chain.l_6_final_verif);
    }
   
    sign_payload(msg.n_7, msg.n_8, srv_chain.l_7_global, msg.n_9);
    srv->io.send(srv->io.obj, (uint8_t*)&msg, sizeof(msg));
    printf("[SERVER] Global Update Sent. Round Complete.\n");

    // Update link count
    srv->current_link_srv += TRANSPORT_CHAIN_LEN; 
    
    // Reset mem
    server_reset_buffers(srv);
    // Get ready for the next iteration of the protocol
    srv->current_state = srv_state_wait_updates;
}