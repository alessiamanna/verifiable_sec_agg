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
#include <algorithm>

// SSS reconstruction threshold. Must match the threshold used by the TA when
// it created the shares (ta_compute_offset)
static int sss_threshold = 2;

// DB to store the offsets precomputed by the Trusted Authority
static server_offset_db_t offset_db;

// DB to store the consistency check public commitments and per-node offsets
typedef struct{
    uint8_t offset_y[ECC_SCALAR_LEN];
    uint8_t offset_z[ECC_SCALAR_LEN];
    bool valid;
} cc_offset_entry_t;

static ecc_point_t cc_commit_G1;
static ecc_point_t cc_commit_G2;
static bool cc_commitments_valid = false;
static cc_offset_entry_t cc_offset_db[MAX_NUM_CLIENTS];

// Collects w_j = h*y_j + z_j values submitted by nodes during the consistency
// check round, then Lagrange-interpolates them at x=0 once enough have arrived.
typedef struct{
    node_id_t node_ids[MAX_NUM_CLIENTS];
    ecc_scalar_t w[MAX_NUM_CLIENTS];
    int count;
    bool done;
} cc_check_ctx_t;

static cc_check_ctx_t cc_check_ctx;

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


// Utility to print
static void print_vec_head(const char* label, const std::vector<update_t>& vec) {
    #if DEBUG
    if (!vec.empty()) {
        printf("   [%s] First element: %u\n", label, vec[0].data[0]); 
    }
    #endif
}

//------ UTILITY FUNCTIONS ------

static void server_reset_buffers(server_t* srv){
    std::fill(srv->aggr_sum.begin(), srv->aggr_sum.end(), UInt128{0,0,0,0});
    std::fill(srv->aggr_verif.begin(), srv->aggr_verif.end(), UInt128{0,0,0,0});
    std::fill(srv->dropped_mask_x.begin(), srv->dropped_mask_x.end(), UInt128{0,0,0,0});
    std::fill(srv->droppes_mask_hat.begin(), srv->droppes_mask_hat.end(), UInt128{0,0,0,0});
    std::fill(srv->active_noise_x.begin(), srv->active_noise_x.end(), UInt128{0,0,0,0});
    std::fill(srv->active_noise_hat.begin(), srv->active_noise_hat.end(), UInt128{0,0,0,0});
    srv->J_prime_set.node_count = 0;
    srv->Z_set.node_count = 0;
}

static void vector_add(update_t* acc, const update_t* input, size_t len) {
    for(size_t i = 0; i < len; i++) acc[i] += input[i];
}

static void vector_sub(update_t* acc, const update_t* input, size_t len) {
    for(size_t i = 0; i < len; i++) acc[i] -= input[i];
}

// ------ SERVER FUNCTIONS ------

void server_db_set_threshold(int k){
    sss_threshold = k;
}

void server_db_init(){
    for(int i = 0; i < MAX_NUM_CLIENTS; i++){
        for(int j = 0; j < MAX_NUM_CLIENTS; j++){
            for(int k = 0; k < DB_IDX_COUNT; k++){
                offset_db.entries[i][j][k].valid = false;
                offset_db.entries[i][j][k].offset.clear();
            }
        }
    }
    memset(cc_commit_G1, 0, sizeof(cc_commit_G1));
    memset(cc_commit_G2, 0, sizeof(cc_commit_G2));
    cc_commitments_valid = false;
    memset(cc_offset_db, 0, sizeof(cc_offset_db));
    memset(&cc_check_ctx, 0, sizeof(cc_check_ctx));
}

void server_db_store_commitments(ecc_point_t G1, ecc_point_t G2){
    memcpy(cc_commit_G1, G1, ECC_POINT_LEN);
    memcpy(cc_commit_G2, G2, ECC_POINT_LEN);
    cc_commitments_valid = true;
}

void server_db_store_offset_cc(node_id_t target, uint8_t* offset_y, uint8_t* offset_z){
    if(target >= MAX_NUM_CLIENTS){
        #if DEBUG
            printf("[SERVER DB] Error Store CC: Node ID out of bounds (T:%d)\n", target);
        #endif
        return;
    }
    memcpy(cc_offset_db[target].offset_y, offset_y, ECC_SCALAR_LEN);
    memcpy(cc_offset_db[target].offset_z, offset_z, ECC_SCALAR_LEN);
    cc_offset_db[target].valid = true;
}

void server_db_get_commitments(ecc_point_t G1, ecc_point_t G2){
    if(!cc_commitments_valid){
        #if DEBUG
            printf("[SERVER DB] Error Get: CC commitments not initialized\n");
        #endif
        return;
    }
    memcpy(G1, cc_commit_G1, ECC_POINT_LEN);
    memcpy(G2, cc_commit_G2, ECC_POINT_LEN);
}

void server_db_get_offset_cc(node_id_t target, uint8_t* out_off_y, uint8_t* out_off_z){
    if(target >= MAX_NUM_CLIENTS || !cc_offset_db[target].valid){
        #if DEBUG
            printf("[SERVER DB] Error Get CC: Node ID out of bounds or not set (T:%d)\n", target);
        #endif
        return;
    }
    memcpy(out_off_y, cc_offset_db[target].offset_y, ECC_SCALAR_LEN);
    memcpy(out_off_z, cc_offset_db[target].offset_z, ECC_SCALAR_LEN);
}

void server_receive_cc_value(node_cc_msg_t* msg){
    if(cc_check_ctx.count >= MAX_NUM_CLIENTS) return;
    for(int i = 0; i < cc_check_ctx.count; i++){
        if(cc_check_ctx.node_ids[i] == msg->node_id) return;
    }
    cc_check_ctx.node_ids[cc_check_ctx.count] = msg->node_id;
    memcpy(cc_check_ctx.w[cc_check_ctx.count], msg->w_j, ECC_SCALAR_LEN);
    cc_check_ctx.count++;
}

bool server_try_compute_cc_result(server_t* srv, srv_cc_result_t* out_msg){
    if(cc_check_ctx.count < sss_threshold) return false;

    ecc_scalar_t W;
    ecc_shamir_interpolate_at_zero(cc_check_ctx.node_ids, cc_check_ctx.w, sss_threshold, W);

    out_msg->type = MSG_SRV_SEND_CC_RESULT;
    out_msg->srv_id = srv->srv_id;
    memcpy(out_msg->W, W, ECC_SCALAR_LEN);

    cc_check_ctx.done = true;
    return true;
}

void server_db_store_offset(node_id_t helper, node_id_t target, share_db_idx_t idx, const uint8_t* offset, size_t update_len) {
    if (helper >= MAX_NUM_CLIENTS || target >= MAX_NUM_CLIENTS  || idx >= DB_IDX_COUNT) {
        #if DEBUG
            printf("[SERVER DB] Error Store: Node ID out of bounds (H:%d, T:%d)\n", helper, target);
        #endif
        return;
    }

    share_offset_entry_t* e = &offset_db.entries[helper][target][idx];
    e->offset.assign(offset, offset + update_len * sss_SHARE_LEN);
    e->valid = true;
}

uint8_t* server_db_get_offset(node_id_t helper, node_id_t target, share_db_idx_t idx) {
    if (helper >= MAX_NUM_CLIENTS || target >= MAX_NUM_CLIENTS || idx >= DB_IDX_COUNT) {
        return NULL; 
    }
    share_offset_entry_t* e = &offset_db.entries[helper][target][idx];
    
    if(e->valid){
        return e->offset.data();
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
        out_target->ctx_data = &ctx_mask[target];
        out_target->ctx_verif = &ctx_mask_verif[target];
        out_target->db_idx_data = DB_IDX_MASK_DATA;
        out_target->db_idx_verif = DB_IDX_MASK_VERIF;
    }
    else{
        if(item->type == SHARE_TYPE_MASK) return false;
        out_target->ctx_data = &ctx_noise[target];
        out_target->ctx_verif = &ctx_noise_verif[target];
        out_target->db_idx_data = DB_IDX_NOISE_DATA;
        out_target->db_idx_verif = DB_IDX_NOISE_VERIF;
    }
    return true;
}

static void accumulate_share(recon_ctx_t* ctx, node_id_t helper, node_id_t target, int db_idx, const uint8_t* raw_share, size_t update_len){
    if(ctx->done || ctx->count >= MAX_NUM_CLIENTS) return;
    
    uint8_t* off_ptr = server_db_get_offset(helper, target, static_cast<share_db_idx_t>(db_idx));    
    if(!off_ptr) return;

    if (ctx->share.size() != update_len) {
        ctx->share.assign(update_len, std::vector<sss_share_t>(MAX_NUM_CLIENTS));
    }

    for(size_t m = 0; m < update_len; m++) {
        for(size_t j = 0; j < sss_SHARE_LEN; j++){
            size_t idx = m * sss_SHARE_LEN + j;
            ctx->share[m][ctx->count][j] = raw_share[idx] ^ off_ptr[idx];
        }
    }
    ctx->count++;
}

static void try_reconstruction(recon_ctx_t* ctx, update_t* buffer_acc, size_t update_len){
    if(ctx->done || ctx->count < sss_threshold) return;

    std::vector<update_t> recovered_vector(update_len);
    size_t success_count = 0;

    for(size_t m = 0; m < update_len; m++) {
        uint8_t secret_buff[sss_MLEN];
        if(sss_combine_shares(secret_buff, reinterpret_cast<const sss_Share*>(ctx->share[m].data()), sss_threshold) == 0){
            memcpy(&recovered_vector[m], secret_buff, sizeof(update_t));
            success_count++;
        }
    }

    if(success_count == update_len) {
        vector_add(buffer_acc, recovered_vector.data(), update_len);
        ctx->done = true; 
    }
}

static void compute_dropout_set(server_t* srv){
    srv->Z_set.node_count = 0;
    for(int i = 0; i < srv->J_set.node_count; i++){
        node_id_t id = srv->J_set.node_id[i];
        if(!node_is_present(&srv->J_prime_set, id)){
            node_set_add(&srv->Z_set, id);
        }
    }
}

static void compute_global_result(update_t* out_vec, const update_t* aggr, const update_t* ta_mask, const update_t* dropped_mask, const update_t* active_noise, size_t len){
    memcpy(out_vec, aggr, sizeof(update_t) * len);
    vector_sub(out_vec, ta_mask, len);
    vector_add(out_vec, dropped_mask, len);
    vector_sub(out_vec, active_noise, len);
}

static void reset_ctx(server_t* srv){
    for(int i = 0; i < MAX_NUM_CLIENTS; i++){
        ctx_mask[i].share.assign(srv->update_len, std::vector<sss_share_t>(MAX_NUM_CLIENTS));
        ctx_mask[i].count = 0;
        ctx_mask[i].done = false;

        ctx_noise[i].share.assign(srv->update_len, std::vector<sss_share_t>(MAX_NUM_CLIENTS));
        ctx_noise[i].count = 0;
        ctx_noise[i].done = false;

        ctx_mask_verif[i].share.assign(srv->update_len, std::vector<sss_share_t>(MAX_NUM_CLIENTS));
        ctx_mask_verif[i].count = 0;
        ctx_mask_verif[i].done = false;

        ctx_noise_verif[i].share.assign(srv->update_len, std::vector<sss_share_t>(MAX_NUM_CLIENTS));
        ctx_noise_verif[i].count = 0;
        ctx_noise_verif[i].done = false;
    }
    std::fill(srv->dropped_mask_x.begin(), srv->dropped_mask_x.end(), UInt128{0,0,0,0});
    std::fill(srv->droppes_mask_hat.begin(), srv->droppes_mask_hat.end(), UInt128{0,0,0,0});
    std::fill(srv->active_noise_x.begin(), srv->active_noise_x.end(), UInt128{0,0,0,0});
    std::fill(srv->active_noise_hat.begin(), srv->active_noise_hat.end(), UInt128{0,0,0,0});
    memset(&cc_check_ctx, 0, sizeof(cc_check_ctx));
}

void server_setup(server_t *srv, srv_id_t id, size_t update_len, io_interface_t io){
    srv->srv_id = id;
    srv->io = io;
    srv->current_link_srv = INITIAL_LINK;
    srv->update_len = static_cast<uint32_t>(update_len);

    srv->clear_res.assign(update_len, UInt128{0,0,0,0});
    srv->aggr_sum.assign(update_len, UInt128{0,0,0,0});
    srv->aggr_verif.assign(update_len, UInt128{0,0,0,0});
    srv->ta_mask_x.assign(update_len, UInt128{0,0,0,0});
    srv->ta_mask_hat.assign(update_len, UInt128{0,0,0,0});
    srv->active_noise_x.assign(update_len, UInt128{0,0,0,0});
    srv->active_noise_hat.assign(update_len, UInt128{0,0,0,0});
    srv->dropped_mask_x.assign(update_len, UInt128{0,0,0,0});
    srv->droppes_mask_hat.assign(update_len, UInt128{0,0,0,0});

    srv->J_set.node_count = 0;
    srv->J_prime_set.node_count = 0;

    for(int i = 0; i < MAX_NUM_CLIENTS; i++){
        node_set_add(&srv->J_set, i); 
    }

    srv->current_state = srv_state_wait_updates; 
}

void server_set_ta_sums(server_t* srv, const update_t* sum_data, const update_t* sum_verif, size_t len){
    srv->ta_mask_x.assign(sum_data, sum_data + len);
    srv->ta_mask_hat.assign(sum_verif, sum_verif + len);
}

void srv_state_wait_updates(server_t* srv){
    node_local_update_t rcv_msg;
    if (srv->current_in_update) {
        rcv_msg = *srv->current_in_update;
    } else {
        return;
    }

    if(node_is_present(&srv->J_prime_set, rcv_msg.node_id)) return;

    transport_chain_t srv_chain;
    get_transport_chain(srv->current_link_srv, &srv_chain);

    size_t len = srv->update_len;
    std::vector<update_t> y_clean(len);
    std::vector<update_t> y_hat_clean(len);

    for(size_t i = 0; i < len; i++){
        y_clean[i] = decrypt_puf(rcv_msg.n_0[i], srv_chain.l_0_data);
        y_hat_clean[i] = decrypt_puf(rcv_msg.n_1[i], srv_chain.l_1_verif);
    }
 
    hmac_t calc_hmac;
    sign_payload(y_clean.data(), y_hat_clean.data(), len, srv_chain.l_2_hmac_local, calc_hmac);

    if(!verify_hmac(calc_hmac, rcv_msg.n_2)){
        printf("[SERVER] HMAC mismatch from node %d\n", rcv_msg.node_id);
        return; 
    }

    #if DEBUG 
    printf("[SERVER] aggregating update from %d\n", rcv_msg.node_id);
    #endif

    vector_add(srv->aggr_sum.data(), y_clean.data(), len);
    vector_add(srv->aggr_verif.data(), y_hat_clean.data(), len);
    node_set_add(&srv->J_prime_set, rcv_msg.node_id);
}

void srv_state_req_shares(server_t* srv){
    #if DEBUG
    printf("[SERVER] Calculating dropouts");
    #endif
    compute_dropout_set(srv);
    printf("[SERVER] Dropouts: %d\n", srv->Z_set.node_count);

    if (srv->current_out_drop_msg) {
        srv->current_out_drop_msg->type = MSG_SRV_SEND_DROP_LIST;
        srv->current_out_drop_msg->srv_id = srv->srv_id;
        memcpy(&srv->current_out_drop_msg->n_3, &srv->Z_set, sizeof(node_set_t));

        transport_chain_t srv_chain;
        get_transport_chain(srv->current_link_srv, &srv_chain);
        sign_node_set(&srv->Z_set, srv_chain.l_3_hmac_drop, srv->current_out_drop_msg->n_4);
    }

    reset_ctx(srv);
    srv->current_state = srv_state_wait_recovery;
}   

void srv_state_wait_recovery(server_t* srv){
    node_shares_msg_t share_msg;
    if (srv->current_in_shares) {
        share_msg = *srv->current_in_shares;
    } else {
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

    size_t len = srv->update_len;

    for(share_cnt_t i = 0; i < share_msg.item_cnt; i++){
        share_item_t* item = &share_msg.items[i];
        node_id_t helper = share_msg.node_id;  
        node_id_t target = item->target_node_id; 

        share_target_t share_target;
        if(!get_share_target(srv, item, target, &share_target)){
            #if DEBUG
            printf("[SERVER] Invalid share type %d for target %d. Ignoring.\n", item->type, target);
            #endif
            continue;
        }

        accumulate_share(share_target.ctx_data, helper, target, share_target.db_idx_data, item->share_data.data(), len);
        accumulate_share(share_target.ctx_verif, helper, target, share_target.db_idx_verif, item->share_verif.data(), len);
    }

    for(int t = 0; t < MAX_NUM_CLIENTS; t++){
        if (node_is_present(&srv->Z_set, t)) {
           try_reconstruction(&ctx_mask[t], srv->dropped_mask_x.data(), len);
           try_reconstruction(&ctx_mask_verif[t], srv->droppes_mask_hat.data(), len);
        } else { 
           try_reconstruction(&ctx_noise[t], srv->active_noise_x.data(), len);
           try_reconstruction(&ctx_noise_verif[t], srv->active_noise_hat.data(), len);
        }
    }

    if (dropout_recovered(srv) == true) {
        #if DEBUG
        printf("[SERVER] Recovery complete. Finalizing.\n");
        #endif
    }
}

void srv_state_compute_global(server_t* srv){
    printf("[SERVER] Finalizing Round...\n");

    print_vec_head("1. Aggregate Sum (Encrypted)", srv->aggr_sum);
    print_vec_head("2. TA Mask (Total)", srv->ta_mask_x);
    print_vec_head("3. Dropped Mask (Recovered)", srv->dropped_mask_x);
    print_vec_head("4. Active Noise (Recovered)", srv->active_noise_x);

    size_t len = srv->update_len;
    compute_global_result(srv->clear_res.data(), srv->aggr_sum.data(), srv->ta_mask_x.data(), srv->dropped_mask_x.data(), srv->active_noise_x.data(), len);
   
    std::vector<update_t> final_verif_vec(len);
    compute_global_result(final_verif_vec.data(), srv->aggr_verif.data(), srv->ta_mask_hat.data(), srv->droppes_mask_hat.data(), srv->active_noise_hat.data(), len);

    transport_chain_t srv_chain;
    get_transport_chain(srv->current_link_srv, &srv_chain);

    if (srv->current_out_global_msg) {
        srv->current_out_global_msg->type = MSG_SRV_SEND_GLOBAL_UPDATE;
        srv->current_out_global_msg->srv_id = srv->srv_id;
        srv->current_out_global_msg->num_participants = srv->J_prime_set.node_count;
        srv->current_out_global_msg->len = static_cast<uint32_t>(len);
        srv->current_out_global_msg->n_7.resize(len);
        srv->current_out_global_msg->n_8.resize(len);

        for(size_t i = 0; i < len; i++){
            srv->current_out_global_msg->n_7[i] = encrypt_puf(srv->clear_res[i], srv_chain.l_5_final_data);
            srv->current_out_global_msg->n_8[i] = encrypt_puf(final_verif_vec[i], srv_chain.l_6_final_verif);
        }
       
        sign_payload(srv->current_out_global_msg->n_7.data(), srv->current_out_global_msg->n_8.data(), len, srv_chain.l_7_global, srv->current_out_global_msg->n_9);
        printf("[SERVER] Global Update Sent. Round Complete.\n");
    }

    srv->current_link_srv += TRANSPORT_CHAIN_LEN; 
    server_reset_buffers(srv);
    srv->current_state = srv_state_wait_updates;
}

void server_run_state(server_t *srv){
    if(srv->current_state){
        srv->current_state(srv);
    }
}
