#ifndef SERVER_H
#define SERVER_H

#include <string.h>
#include "common.h"
#include "common_share.h"
#include "puf_data.h"
#include "msg_type.h"
#include "sss/sss.h"


// db entry
typedef struct{
    std::vector<uint8_t> offset;
    bool valid;     
} share_offset_entry_t;

// db definition
typedef struct{
    share_offset_entry_t entries[MAX_NUM_CLIENTS][MAX_NUM_CLIENTS][DB_IDX_COUNT];
} server_offset_db_t;

typedef struct server_s server_t;
typedef void(*srv_state_function_t)(server_t*);

struct server_s{
    srv_id_t srv_id;
    srv_state_function_t current_state;

    puf_index_t current_link_srv;
    uint32_t update_len;

    std::vector<update_t> clear_res;
    uint32_t iterations_count; // trials counter

    node_set_t J_set;
    node_set_t J_prime_set;
    node_set_t Z_set; //dropouts

    std::vector<update_t> aggr_sum;
    std::vector<update_t> aggr_verif;

    //masks sent from the TA
    std::vector<update_t> ta_mask_x;
    std::vector<update_t> ta_mask_hat;

    std::vector<update_t> active_noise_x;
    std::vector<update_t> active_noise_hat;

    std::vector<update_t> dropped_mask_x;
    std::vector<update_t> droppes_mask_hat;
    
    // In/out message pointers
    node_local_update_t* current_in_update;
    node_shares_msg_t* current_in_shares;
    srv_dropout_list_t* current_out_drop_msg;
    srv_global_update_t* current_out_global_msg;

    io_interface_t io;

};

void server_setup(server_t *srv, srv_id_t id, size_t update_len, io_interface_t io);
void server_run_state(server_t *srv);
void server_set_ta_sums(server_t* srv, const update_t* sum_data, const update_t* sum_verif, size_t len);

// Functions to handle offset DB
void server_db_store_offset(node_id_t helper_id, node_id_t target_id, share_db_idx_t idx, const uint8_t* offset, size_t update_len);

void server_db_init();

// To recover offset during recovering phase
uint8_t* server_db_get_offset(node_id_t helper_id, node_id_t target_id, share_db_idx_t idx);

void server_db_set_threshold(int k);
void server_db_store_commitments(ecc_point_t G1, ecc_point_t G2);
void server_db_store_offset_cc(node_id_t node_id, uint8_t* offset_y, uint8_t* offset_z);
void server_db_get_commitments(ecc_point_t out_G1, ecc_point_t out_G2);
void server_db_get_offset_cc(node_id_t node_id, uint8_t* out_y, uint8_t* out_z);
void server_receive_cc_value(node_cc_msg_t* msg);
bool server_try_compute_cc_result(server_t* srv, srv_cc_result_t* out_msg);

// ------ FSM STATES ------
void srv_state_wait_updates(server_t* srv);
void srv_state_req_shares(server_t* srv);
void srv_state_wait_recovery(server_t* srv);
void srv_state_compute_global(server_t* srv);

#endif
