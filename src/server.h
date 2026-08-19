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
    uint8_t offset[UPDATE_LEN][sss_SHARE_LEN];
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

    update_t clear_res[UPDATE_LEN];
    uint32_t iterations_count; // trials counter

    node_set_t J_set;
    node_set_t J_prime_set;
    node_set_t Z_set; //dropouts

    update_t aggr_sum[UPDATE_LEN];
    update_t aggr_verif[UPDATE_LEN];

    //masks sent from the TA
    update_t ta_mask_x[UPDATE_LEN];
    update_t ta_mask_hat[UPDATE_LEN];

    update_t active_noise_x[UPDATE_LEN];
    update_t active_noise_hat[UPDATE_LEN];

    update_t dropped_mask_x[UPDATE_LEN];
    update_t droppes_mask_hat[UPDATE_LEN];
    io_interface_t io;

};

void server_setup(server_t *srv, srv_id_t id, io_interface_t io);
void server_run_state(server_t *srv);
void server_set_ta_sums(server_t* srv, update_t* sum_data, update_t* sum_verif);

// Functions to handle offset DB
void server_db_store_offset(node_id_t helper_id, node_id_t target_id, share_db_idx_t idx, uint8_t offset[UPDATE_LEN][sss_SHARE_LEN]);

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
