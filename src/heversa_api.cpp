#include "heversa_api.h"
#include "common.h"
#include "int128.h"
#include "server.h"
#include "ta.h"
#include <string.h>

#include "puf_manager.h"
#include "crypto_utils.h"

static void* current_out_buffer = NULL;
static const void* current_in_buffer = NULL;
static size_t current_in_len = 0;
static int current_num_clients = MAX_NUM_CLIENTS;

static prot_ret_t mock_send(void* obj, const uint8_t* data, size_t data_len){
    if(current_out_buffer != NULL){
        memcpy(current_out_buffer, data, data_len);
        return OK; 
    }
    return ERROR;
}

static prot_ret_t mock_recv(void* obj, uint8_t* buffer, size_t max_len, size_t* out_len){
    if(current_in_buffer != NULL && current_in_len > 0){
        size_t copy_len = (current_in_len > max_len) ? max_len : current_in_len;
        memcpy(buffer, current_in_buffer, copy_len);
        *out_len = copy_len;

        current_in_buffer = NULL;
        current_in_len = 0;
        return OK;
    }
    return ERROR;
}


void configure_complete_recovery_topology(int num_clients){
    current_num_clients = num_clients;
    recovery_topology_set_complete(num_clients);
}

void configure_recovery_topology(int num_clients, const node_set_t helper_targets[MAX_NUM_CLIENTS]){
    current_num_clients = num_clients;
    recovery_topology_set_custom(num_clients, helper_targets);
}

void ta_setup_protocol(int num_clients, int threshold_value, server_t* srv){
    current_num_clients = num_clients;
    if(!recovery_topology_is_configured_for(num_clients)){
        recovery_topology_set_complete(num_clients);
    }
    ta_compute_offset(num_clients, threshold_value, INITIAL_LINK);
    ta_compute_cc_offset(num_clients, threshold_value, INITIAL_LINK);
    io_interface_t mock_io = {
        .obj = &srv->srv_id,
        .send = mock_send,
        .recv = mock_recv
    };

    server_setup(srv, srv->srv_id, mock_io);
    server_db_set_threshold(threshold_value);
    srv->J_set.node_count = 0;
    for(int i = 0; i < num_clients; i++){
        node_set_add(&srv->J_set, i);
    }
    ta_send_global_masks(srv, num_clients, INITIAL_LINK);

}

void client_setup(node_t* node, node_id_t id){
    io_interface_t mock_io = {
        .obj = &node->node_id,
        .send = mock_send,
        .recv = mock_recv
    };

    node_setup(node, id, mock_io);

    // Initialize K_j: Tell the node it has permission to recover all other clients
    recovery_topology_get_targets(id, &node->K_j);

    // Fetch the consistency check commitments and this node's shares (y_j, z_j)
    node_cc_data(node);
}

void server_broadcast_dropouts(server_t* srv, srv_dropout_list_t* out_msg, node_set_t* out_dropouts){
    srv->current_state = srv_state_req_shares;
    current_out_buffer = (void*)out_msg;
    server_run_state(srv);
    current_out_buffer = NULL;
    *out_dropouts = srv->Z_set;
}

void client_compute_shares(node_t* node, srv_dropout_list_t* in_drop_msg, node_shares_msg_t* out_msg){
    current_in_buffer = (const void*)in_drop_msg;
    current_in_len = sizeof(srv_dropout_list_t);
    current_out_buffer = (void*)out_msg;

    run_node_state(node);

    current_in_buffer = NULL;
    current_in_len = 0;
    current_out_buffer = NULL;
}

void client_mask_update(node_t* node, uint32_t* weights, node_local_update_t* out_msg){
    for(int i = 0; i < UPDATE_LEN; i++){
        node->data_update[i] = UInt128::from_uint32(weights[i]);
    }

    current_out_buffer = (void*)out_msg;
    run_node_state(node);
    current_out_buffer = NULL;
}

void server_receive_update(server_t* srv, node_local_update_t* msg){
    current_in_buffer = (const void*)msg;
    current_in_len = sizeof(node_local_update_t);

    server_run_state(srv);

    current_in_buffer = NULL;
    current_in_len = 0;
}

void server_recover_dropouts(server_t* srv, node_set_t* out_dropouts){
    *out_dropouts = srv->Z_set;
}

void server_receive_shares(server_t* srv, node_shares_msg_t* msg){
    current_in_buffer = (const void*)msg;
    current_in_len = sizeof(node_shares_msg_t);

    server_run_state(srv);

    current_in_buffer = NULL;
    current_in_len = 0;
}

void server_aggregate_updates(server_t* srv, uint32_t* out_model){
    srv->current_state = srv_state_compute_global;

    server_run_state(srv);

    for(int i = 0; i < UPDATE_LEN; i++){
        out_model[i] = srv->clear_res[i].data[0];
    }
}

// ------ CONSISTENCY CHECK ------

void client_compute_cc_value(node_t* node, srv_dropout_list_t* in_drop_msg, node_cc_msg_t* out_msg){
    node_compute_cc_value(node, &in_drop_msg->n_3, out_msg);
}

void server_receive_cc_value_msg(server_t* srv, node_cc_msg_t* msg){
    server_receive_cc_value(msg);
}

bool server_finalize_cc_result(server_t* srv, srv_cc_result_t* out_msg){
    return server_try_compute_cc_result(srv, out_msg);
}

bool client_verify_cc_result(node_t* node, srv_dropout_list_t* in_drop_msg, srv_cc_result_t* result_msg){
    return node_verify_cc_result(node, &in_drop_msg->n_3, result_msg);
}

