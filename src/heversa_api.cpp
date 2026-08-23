#include "heversa_api.h"
#include "common.h"
#include "int128.h"
#include "server.h"
#include "ta.h"
#include <string.h>

#include "puf_manager.h"
#include "crypto_utils.h"

static int current_num_clients = MAX_NUM_CLIENTS;

static prot_ret_t dummy_send(void* obj, const uint8_t* data, size_t data_len){
    return OK;
}

static prot_ret_t dummy_recv(void* obj, uint8_t* buffer, size_t max_len, size_t* out_len){
    return OK;
}

void configure_complete_recovery_topology(int num_clients){
    current_num_clients = num_clients;
    recovery_topology_set_complete(num_clients);
}

void configure_recovery_topology(int num_clients, const node_set_t helper_targets[MAX_NUM_CLIENTS]){
    current_num_clients = num_clients;
    recovery_topology_set_custom(num_clients, helper_targets);
}

void ta_setup_protocol(int num_clients, int threshold_value, size_t update_len, server_t* srv){
    current_num_clients = num_clients;
    if(!recovery_topology_is_configured_for(num_clients)){
        recovery_topology_set_complete(num_clients);
    }
    ta_compute_offset(num_clients, threshold_value, update_len, INITIAL_LINK);
    ta_compute_cc_offset(num_clients, threshold_value, INITIAL_LINK);
    
    io_interface_t mock_io = {
        .obj = &srv->srv_id,
        .send = dummy_send,
        .recv = dummy_recv
    };

    server_setup(srv, srv->srv_id, update_len, mock_io);
    server_db_set_threshold(threshold_value);
    srv->J_set.node_count = 0;
    for(int i = 0; i < num_clients; i++){
        node_set_add(&srv->J_set, i);
    }
    ta_send_global_masks(srv, num_clients, update_len, INITIAL_LINK);
}

void client_setup(node_t* node, node_id_t id, size_t update_len){
    io_interface_t mock_io = {
        .obj = &node->node_id,
        .send = dummy_send,
        .recv = dummy_recv
    };

    node_setup(node, id, update_len, mock_io);
    recovery_topology_get_targets(id, &node->K_j);
    node_cc_data(node);
}

void server_broadcast_dropouts(server_t* srv, srv_dropout_list_t* out_msg, node_set_t* out_dropouts){
    srv->current_state = srv_state_req_shares;
    srv->current_out_drop_msg = out_msg;
    server_run_state(srv);
    srv->current_out_drop_msg = nullptr;
    *out_dropouts = srv->Z_set;
}

void client_compute_shares(node_t* node, const srv_dropout_list_t* in_drop_msg, node_shares_msg_t* out_msg){
    node->current_in_drop_msg = const_cast<srv_dropout_list_t*>(in_drop_msg);
    node->current_out_shares = out_msg;

    run_node_state(node);

    node->current_in_drop_msg = nullptr;
    node->current_out_shares = nullptr;
}

void client_mask_update(node_t* node, const uint32_t* weights, size_t len, node_local_update_t* out_msg){
    node->update_len = static_cast<uint32_t>(len);
    node->data_update.resize(len);
    for(size_t i = 0; i < len; i++){
        node->data_update[i] = UInt128::from_uint32(weights[i]);
    }

    node->current_out_update = out_msg;
    run_node_state(node);
    node->current_out_update = nullptr;
}

void server_receive_update(server_t* srv, const node_local_update_t* msg){
    srv->current_in_update = const_cast<node_local_update_t*>(msg);
    server_run_state(srv);
    srv->current_in_update = nullptr;
}

void server_receive_shares(server_t* srv, const node_shares_msg_t* msg){
    srv->current_in_shares = const_cast<node_shares_msg_t*>(msg);
    server_run_state(srv);
    srv->current_in_shares = nullptr;
}

void server_aggregate_updates(server_t* srv, uint32_t* out_model){
    srv_global_update_t out_global;
    srv->current_state = srv_state_compute_global;
    srv->current_out_global_msg = &out_global;

    server_run_state(srv);
    srv->current_out_global_msg = nullptr;

    for(size_t i = 0; i < srv->update_len; i++){
        out_model[i] = srv->clear_res[i].data[0];
    }
}

// ------ CONSISTENCY CHECK ------

void client_compute_cc_value(node_t* node, const srv_dropout_list_t* in_drop_msg, node_cc_msg_t* out_msg){
    node_set_t drop_set = in_drop_msg->n_3;
    node_compute_cc_value(node, &drop_set, out_msg);
}

void server_receive_cc_value_msg(server_t* srv, const node_cc_msg_t* msg){
    server_receive_cc_value(const_cast<node_cc_msg_t*>(msg));
}

bool server_finalize_cc_result(server_t* srv, srv_cc_result_t* out_msg){
    return server_try_compute_cc_result(srv, out_msg);
}

bool client_verify_cc_result(node_t* node, const srv_dropout_list_t* in_drop_msg, const srv_cc_result_t* result_msg){
    node_set_t drop_set = in_drop_msg->n_3;
    return node_verify_cc_result(node, &drop_set, const_cast<srv_cc_result_t*>(result_msg));
}
