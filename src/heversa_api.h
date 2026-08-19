#ifndef HEVERSA_API_H
#define HEVERSA_API_H

#include "node.h"
#include "server.h"
#include "ta.h"
#include "msg_type.h"

void configure_complete_recovery_topology(int num_clients);
void configure_recovery_topology(int num_clients, const node_set_t helper_targets[MAX_NUM_CLIENTS]);

void ta_setup_protocol(int num_clients, int threshold_value, server_t* srv);

void client_setup(node_t* node, node_id_t id);

void client_mask_update(node_t* node, uint32_t* weights, node_local_update_t* out_msg);

void client_compute_shares(node_t* node, srv_dropout_list_t* in_drop_msg, node_shares_msg_t* out_msg);
void server_receive_update(server_t* srv, node_local_update_t* msg);

void server_broadcast_dropouts(server_t* srv, srv_dropout_list_t* out_msg, node_set_t* out_dropouts);

void server_receive_shares(server_t* srv, node_shares_msg_t* msg);

void server_aggregate_updates(server_t* srv, uint32_t* out_model);

// ------ CONSISTENCY CHECK ------
// Client hashes the announced dropout list and computes w_j = h*y_j + z_j
void client_compute_cc_value(node_t* node, srv_dropout_list_t* in_drop_msg, node_cc_msg_t* out_msg);
// Server accumulates w_j values submitted by the nodes this round
void server_receive_cc_value_msg(server_t* srv, node_cc_msg_t* msg);
// Once enough w_j have been collected, interpolate W and fill out_msg. False if not ready yet.
bool server_finalize_cc_result(server_t* srv, srv_cc_result_t* out_msg);
// Client checks the server's W against G1/G2; false means the round must be aborted
bool client_verify_cc_result(node_t* node, srv_dropout_list_t* in_drop_msg, srv_cc_result_t* result_msg);

#endif

