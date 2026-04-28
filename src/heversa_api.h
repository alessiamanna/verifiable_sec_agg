#ifndef HEVERSA_API_H
#define HEVERSA_API_H

#include "node.h"
#include "server.h"
#include "ta.h"
#include "msg_type.h"

void ta_setup_protocol(int num_clients, int threshold_value, server_t* srv);

void client_setup(node_t* node, node_id_t id);

void client_mask_update(node_t* node, uint32_t* weights, node_local_update_t* out_msg);

void client_compute_shares(node_t* node, srv_dropout_list_t* in_drop_msg, node_shares_msg_t* out_msg);
void server_receive_update(server_t* srv, node_local_update_t* msg);

void server_broadcast_dropouts(server_t* srv, srv_dropout_list_t* out_msg, node_set_t* out_dropouts);

void server_receive_shares(server_t* srv, node_shares_msg_t* msg);

void server_aggregate_updates(server_t* srv, uint32_t* out_model);
#endif