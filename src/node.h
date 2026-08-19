#ifndef NODE_H
#define NODE_H

#include "common.h"
#include "common_share.h"
#include "puf_data.h"
#include "msg_type.h"

typedef struct node_s node_t; 
typedef void (*node_state_func_t)(node_t*); //function pointer for FSM


typedef struct {
    ecc_point_t G1;
    ecc_point_t G2;
    ecc_scalar_t y_j;
    ecc_scalar_t z_j;
} node_cc_data_t;

struct node_s{
    node_id_t node_id; //device ID
    srv_id_t srv_id; //ID of the server aggregating the updates

    update_t data_update[UPDATE_LEN]; //update array
    node_state_func_t current_state; //to keep track of the state in the automa

    puf_index_t current_link_ta; //to keep track of the current link used in the protocol
    puf_index_t current_link_srv;

    // J-th node can recover shares for the nodes in the K_j set
    node_set_t K_j;
    
    node_cc_data_t consistency_data;

    //HAL
    io_interface_t io;

};

void node_setup(node_t* node, node_id_t node_id, io_interface_t io);
void run_node_state(node_t* node);

void node_cc_data(node_t* node);
void node_compute_cc_value(node_t* node, node_set_t* dropout_set, node_cc_msg_t* out_msg);
bool node_verify_cc_result(node_t* node, node_set_t* dropout_set, srv_cc_result_t* result_msg);

// --- FSM STATES ---
void node_state_compute_update(node_t* node);
void node_state_wait_for_server(node_t* node);
void node_state_wait_final(node_t* node);
void node_state_error(node_t* node);

#endif