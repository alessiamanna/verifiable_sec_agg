#ifndef HEVERSA_SIM_H
#define HEVERSA_SIM_H

#include "heversa_api.h"

void run_federated_round_sim(
    server_t* srv, 
    node_t* clients, 
    int num_clients, 
    size_t update_len,
    const uint32_t* client_weights, 
    uint32_t* final_out_model
);

#endif
