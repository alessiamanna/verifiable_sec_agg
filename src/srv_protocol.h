#ifndef SRV_PROTOCOL_H
#define SRV_PROTOCOL_H

#include "common.h"
#include "puf_data.h"

typedef struct server_s server_t;
typedef void(*srv_state_function_t)(server_t*);

struct server_s{
    srv_id_t srv_id;

    dev_id_t rcvd_updates[MAX_NUM_CLIENTS];
    int num_devs; //to keep track of current clients

    payload_t cumsum[PUF_ITERATIONS]; //to store cumulative sum to send back to the devs 
    shares_t ta_sum[PUF_ITERATIONS];
    
    srv_state_function_t current_state;
    puf_state_t current_link;
    //HAL 
    io_interface_t io;
};

void process_data(server_t* srv, dev_pckt_t* pckt);
void server_setup(server_t* srv, srv_id_t srv_id, io_interface_t io);
void run_srv_state(server_t* srv);

// FSM STATES
void server_rx(server_t* srv);
void server_tx(server_t* srv);

#endif