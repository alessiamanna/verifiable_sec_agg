#ifndef DEV_PROTOCOL_H
#define DEV_PROTOCOL_H

#include "common.h"


typedef struct device_s device_t; 
typedef void (*dev_state_function_t)(device_t*); //function pointer for FSM


struct device_s{
    dev_id_t dev_id; //device ID
    srv_id_t srv_id; //ID of the server aggregating the updates

    update_t data_update[UPDATE_LEN]; //update array
    dev_state_function_t current_state; //to keep track of the state in the automa

    puf_state_t current_link; //to keep track of the current link used in the protocol

    //HAL
    io_interface_t io;

};

void device_setup(device_t* dev, dev_id_t dev_id, io_interface_t io);
void run_device_state(device_t* dev);

// STATES
void device_tx(device_t* dev);
void device_rx(device_t* dev);

#endif