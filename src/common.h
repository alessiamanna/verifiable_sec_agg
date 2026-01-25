#ifndef COMMON_H
#define COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define DEBUG 1
#define MAX_NUM_CLIENTS 4 //for now let's consider node A-B-C-D
#define INITIAL_LINK 0 

#define VERIF_A 3
#define VERIF_B 5

#define UPDATE_LEN 8 // for now let's assume 128bit update, 16 bit x 8 components.

#define LINK_MASK_DATA 0
#define LINK_NOISE_DATA 1
#define LINK_MASK_VERIF 2
#define LINK_NOISE_VERIF 3

#define LINK_TA_4 4
#define LINK_TA_5 5
#define LINK_TA_6 6
#define LINK_TA_7 7

#define OFF_SRV_0 0
#define OFF_SRV_1 1
#define OFF_SRV_2 2
#define OFF_SRV_3 3
#define OFF_SRV_4 4
#define OFF_SRV_5 5
#define OFF_SRV_6 6
#define OFF_SRV_7 7
#define OFF_SRV_8 8
#define OFF_SRV_9 9

#define OFF_MASK_DATA 4 //d_{i+4} to recover d_i and so on
#define OFF_NOISE_DATA 5
#define OFF_MASK_VERIF 6
#define OFF_NOISE_VERIF 7

// Define 128bit data type. Requires C23.
typedef unsigned _BitInt(128) uint128_t;

typedef uint128_t payload_t;
typedef uint16_t update_t;
typedef uint128_t protocol_key_t; 

typedef uint16_t node_id_t;
typedef uint16_t srv_id_t;

typedef uint32_t private_key_t;

//enum for protocol states 
typedef enum{
    OK = 0, //send and receive correct
    ERROR = -1,
    TIMEOUT = -2,
}prot_ret_t;

//callbacks for send and receive
//return the protocol state, takes the context and the r/w data as inputs
typedef prot_ret_t(*prt_snd_fn)(void* obj, const uint8_t* data, size_t len);
typedef prot_ret_t(*prt_rcv_fn)(void* obj, uint8_t* buff, size_t max_len, size_t* out_len); //outlen as return parameter


//interface to decouple protocol logic from transport mechanism
typedef struct{
    void* obj; //specific instance of the connection
    prt_snd_fn send; //function to send data
    prt_rcv_fn recv; //function to receive data
} io_interface_t;

// Utility functions

static inline private_key_t calc_hmac_sign(const void* data, size_t data_len, private_key_t key){
    const uint8_t* bytes = (const uint8_t*)data;
    private_key_t hash = key;

    for(size_t i = 0; i < data_len; i++){
        hash = ((hash << 5) + hash) ^ bytes[i];
    }

    return hash;
}



#endif