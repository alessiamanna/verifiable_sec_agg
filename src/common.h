#ifndef COMMON_H
#define COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define DEBUG 1
#define MAX_NUM_CLIENTS 4 //for now let's consider node A-B-C-D
#define INITIAL_LINK 0 


//TODO: these values should be generated through a random seed 
#define VERIF_A 3
#define VERIF_B 5

#define UPDATE_LEN 8 // for now let's assume 128bit update, 16 bit x 8 components.
#define SHA256_DIGEST 32

// Define 128bit data type. Requires C23.
typedef unsigned _BitInt(128) uint128_t;

// define puf response
typedef uint128_t puf_resp_t;

//define puf link, index in the array
typedef uint8_t puf_index_t;

typedef uint128_t payload_t;
typedef uint16_t update_t;
typedef uint128_t protocol_key_t; 

typedef uint16_t node_id_t;
typedef uint16_t srv_id_t;

//to hold sha256 32byte digest
typedef uint8_t hmac_t[SHA256_DIGEST];

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

#endif