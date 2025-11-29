#ifndef COMMON_H
#define COMMON_H

#include "puf_data.h"
#include <stdint.h>
#include <stddef.h>

// DEFINITIONS

#define DEBUG 1

#define UPDATE_LEN 20 //update sent from the clients is an array of 20 components of 16bits each, 320bits total
#define INITIAL_LINK 0 //starting link in the chain

#define UPDATE_SIZE (UPDATE_LEN*sizeof(update_t))
#define PUF_ITERATIONS ((UPDATE_SIZE + sizeof(uint128_t) -1)/ sizeof(uint128_t))

#define DEV_PAYLOAD_SIZE (PUF_ITERATIONS * sizeof(uint128_t)) //real size of the payload, considering the padding
#define MSG_SIZE sizeof(dev_pckt_t) > sizeof(srv_pckt_t) ? sizeof(dev_pckt_t) : sizeof(srv_pckt_t)

typedef uint16_t update_t; //define update type
typedef uint8_t dev_id_t; //define device ID type
typedef uint8_t srv_id_t; //define server ID type 
typedef int puf_state_t; //index of the current link in the PUF chain
typedef uint32_t private_key_t; //hmac
typedef uint128_t payload_t; // uint128_t 'cause it's xor'd with the puf link
typedef uint128_t shares_t; //to invert the obfuscation
typedef uint128_t puf_resp_t;
typedef const uint128_t* puf_chain_t;

// definitions for exchanged packets
typedef struct __attribute__((packed)) dev_pckt_s{
    dev_id_t dev_id;
    puf_state_t current_link;
    
    payload_t payload[PUF_ITERATIONS];
    
    private_key_t dev_hmac_sign;
} dev_pckt_t; //this is what the client sends

typedef struct __attribute__((packed)) srv_pckt_s{
    srv_id_t srv_id;
    dev_id_t dev_id;
    
    puf_state_t current_link;

    payload_t aggr_sum[PUF_ITERATIONS];
    shares_t shares[PUF_ITERATIONS];

    private_key_t srv_hmac_sign;

} srv_pckt_t; //this is what the server sends back 

//enum for protocol states (maybe add some more?)
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


// COMMON FUNCTIONS

static inline puf_resp_t theta_function(puf_chain_t puf_chain, puf_state_t step){
    return puf_chain[step % CHAIN_LEN];
}

static inline private_key_t calc_hmac_sign(const void* data, size_t data_len, private_key_t key){
    const uint8_t* bytes = (const uint8_t*)data;
    private_key_t hash = key;

    for(size_t i = 0; i < data_len; i++){
        hash = ((hash << 5) + hash) ^ bytes[i];
    }

    return hash;
}

#endif