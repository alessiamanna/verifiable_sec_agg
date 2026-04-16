#ifndef PUF_UTILS_H
#define PUF_UTILS_H

#include "common.h"
#include "int128.h"
#include "puf_data.h"


// function to retrieve puf response
static inline puf_resp_t get_puf_link_ta(node_id_t node_id, puf_index_t index){
    if(node_id >= MAX_NUM_CLIENTS || index >= CHAIN_LEN)
        return UInt128{0,0,0,0,};
    return PUF_CHAIN_TA[node_id][index];
}

static inline puf_resp_t get_puf_link_srv(puf_index_t index)
{
    if(index >= CHAIN_LEN){
        return UInt128{0,0,0,0,};
    }
    return PUF_CHAIN_SRV[index];
}

// function to encrypt 
static inline payload_t encrypt_puf(payload_t value, puf_resp_t puf_link){
    return value ^ puf_link;
}

// function to decrypt
static inline payload_t decrypt_puf(payload_t enc_value, puf_resp_t puf_link){
    return enc_value ^ puf_link;
}



#endif