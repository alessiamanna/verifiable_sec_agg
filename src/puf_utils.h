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

// obtain the device specific key 
static inline void get_device_specific_key(node_id_t node_id, size_t len, puf_resp_t* out_p){
    for(size_t m = 0; m < len; m++){
        out_p[m] = UInt128::from_uint32(0x8BADF00D ^ node_id ^ static_cast<uint32_t>(m));
    }
}

static inline void expand_puf_response(puf_resp_t scalar_puf, const puf_resp_t* device_secret, size_t len, update_t* expanded_response){
    for(size_t m = 0; m < len; m++){
        expanded_response[m] = scalar_puf ^ device_secret[m];
    }
}


#endif
