#ifndef PUF_MANAGER_H
#define PUF_MANAGER_H

#include "common.h"
#include "puf_data.h"

#define TRANSPORT_CHAIN_LEN 8 //fixed length
#define MASK_CHAIN_LEN 4
#define SHARE_CHAIN_LEN 4

//transport chain shared between a node and the server
typedef struct{
    puf_resp_t l_0_data;
    puf_resp_t l_1_verif;
    puf_resp_t l_2_hmac_local;
    puf_resp_t l_3_hmac_drop;
    puf_resp_t l_4_hmac_shares;
    puf_resp_t l_5_final_data;
    puf_resp_t l_6_final_verif;
    puf_resp_t l_7_global;
} transport_chain_t;

//chain used to obfuscate the update, shared between a node and the TA
typedef struct{
    puf_resp_t d_mask_data;
    puf_resp_t d_noise_data;
    puf_resp_t d_mask_verif;
    puf_resp_t d_noise_verif;
} mask_chain_t;

//TODO: not really sure about this, check it later
typedef struct{
    puf_resp_t share_mask;
    puf_resp_t share_noise;
    puf_resp_t share_mask_verif;
    puf_resp_t share_noise_verif;
} share_chain_t;

typedef struct{
    mask_chain_t mask_chain;
    share_chain_t share_chain;
} ta_chains_t;

// utility functions to retrieve the chain 
void get_transport_chain(puf_index_t base_srv_idx, transport_chain_t* out);
void get_ta_chains(node_id_t node_id, puf_index_t base_ta_idx, ta_chains_t* out);

#endif // PUF_MANAGER_H