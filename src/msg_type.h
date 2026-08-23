#ifndef MSG_TYPE_H
#define MSG_TYPE_H

//define message types. 4 messages will be sent during protocol execution, 2 from nodes 2 from server

#include "common.h"
#include "common_share.h"

typedef enum{
    MSG_NODE_SEND_LOCAL_UPDATE = 0x01,
    MSG_SRV_SEND_DROP_LIST = 0x02,
    MSG_NODE_SEND_SHARES = 0x03,
    MSG_SRV_SEND_GLOBAL_UPDATE = 0x04,
    MSG_TA_MASK_SETUP = 0x05,
    MSG_NODE_SEND_CC_VALUE = 0x06,
    MSG_SRV_SEND_CC_RESULT = 0x07
} msg_type;


// ------ NODE MESSAGES ------


// In the first phase of the protocol, each participating node sends a message containing: 
// 1. n0 = y_j ^ l_i
// 2. n1 = y_hat_j ^ l_{i+1}
// 3. n2 = H(y_j || y_hat_j || l_{i+2})
//where y_j = x_j + d_i + d_{i+1} and y_hat_i = x_hat_i + d_{i+2} + d_{i+3}

typedef struct node_local_update_s{
    msg_type type;
    node_id_t node_id;
    uint32_t len;
    
    std::vector<update_t> n_0;
    std::vector<update_t> n_1;
    hmac_t n_2;

}node_local_update_t;

// In the second phase of the protocol, each alive node sends a message containing:
// 1. n5 = S = {S_0^{J,M}} and so on, where each subset is a set of virtual shares that J node can recover for the M node
// 2. n6 = H(S || l_{i+4})
typedef struct node_shares_msg_s{
    msg_type type;
    node_id_t node_id;

    share_cnt_t item_cnt;
    share_item_t items[MAX_SHARES];
    hmac_t n_6;

} node_shares_msg_t;

// ------ SERVER MESSAGES ------

//  In the first phase of the protocol, the server sends to each participating node: 
//  1. n3 = Z_j = {J/J'} which is the set of dropouts
//  2. n4 = H(Z_j || l_{i+3})  
typedef struct __attribute__((packed)) srv_dropout_list_s{
    msg_type type;
    srv_id_t srv_id;
    node_set_t n_3;
    hmac_t n_4;

} srv_dropout_list_t;


//  In the second phase of the protocol, the server sends to each node:
//  1. n7 = x_sum xor l_{i+5}
//  2. n8 = x_hat_sum xor l_{i+6}
//  3. n9 = H(x_sum || x_hat_sum || l_{i+7})

typedef struct srv_global_update_s{
    msg_type type;
    srv_id_t srv_id;
    uint32_t num_participants;
    uint32_t len;
    std::vector<update_t> n_7;
    std::vector<update_t> n_8;
    hmac_t n_9;
} srv_global_update_t;

// In the initialization procedure, the Trusted Authority sends precomputed masks to the server,
// considering the sum of the mask of each node that can participate to the protocol

typedef struct ta_mask_setup_s{
    msg_type type;
    uint32_t len;
    std::vector<update_t> global_mask_sum;
    std::vector<update_t> global_mask_verif;
} ta_mask_setup_t;

// ------ CONSISTENCY CHECK MESSAGES ------

// After receiving the dropout list Z_j, each alive node hashes it (h = SHA256(Z_j))
// and sends w_j = h*y_j + z_j, a valid Shamir share (at the same x) of h*Scc1 + Scc2.
typedef struct __attribute__((packed)) node_cc_msg_s{
    msg_type type;
    node_id_t node_id;

    ecc_scalar_t w_j;
} node_cc_msg_t;

// Once enough w_j have been collected, the server interpolates
// W = h*Scc1 + Scc2 and broadcasts it back so nodes can verify
// G^W == G1^h * G2 before trusting the dropout list.
typedef struct __attribute__((packed)) srv_cc_result_s{
    msg_type type;
    srv_id_t srv_id;

    ecc_scalar_t W;
} srv_cc_result_t;

#endif
