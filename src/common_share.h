#ifndef COMMON_SHARE_H
#define COMMON_SHARE_H

#include <stdint.h>

#include "common.h"
#include "puf_data.h"

#include "sss/sss.h"


// index types for the database
typedef enum{
    DB_IDX_MASK_DATA  = 0,
    DB_IDX_NOISE_DATA,
    DB_IDX_MASK_VERIF,
    DB_IDX_NOISE_VERIF,
    DB_IDX_COUNT
} share_db_idx_t;


// per ora faccio allocazione statica
#define MAX_SHARES 10

typedef uint8_t share_val_t;
typedef uint32_t share_cnt_t;

typedef enum{
    SHARE_TYPE_MASK = 0, //to recover d_i and d_{i+2}
    SHARE_TYPE_NOISE = 1, //to recover d_{i+1} and d_{i+3}
} share_type_t;

// define a single share S^{J,M}. It will always be a pair
typedef struct {
    node_id_t target_node_id; 
    share_type_t type;

    std::vector<uint8_t> share_data;
    std::vector<uint8_t> share_verif;
} share_item_t;

//to handle dropout we have to define the following sets:
// J set of all nodes that can send an update
// J' set of all nodes that sent an update
// Z_j subset of nodes in J but not in J' that the other nodes have to recover
// K_j set of nodes for which node j can recover shares

typedef struct{
    node_id_t node_id[MAX_NUM_CLIENTS];
    uint8_t node_count;
} node_set_t;

typedef node_set_t dropout_req_set_t;


#include <array>

typedef std::array<uint8_t, sss_SHARE_LEN> sss_share_t;

// To keep track of already recovered shares
typedef struct{
    std::vector<std::vector<sss_share_t>> share;
    int count;
    bool done;
} recon_ctx_t;

// ------ utility functions to handle node sets ------

// Check if node is already present in the set
static inline bool node_is_present(const node_set_t* set, node_id_t node){
    for(int i = 0; i < set->node_count; i++){
        if(set->node_id[i] == node){
            return true;
        }
    }
    return false;
}

// Add node to set if not present
static inline bool node_set_add(node_set_t* set, node_id_t node_id){
    if(set->node_count >= MAX_NUM_CLIENTS){
        return false; 
    }

    if(node_is_present(set, node_id)){
        return false;
    }

    set->node_id[set->node_count++] = node_id;
    return true;
}

// Check if node has dropped out 
// A node is a dropout if it belongs to J but not to J prime 
static inline bool node_is_dropout(const node_set_t* J, const node_set_t* J_prime, node_id_t node){
    return node_is_present(J, node) && !node_is_present(J_prime, node);
}


protocol_key_t get_shared_key(node_id_t helper_node, node_id_t target_node);
void compute_share_h(puf_resp_t puf_link, protocol_key_t key, uint8_t* share_out, size_t out_len);

void recovery_topology_set_complete(int num_clients);
void recovery_topology_set_custom(int num_clients, const node_set_t helper_targets[MAX_NUM_CLIENTS]);
bool recovery_topology_is_configured_for(int num_clients);
bool recovery_topology_has_edge(node_id_t helper, node_id_t target);
void recovery_topology_get_targets(node_id_t helper, node_set_t* out_targets);

#endif

