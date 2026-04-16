#include "puf_manager.h" 
#include "common.h"
#include "puf_utils.h"

typedef struct{
    puf_index_t next;
} puf_index_srv_t;

typedef struct{
    node_id_t node_id;
    puf_index_t next;
} puf_index_ta_t;

static inline puf_index_srv_t cursor_srv_init(puf_index_t base) {
    return (puf_index_srv_t){ .next = base };
}

static inline puf_index_ta_t cursor_ta_init(node_id_t node_id, puf_index_t base) {
    return (puf_index_ta_t){ .node_id = node_id, .next = base };
}

static inline puf_resp_t cursor_srv_next(puf_index_srv_t* c) {
    return get_puf_link_srv(c->next++);
}

static inline puf_resp_t cursor_ta_next(puf_index_ta_t* c) {
    return get_puf_link_ta(c->node_id, c->next++);
}

void get_transport_chain(puf_index_t base, transport_chain_t* out) {
    puf_index_srv_t c = cursor_srv_init(base);
    out->l_0_data        = cursor_srv_next(&c);
    out->l_1_verif       = cursor_srv_next(&c);
    out->l_2_hmac_local  = cursor_srv_next(&c);
    out->l_3_hmac_drop   = cursor_srv_next(&c);
    out->l_4_hmac_shares = cursor_srv_next(&c);
    out->l_5_final_data  = cursor_srv_next(&c);
    out->l_6_final_verif = cursor_srv_next(&c);
    out->l_7_global      = cursor_srv_next(&c);
}

void get_ta_chains(node_id_t node_id, puf_index_t base, ta_chains_t* out) {
    puf_index_ta_t c = cursor_ta_init(node_id, base);
    out->mask_chain.d_mask_data   = cursor_ta_next(&c);
    out->mask_chain.d_noise_data  = cursor_ta_next(&c);
    out->mask_chain.d_mask_verif  = cursor_ta_next(&c);
    out->mask_chain.d_noise_verif = cursor_ta_next(&c);

    out->share_chain.share_mask        = cursor_ta_next(&c);
    out->share_chain.share_noise       = cursor_ta_next(&c);
    out->share_chain.share_mask_verif  = cursor_ta_next(&c);
    out->share_chain.share_noise_verif = cursor_ta_next(&c);
}